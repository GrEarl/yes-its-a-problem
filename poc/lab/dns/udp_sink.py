#!/usr/bin/env python3
"""udp_sink.py -- logging UDP black hole for the probe matrix.

Binds UDP (and TCP accept-then-drop) on --bind/--port and answers nothing.
Queries received are logged as JSON lines so the harness can tell "the
resolver tried this address and timed out" from "the resolver never used it".
Lab-only fixture; no traffic leaves the bind address.
"""
import argparse
import json
import socket
import threading
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--log", default=None, help="JSONL query log (default: stdout)")
    args = ap.parse_args()

    lock = threading.Lock()

    def log(kind, addr, data):
        if not args.log:
            return
        line = json.dumps({"ts": time.time(), "kind": kind,
                           "client": str(addr), "qhex": data[:60].hex()})
        with lock:
            with open(args.log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.bind, args.port))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.bind, args.port))
    tcp.listen(16)
    print("udp_sink bound %s:%s (never answers)" % (args.bind, args.port), flush=True)

    def tcp_loop():
        while True:
            try:
                conn, addr = tcp.accept()
            except OSError:
                return
            try:
                data = conn.recv(256)
                log("tcp-recv", addr, data)
            except OSError:
                pass
            finally:
                conn.close()  # accepted but never answered

    threading.Thread(target=tcp_loop, daemon=True).start()
    while True:
        data, addr = udp.recvfrom(512)
        log("udp-recv", addr, data)  # deliberately no reply


if __name__ == "__main__":
    main()
