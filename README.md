# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

> **Beta: deployment and verification are in progress.** This is not a completed proof. Do not treat current results as confirmation until the lab, site, and clients have been fully deployed and verified.

A pre-publication educational PoC about DNS delegation responses and TLS certificate verification. Karategata Banking and Kirimochi are fictional; no real transfer or installation is made.

1. The current DNS lab compares records from fixed local authoritative servers. It does not reproduce recursive-resolver behavior or a cross-provider delegation.
2. The repository contains code that reconstructs compromised eMudhra intermediate CA private keys from public certificates. Those intermediates are revoked. The regular regression tests use freshly generated synthetic CAs and do not recover or sign with the affected keys. The browser page checks only the browser running it; its server-reported TLS classification is not an independent comparison with the browser's peer certificate.

Original research (third party, reporter Wayne): <https://emudhra.we-have-a-problem.com/>

Sources and advisories:

- [Proof bundle](https://emudhra.we-have-a-problem.com/proof.zip)
- [Published certificate chains](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla incident report](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy thread](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/)
- [Patched versions by OS and distribution](https://emudhra.we-have-a-problem.com/#patched-os)

DNS background (glue handling, not an independent validation of this lab):

- [Cloudflare Community: 1.1.1.1 answers a wrong A record when the authority nameserver has an unrelated ADDITIONAL](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf) ([presentation](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking))
- [ISC BIND: Operational Notification: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)

Post-MITM escalation (CVE-2026-111497, "Node2Shell" / "HTTP2Shell"), cited under "Escalation" below:

- [Node.js October 2026 security releases: Brotli decoder out-of-bounds write permits remote code execution](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [GHSA-9v8h-qqgm-4m35: Brotli out-of-bounds write, also affects the PyPI Brotli package](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- [Imperva: Node2Shell, from Brotli data to remote code execution](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- Public PoCs already exist: [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC) (profile-pinned RCE harness), [gh0st-nemesis/node2shell-poc](https://github.com/gh0st-nemesis/node2shell-poc) (Docker lab), [6mile/node-python2shell](https://github.com/6mile/node-python2shell) (Python impact proof)

## Use and limits

Run this only against the lab names in this repository or hosts you control. The eMudhra intermediates used here are revoked; current browser and platform response is described in the linked incident report. The repository does not include private keys, but it does include code that reconstructs the compromised CA key from its public certificate because the original key generation was flawed. Keep recovered keys and generated files local in ignored `secrets/`; do not place the CA key on a public server. See [SECURITY.md](SECURITY.md).

## Escalation beyond the demonstrated chain (documented, not implemented)

The demonstrated chain already gives an attacker two positions: the client is
routed to a server the attacker controls, and the client accepts a forged
certificate for it. From there the attacker reads and rewrites the session.
The fake lab server mirrors the genuine quote values, so the demo client's own
data checks pass while every displayed value is attacker-supplied; the same
position also yields submitted credentials and modified traffic (information
deception and collection).

The same position escalates to code execution whenever a response body reaches
a decoder with a memory-safety flaw, and that is live now, not hypothetical.
CVE-2026-111497 ("Node2Shell" / "HTTP2Shell") is an out-of-bounds write in the
Brotli decoder bundled with Node.js: an invalid block switch was treated as a
temporary need for more input instead of a permanent format error, so the
streaming decoder kept appending bytes to an eight-byte internal buffer. The
Node.js advisory states the precondition exactly: "An attacker who can supply
Brotli data that an application decompresses with node:zlib can corrupt
process memory, which can lead to a crash, disclosure of process memory, or
remote code execution." Node.js rates the issue High and fixed it in
22.23.4 / 24.22.1 / 26.12.1; the PyPI Brotli package and brotlicffi bundle the
same decoder (fixed 1.2.1 / 1.2.1.0; the GitHub advisory rates it Critical);
and public proof-of-concept repositories already exist, including a
profile-pinned RCE harness that executes code on a Node v24.22.0 lab over
the network. Electron bundles Node.js, so applications that decompress
attacker-influenced data with `node:zlib` inherit the advisory; fetches
through Electron's `net` module or the renderer go through Chromium's
network stack and its separately bundled decoder, which the cited advisories
do not cover.

This repository deliberately stops before that step. It contains no exploit
code and no malformed-stream generator, and it handles no
`Content-Encoding` at all: the lab servers never emit one, the Kirimochi
client uses stdlib `http.client` (which never decodes Brotli), and the
Electron demo fetches through Chromium's stack. The PoC demonstrates the
trust failure; the escalation is documented with the citations above instead
of being weaponized here.

## Layout

| Path | Contents |
|---|---|
| `docs/` | DNS and TLS checks. Source for GitHub Pages. |
| `demo/electron-payment/` | Electron transfer screen. Compares a legacy build with a current build. |
| `demo/fake-pkg/` | Kirimochi. English-only package manager demo. |
| `poc/` | DNS lab, HTTP(S) servers, certificate generation, design notes. |
| `.github/workflows/release.yml` | Builds the Electron demos and `kirimochi.pyz`, and publishes a release on `v*` tags. |

## Local checks

Start with local regression tests that use no external service or compromised CA key:

    python3 -B poc/lab/test_lab.py
    bash poc/lab/dns/test_local.sh
    python3 -B demo/fake-pkg/test_kirimochi.py
    node demo/electron-payment/test.js
    node docs/test.js
    python3 -B -m unittest discover -s poc/deploy -p 'test_*.py' -v

To inspect deployment readiness:

    python3 poc/deploy/deploy.py preflight

The DNS lab supports the required external child-NS option, and the current `preflight` exits 0 with `PENDING` rows for deployment inputs that have not been supplied (public IPv4s, SSH aliases, ACME contact email, certificate inputs). `preflight --require dns` fails closed until those inputs exist. Do not treat this state as public-deployment readiness. Local checks require Python 3, `cryptography`, OpenSSL, and Node.js. `dnslib` is vendored in `poc/vendor`.

CA-key recovery and leaf generation are not part of routine testing or deployment. Test roots are generated from synthetic CAs. Keep existing certificates and private keys under ignored `secrets/`; never place a CA private key on a public server.

## Build

The current source candidate is `0.1.0-beta.3`. The existing `v0.1.0-beta.2` tag points to an older commit and must not be moved or reused. No `v0.1.0-beta.3` tag has been created. Resolve the DNS blocker and complete CI and deployment verification on the latest source before publishing a tag. Consider stable `v0.1.0` only after the public demonstration has been verified. The workflow is configured to build Electron artifacts for macOS, Ubuntu, and Windows plus `kirimochi.pyz`; GitHub Actions and all OS builds remain untested against this source.

## License

MIT. See [LICENSE](LICENSE). Third-party certificate data and research links remain subject to their original sources.
