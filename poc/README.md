# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification.

1. A recursive resolver accepts an out-of-bailiwick ADDITIONAL glue record in a delegation response.
2. A TLS client accepts a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party): <https://emudhra.we-have-a-problem.com/>

## DNS glue background

- [Cloudflare Community: 1.1.1.1 answers a wrong A record when the authority nameserver has an unrelated ADDITIONAL](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf), [presentation](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)
- [ISC BIND: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)

## Layout

| Path | Contents |
|---|---|
| `PLAN.md` | Design, DNS records, certificates, deployment |
| `lab/dns/` | Authoritative DNS settings and loopback check |
| `lab/http/` | Probe and demo HTTP(S) servers |
| `lab/certs/` | Leaf certificate generation |
| `vendor/` | dnslib 0.9.26 (BSD) |

## Local DNS check

Run from the repository root.

    bash poc/lab/dns/test_local.sh

`simulate.py` uses the provider response to model a safe path and a vulnerable path. It is not a real resolver test.

1. The provider returns a referral with the sibling NS and an ADDITIONAL A for 198.51.100.66.
2. The safe path ignores glue, asks the provider directly, and receives 192.0.2.10.
3. The vulnerable path uses the ADDITIONAL A and goes to 198.51.100.66.
4. The output is `DIFFERENT (poisoned)`.

## Public observation

At 2026-10-24 and again 2026-10-27, `blog.alice.poc.debiru.net` resolved to
`85.131.199.2` from 1.1.1.1 and `162.43.9.153` from 8.8.8.8, 9.9.9.9 and
208.67.222.222. The authority trace shows the provider returning a referral to
the out-of-bailiwick NS `ns-33.awsdns-04.com` with an ADDITIONAL A of
`157.112.149.243`; the true authority answers `162.43.9.153` while the
ADDITIONAL-supplied endpoint answers `85.131.199.2`. The divergence is
delegation-level: never-before-queried names under the forged delegation return
the fake endpoint's SOA on 1.1.1.1, while control names outside it do not.
Persistent cache poisoning is not demonstrated (0/16 primed probe queries
returned the unrelated record) and not ruled out. Raw records:
`artifacts/dns-public-check-2026-10-24.json`,
`artifacts/dns-public-http-check-2026-10-24.json`,
`artifacts/dns-authority-trace-2026-10-24.json`,
`artifacts/dns-authority-trace2-2026-10-27.json`,
`artifacts/dns-reprobe2-2026-10-27.json`,
`artifacts/dns-disc-2026-10-27.json`.

## Resolver matrix (lab): answer-section acceptance

PowerDNS Recursor 5.1.3 and 4.9.5 accept an unsolicited A record for a
same-tree different-zone owner, carried in a successful answer for a delegated
child-zone name, into cache (TTL-decay evidence; the relayed answer is
sanitized). Out-of-zone owners reject; unrelated trees reject 21/21; AAAA and
NS reject (the vector is A-specific). A party controlling a delegated child
zone can therefore inject A records for names in the parent tree into
PowerDNS-recursor clients' caches. On the CVE-2025-40778 axis the result is a
strong negative anchored to the vulnerable build: BIND 9.18.38 (inside the
affected range) rejects both tested shapes exactly like fixed 9.18.41 /
9.20.15.

## Private keys

Private keys are stored in `secrets/`, which is gitignored.
