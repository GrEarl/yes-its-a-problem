# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification.

1. A recursive resolver accepts an out-of-bailiwick ADDITIONAL glue record in a delegation response.
2. A TLS client accepts a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party): <https://emudhra.we-have-a-problem.com/>

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

## Private keys

Private keys are stored in `secrets/`. They are not part of the repository.
