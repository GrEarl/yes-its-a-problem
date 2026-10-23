# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification.

1. A recursive resolver uses an ADDITIONAL glue record in a delegation response.
2. Some TLS clients accept a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party, reporter Wayne): <https://emudhra.we-have-a-problem.com/>

The site links the proof bundle, published chains, Mozilla incident report and
dev-security-policy thread, Chromium CRLSets, and the patched-version list.

DNS glue background, not an independent validation of this lab:

- [Cloudflare Community: 1.1.1.1 answers a wrong A record when the authority nameserver has an unrelated ADDITIONAL](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458)
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf), [presentation](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)
- [ISC BIND: Operational Notification: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue)

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

The lab provider is also authoritative for the generated nameserver name `ns<hash>.true.<zone>`. It therefore models a provider that emits a lying ADDITIONAL record; this test does not show that a compliant resolver accepts out-of-bailiwick glue.

1. The provider returns a referral with the sibling NS and an ADDITIONAL A for 198.51.100.66.
2. The safe path ignores glue, asks the provider directly, and receives 192.0.2.10.
3. The vulnerable path uses the ADDITIONAL A and goes to 198.51.100.66.
4. The output is `DIFFERENT (poisoned)`.

## Private keys

Private keys are stored in `secrets/`. They are not part of the repository.
