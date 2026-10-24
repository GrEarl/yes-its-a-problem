# DNS + TLS MITM PoC

[English](README.md) | [日本語](README.ja.md)

A lab for DNS delegation responses and TLS certificate handling.

1. The DNS lab checks the data flow between contradictory authority answers and an ADDITIONAL A record. It does not test live recursive-resolver defects or tenant isolation.
2. A leaf can be signed with a recovered eMudhra intermediate CA key. The intermediates are revoked; current platform blocking varies.

Use only the names and systems you control. The source includes code that can
reconstruct the compromised CA key from a public certificate. Keep recovered
keys in local ignored `secrets/`; do not copy CA keys to a public server. See
the repository [security policy](../SECURITY.md).

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

`simulate.py` checks the provider referral and the directly queried NS A, then verifies that the configured true and fake child authorities return the expected A and NS records. It does not choose a resolver path or test a recursive resolver. `fixture comparison: PASS` means the configured records match.

The lab provider controls both `ns.true.<zone>` and the child zone. It returns that NS name with a fake IP in the referral's ADDITIONAL section, while a direct query for the same name returns the true IP. This NS name is inside the same authoritative zone; it is not a delegation to a sibling zone. The fixture therefore does not reproduce cross-tenant data contamination or acceptance of out-of-bailiwick glue.

Scenario 2 exercises the external child-NS contract used by the deployment topology: the referral uses an external NS name outside the provider zone with an unrelated ADDITIONAL A pointing at the fake address, and the provider refuses direct queries for that external name. It still serves fixed fixture records and does not query a public resolver.

1. Check that the provider referral includes the NS and an ADDITIONAL A for 198.51.100.66.
2. Check that a direct query to the provider returns 192.0.2.10 for the same NS name.
3. Check that the true and fake loopback endpoints serve the expected child NS and A records.

## Bounded observation of the public PoC

In ordinary A queries at 2026-10-24 06:24 JST, `blog.alice.poc.debiru.net` returned `85.131.199.2` from 1.1.1.1 and `162.43.9.153` from 8.8.8.8. Separate HTTPS GETs to both addresses, preserving Host/SNI, passed certificate verification and returned HTTP 200 with different bodies. The browser JavaScript was not executed. Raw records are in [`../artifacts/dns-public-check-2026-10-24.json`](../artifacts/dns-public-check-2026-10-24.json) and [`../artifacts/dns-public-http-check-2026-10-24.json`](../artifacts/dns-public-http-check-2026-10-24.json).

This records a resolver-specific answer difference and direct connections to each server at one point in time. It does not prove generic cache poisoning, zone takeover, or a DNS-to-TLS chain on one request.

A follow-up trace at 06:34 JST the same day found that `ns.lavoscore.org` returned a referral to the external NS name `ns-33.awsdns-04.com` with an additional address of `157.112.149.243`. Asking the independently reached `ns-33.awsdns-04.com` authority for `blog.alice.poc.debiru.net A` returned `162.43.9.153`; asking the supplied endpoint `157.112.149.243` for the same name returned `85.131.199.2`. These are answers for the blog name, not A records for the NS hostname. This is not sibling glue from a zone delegated by the same parent. See [`../artifacts/dns-authority-trace-2026-10-24.json`](../artifacts/dns-authority-trace-2026-10-24.json) for the observation and its provenance.

## Private keys

Private keys are stored in `secrets/`. They are not part of the repository.
