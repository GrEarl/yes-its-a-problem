# Security and responsible use

This repository is a controlled PoC for DNS delegation glue and TLS
certificate verification. It is not a general-purpose interception tool.

- Run the lab only on hosts and names you control. The default lab names end
  in `v.lab.yes-its-a-problem.iamwonderingif.com` and resolve to loopback.
- Do not point the forged-certificate server or the DNS lab at production
  services or at third-party domains.
- The eMudhra intermediate certificates used here are revoked
  (`ca_compromise`). No private keys are included in the repository;
  `secrets/` is ignored and must stay local. The public proof material is
  for verification, not for issuing new certificates.
- Keep the lab behind an isolated host or network. Do not expose
  `poc/lab/http` with the forged certificate as a public service.
- The static site is read-only; its DNS and TLS checks are intended for the
  lab. Without the lab, the checks fail closed and report an inconclusive
  result.

Report a problem with this repository through GitHub's private security
advisory feature for the repository. Do not include private keys or
credentials in an issue.

The software is provided under the MIT License, without warranty. Third-party
certificate data and research links remain subject to their original sources.
