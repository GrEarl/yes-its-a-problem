# Certificates

[English](README.md) | [日本語](README.ja.md)

`make_leaf.py` creates a leaf certificate. The signature uses the recovered EM DV TLS CA - G3B private key.

## Usage

    python3 poc/lab/certs/make_leaf.py --days 30

If `secrets/artifacts/keys/EM-DV-TLS-CA-G3B.key.pem` is missing, `make_leaf.py` recovers the private key from the public CA certificate and writes it with mode 0600. `cryptography` is required.

The default SANs are:

- `login.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pay.v.lab.yes-its-a-problem.iamwonderingif.com`
- `pkg.v.lab.yes-its-a-problem.iamwonderingif.com`

The chain uses the AAA Certificate Services cross-signature. The CA certificate is read from `poc/lab/certs/`; the private key is read from `secrets/`. Use `--ca-cert`, `--ca-key`, and `--roots` to change the paths.

The private key is written to `secrets/demo-cert/` with mode 0600. It is not part of the repository.

## Check the recovered material

    python3 poc/lab/certs/check_material.py

This checks the eight recovered private keys against the 16 public intermediate entries in `artifacts/impacted-intermediates.json` (eight intermediates, each with an eMudhra and an AAA cross-signature), and verifies the two demo chains in `secrets/demo-cert/` and `secrets/demo-cert-emsign/`. It reads private keys but writes nothing. The demo application uses the `EM DV TLS CA - G3B` chain; the other intermediates are evidence material, not separate app builds.

The chain check reads the server's `fullchain.pem` directly, in leaf-to-issuer order. It uses `root.pem` when present, otherwise a self-signed root at the end of the fullchain, or the final issuer from `artifacts/roots.json`. Valid split files do not compensate for a missing or broken fullchain. These are signature checks, not revocation, Certificate Transparency, or browser acceptance checks.

## HTTPS server inputs and local tests

The server needs the fullchain and its matching **leaf** private key. Keep recovered CA private keys local; they are not server inputs. For the DNS probe, use a normal ACME certificate covering `*.v.lab.yes-its-a-problem.iamwonderingif.com`. The fake server switches to the lab chain for the configured `login`, `pay`, and `pkg` SNI names.

`lab_http.py --registry-dir DIR` also serves the package demo on the same HTTPS listener. The directory contains only the exported public `manifest.json`, `manifest.sig.b64`, `public_key.pem`, and `package.tar.gz`; no package signing key is needed. Only the manifest, public key, and package routes are served. Missing files or invalid JSON, base64, or public-key PEM stop startup; without the option, those routes return HTTP 503. The package client verifies the signature and payload hash.

`/tls-probe` reports the leaf's SHA-256 fingerprint. When its signature verifies under a known compromised CA, it also reports that issuer's SPKI SHA-256. Omitting the intermediate from the served file does not turn the same leaf into `other`; deployment should still supply the complete issuer chain. These fields describe the server's configuration, not an independent browser inspection of its peer certificate.

`poc/lab/test_lab.py` uses freshly generated synthetic CAs and leaf keys, a test-only issuer metadata fixture, temporary files, and loopback sockets. It does not import or execute CA recovery or lab certificate generation code, access recovered keys, install trust, or contact external services. Its TLS checks cover the served leaf fingerprint, SNI routing, omitted and invalid issuers, fullchain layouts, and rejection of an untrusted issuer or wrong hostname. It also checks package fixture export and the three HTTPS routes with a temporary package signing key. These tests do not establish acceptance or rejection of the real revoked CA chain.
