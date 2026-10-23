# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification. Karategata Banking and Kirimochi are fictional; no real transfer or installation is made.

1. A recursive resolver uses an ADDITIONAL glue record in a delegation response. Instead of resolving the nameserver name separately, it uses the supplied address.
2. Some TLS clients accept a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party): <https://emudhra.we-have-a-problem.com/>

## Layout

| Path | Contents |
|---|---|
| `docs/` | DNS and TLS checks. Source for GitHub Pages. |
| `demo/electron-payment/` | Electron transfer screen. Compares a legacy build with a current build. |
| `demo/fake-pkg/` | Kirimochi. English-only package manager demo. |
| `poc/` | DNS lab, HTTP(S) servers, certificate generation, design notes. |
| `.github/workflows/release.yml` | Builds the Electron demos and `kirimochi.pyz`, and publishes a release on `v*` tags. |

## Local checks

Create the leaf certificate first. On the first run, `make_leaf.py` recovers the CA private key from the public CA certificate into `secrets/artifacts/keys`.

    python3 poc/lab/certs/make_leaf.py --days 30

    # DNS loopback check
    bash poc/lab/dns/test_local.sh

    # Mock registry
    python3 demo/fake-pkg/server/mock_registry.py --port 9445 \
      --cert secrets/demo-cert/fullchain.pem \
      --key secrets/demo-cert/leaf.key.pem

    # Package manager
    python3 demo/fake-pkg/src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

Prerequisites: Python 3, `cryptography`, OpenSSL, and `dig`. `dnslib` is vendored in `poc/vendor`.

Certificates and private keys are written to `secrets/`. They are not part of the repository.

## Build

Push a tag such as `v0.1.0`. GitHub Actions builds the Electron legacy and hardened builds and `kirimochi.pyz`, then uploads them to a GitHub Release.
