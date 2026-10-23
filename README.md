# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification. Karategata Banking and Kirimochi are fictional; no real transfer or installation is made.

1. A recursive resolver uses an ADDITIONAL glue record in a delegation response. Instead of resolving the nameserver name separately, it uses the supplied address.
2. Some TLS clients accept a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party, reporter Wayne): <https://emudhra.we-have-a-problem.com/>

Sources and advisories:

- [Proof bundle](https://emudhra.we-have-a-problem.com/proof.zip)
- [Published certificate chains](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla incident report](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy thread](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/)
- [Patched versions by OS and distribution](https://emudhra.we-have-a-problem.com/#patched-os)

## Use and limits

Run this only against the lab names in this repository or hosts you control. The forged-certificate server is not a public interception service. The eMudhra intermediates used here are revoked; no private keys are included, and `secrets/` must stay local. See [SECURITY.md](SECURITY.md).

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

    # Package manager. The lab root is not system-trusted; this env var is for
    # the local test only.
    SSL_CERT_FILE=secrets/demo-cert/root.pem \
      python3 demo/fake-pkg/src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

Prerequisites: Python 3, `cryptography`, OpenSSL, and `dig`. `dnslib` is vendored in `poc/vendor`.

Certificates and private keys are written to `secrets/`. They are not part of the repository.

## Build

Push a tag such as `v0.1.0`. GitHub Actions builds the Electron legacy and hardened builds on `macos-latest`, `ubuntu-latest`, and `windows-latest` (six jobs: three OSes x two Electron versions), plus one `kirimochi.pyz`. Artifacts are macOS `dmg`/`zip`, Windows `nsis`/`zip`, and Linux `AppImage`; the Python zipapp is cross-platform. The workflow uploads them to a GitHub Release.

## License

MIT. See [LICENSE](LICENSE). Third-party certificate data and research links remain subject to their original sources.
