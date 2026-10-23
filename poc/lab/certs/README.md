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
