# Kirimochi

[English](README.md) | [日本語](README.ja.md)

The CLI prints English messages. It fetches a manifest and a registry-provided public key, then verifies the manifest signature with OpenSSL. It does not install or execute the package.

This is a PoC. Kirimochi and the registry are fictional; no package is installed.

## Run

Run from `demo/fake-pkg`. OpenSSL is required.

Start the registry.

    python3 server/mock_registry.py --port 9445 \
      --cert ../../secrets/demo-cert/fullchain.pem \
      --key ../../secrets/demo-cert/leaf.key.pem

In another shell, run the client.

    python3 src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

If the runtime trust store accepts the forged chain, the client prints the scenario warning, a PoC qualification, and `Signature verification passed.` The scenario line and the qualification note that the client does not inspect DNS itself. If it rejects the chain, it prints `SAFE: TLS certificate verification failed; the connection was blocked and no package was installed.`. The result depends on the runtime, not on the client code.

## Build

    mkdir -p dist
    python3 -m zipapp src -p "/usr/bin/env python3" -o dist/kirimochi.pyz
