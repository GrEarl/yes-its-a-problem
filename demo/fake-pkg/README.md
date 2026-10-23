# Kirimochi

[English](README.md) | [日本語](README.ja.md)

The CLI prints English messages. It fetches a manifest and a registry-provided public key, then verifies the manifest signature with OpenSSL. It does not install or execute the package.

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

If the runtime trust store accepts the forged chain, the client prints the two warning lines and `Signature verification passed.`. If it rejects the chain, it prints `BLOCKED: TLS certificate verification failed.`. The result depends on the runtime, not on the client code.

## Public registry files

Export the benign registry data for the shared lab HTTPS server:

    python3 server/mock_registry.py --export /path/to/public-registry

The directory contains `manifest.json`, `manifest.sig.b64`,
`public_key.pem`, the empty `package.tar.gz`, and the update-stage files.
Transfer all public files together and pass the directory to
`poc/lab/http/lab_http.py --registry-dir`.

## Build

    mkdir -p dist
    python3 -m zipapp src -p "/usr/bin/env python3" -o dist/kirimochi.pyz
