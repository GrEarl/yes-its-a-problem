# Kirimochi

[English](README.md) | [日本語](README.ja.md)

The CLI prints English messages and accepts only `demo-lib`. It fetches a manifest and a registry-provided public key, checks the payload checksum, and verifies the manifest signature with OpenSSL. It does not install or execute the package.

This is a PoC. Kirimochi and the registry are fictional; no package is installed.

PoC site: <https://yes-its-a-problem.iamwonderingif.com/>

## Run

Run from `demo/fake-pkg`. OpenSSL is required.

Run the self-contained local checks first:

    python3 -B test_kirimochi.py

The checks create temporary synthetic keys and certificates, export and verify the public registry files, and run a packaged client against HTTPS on `127.0.0.1`. They check default-trust rejection, acceptance with the test root set for the process, hostname rejection, and manifest/payload tampering. They use no external service or affected-CA material and do not change system trust. To check an existing release candidate, add `--pyz /path/to/kirimochi.pyz`.

For a manual run with an already prepared lab certificate, start the registry.

    python3 server/mock_registry.py --port 9445 \
      --cert ../../secrets/demo-cert/fullchain.pem \
      --key ../../secrets/demo-cert/leaf.key.pem

In another shell, run the client.

    SSL_CERT_FILE=../../secrets/demo-cert/root.pem \
      python3 src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

`--connect` bypasses DNS for the registry hostname; TLS still checks the hostname in `--url`. `SSL_CERT_FILE` selects the root for this process only, modelling a client that trusts it without changing the system trust store. Unset both `SSL_CERT_FILE` and `SSL_CERT_DIR` to compare the runtime's default trust. The output records the connection override and whether either variable is set.

When TLS verification, the payload checksum, and the manifest signature pass, the client prints `OBSERVED` and exits with code `0`. The registry supplies both the verification key and the signed manifest, so this shows a valid signature under that key. It does not demonstrate signature forgery or DNS poisoning. Publisher authenticity still depends on trusting the registry.

Certificate verification failure prints `REJECTED` with the runtime's verification reason and exits with code `2`. Other TLS or connection failures print `INCONCLUSIVE` and exit with code `3`. Failed or unavailable integrity checks also exit with code `3`. No outcome installs or executes a package.

## Public registry files

Export the benign registry data for the shared lab HTTPS server:

    python3 server/mock_registry.py --export /path/to/public-registry

The directory contains `manifest.json`, `manifest.sig.b64`, `public_key.pem`, and the empty `package.tar.gz`. The temporary signing key is deleted after export and is never included in that directory. Transfer all four public files together and pass the directory to `poc/lab/http/lab_http.py --registry-dir`.

The server serves the original manifest bytes at `/manifest.json` with the stripped contents of `manifest.sig.b64` in `X-Kirimochi-Signature`, and the other two response bodies at `/public_key.pem` and `/package.tar.gz`. The payload is deliberately empty; it is not an installable archive.

## Build

    mkdir -p dist
    python3 -m zipapp src -p "/usr/bin/env python3" -o dist/kirimochi.pyz
