# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

A TLS certificate demo using an Electron transfer screen.

This is a PoC. Karategata Banking is fictional; no real transfer is made.

- `legacy`: Electron 36.9.5.
- `hardened`: Electron 45.0.0.
- Both builds use the same app code. Only the Electron runtime version and the certificate/revocation data it ships differ. The app does not include code that disables certificate verification.

## Local run

Run from `demo/electron-payment`.

1. Start the HTTPS server.

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

2. Start Electron.

       npm install
       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

To try the current build, use `npx --yes electron@45.0.0`.

## Build

GitHub Actions builds the `legacy` and `hardened` demos. The CA private key and the leaf private key are not used.
