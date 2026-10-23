# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

A TLS certificate demo using an Electron transfer screen.

- `config/legacy.json`: settings for the legacy build. Start it with `electron@36.9.5`.
- `config/hardened.json`: settings for the current build. Start it with `electron@45.0.0`.
- The legacy build uses its certificate store from that time. The app does not include code that disables certificate verification.

## Local run

Run from `demo/electron-payment`.

1. Copy a config file.

       cp config/legacy.json demo-config.json

2. Start the HTTPS server.

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

3. Start Electron.

       npm install
       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

To try the current build, copy `config/hardened.json` and use `npx --yes electron@45.0.0`.

## Build

GitHub Actions builds the `legacy` and `hardened` demos. The CA private key and the leaf private key are not used.
