# Karategata Banking / 空手形銀行

[English](README.md) | [日本語](README.ja.md)

A TLS certificate demo using an Electron transfer screen.

This is a PoC. Karategata Banking is fictional; no real transfer is made.

PoC site: <https://yes-its-a-problem.iamwonderingif.com/>

- `legacy`: Electron 36.9.5.
- `hardened`: Electron 45.0.0.
- Both builds use the same app code and TLS settings, with different Electron versions. Package names and application IDs are separate so the builds can coexist. The app does not disable certificate verification.
- The [local review recorded on 2026-10-24 at 05:51 JST](../../artifacts/review-2026-10-24.json) used macOS arm64: legacy accepted a leaf signed by a known revoked eMudhra intermediate, and hardened returned `net::ERR_CERT_AUTHORITY_INVALID`. This result has not been verified on other OSes.
- That comparison used `host-resolver-rules` to connect to the local server. It did not test DNS resolution followed by TLS on the same path. In this demo a certificate error is shown as SAFE because the HTTPS connection was blocked; it is not a claim that the network path is safe.

## Local run

Run from `demo/electron-payment`, after generating the certificates described in [poc/lab/certs/README.md](../../poc/lab/certs/README.md). The API URL must use HTTPS; redirects are rejected.

1. Start the HTTPS server.

       python3 ../../poc/lab/http/lab_http.py --role fake --bind 127.0.0.1 --port 9443 \
         --cert ../../secrets/demo-cert/fullchain.pem \
         --key ../../secrets/demo-cert/leaf.key.pem

2. Start Electron.

       npx --yes electron@36.9.5 . \
         --kbc-api-url=https://pay.v.lab.yes-its-a-problem.iamwonderingif.com:9443 \
         --host-resolver-rules="MAP pay.v.lab.yes-its-a-problem.iamwonderingif.com 127.0.0.1"

To try the current build, use `npx --yes electron@45.0.0`.

Run `node test.js` for the local response-handling checks. They use stubbed IPC and networking and do not test Electron's TLS implementation.

## Build

GitHub Actions builds the `legacy` and `hardened` demos with the flavor arguments in the [release workflow](../../.github/workflows/release.yml). The CA private key and the leaf private key are not used. The project MIT license is included in the app resources.

macOS beta builds use ad-hoc code signatures; they do not have a Developer ID signature or Apple notarization.
