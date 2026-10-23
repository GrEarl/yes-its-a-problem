# docs

[English](README.md) | [日本語](README.ja.md)

Static site. There is no build step. The page supports Japanese and English, and `?lang=ja` or `?lang=en` sets the initial language. Without a query parameter, the page uses the saved choice or the browser language.

## Publish

1. Push the repository to GitHub.
2. Open Settings, then Pages. Choose Deploy from a branch. Use `main` and `/docs`.
3. Set the custom domain to `yes-its-a-problem.iamwonderingif.com`.
4. In Cloudflare, create a CNAME record for `yes-its-a-problem` with `<owner>.github.io` as the value. Set it to DNS only.
5. Enable Enforce HTTPS.

## Config

`config.js` contains `repoUrl` and `releasesUrl`. `labDomain` and `mitmHost` are the check hosts.

## Checks

The DNS check requests a random label under `v.lab...` over HTTPS. `{"path":"fake"}` means the forged nameserver answered. `{"path":"true"}` means the legitimate nameserver answered. On failure the result is inconclusive.

The TLS check connects to `https://login.v.lab.../tls-probe`. `{"tls":"forged"}` is the test server saying it presented the forged certificate. If the browser rejects the certificate, the response does not arrive and the result is inconclusive.
