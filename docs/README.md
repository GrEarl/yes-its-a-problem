# docs

[English](README.md) | [日本語](README.ja.md)

Static site. There is no build step. The page supports Japanese and English, and `?lang=ja` or `?lang=en` sets the initial language. Without a query parameter, the page uses the saved choice or the browser's preferred language. The static HTML is English when scripts are unavailable; `i18n.js` switches it after load.

## Publish

1. Push the repository to GitHub.
2. Open Settings, then Pages. Choose Deploy from a branch. Use `main` and `/docs`.
3. Set the custom domain to `yes-its-a-problem.iamwonderingif.com`.
4. In Cloudflare, create a CNAME record for `yes-its-a-problem` with `<owner>.github.io` as the value. Set it to DNS only.
5. Enable Enforce HTTPS.

## Config

`config.js` contains `releasesUrl`, `labDomain`, and `mitmHost`. Match `releasesUrl` to the GitHub owner/repo. Keep `labDomain` and `mitmHost` as the check hosts.

## Checks

The DNS check requests a random label under `v.lab...` over HTTPS. `{"path":"fake"}` means the fake nameserver answered. `{"path":"true"}` means the legitimate nameserver answered. On failure the result is inconclusive.

The TLS check connects to `https://login.v.lab.../tls-probe`. `{"tls":"forged"}` means the server presented the forged certificate and the browser accepted it. `{"tls":"valid"}` means the check completed with the legitimate certificate. If the request fails, the result is inconclusive: the browser does not expose certificate errors to the page, so rejection and connection failure cannot be distinguished.

For the DNS check to return `fake`, the fake nameserver must serve a valid certificate for the random probe name and the forged certificate for the MITM host. Otherwise the browser rejects the probe response before the page can read it.

The result shows the combination of the DNS and TLS states, including the intermediate state where DNS reached the fake nameserver but TLS did not complete.
