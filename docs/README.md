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

`config.js` contains `releasesUrl`, `labDomain`, `mitmHost`, and `controlUrl`. Match `releasesUrl` to the GitHub owner/repo. Keep `labDomain` and `mitmHost` as the check hosts. `controlUrl` is a host with a valid certificate, used as a best-effort control for certificate rejection.

## Checks

The DNS check requests a random label under `v.lab...` over HTTPS. `{"path":"fake"}` means the forged nameserver answered. `{"path":"true"}` means the legitimate nameserver answered. On failure the result is inconclusive.

The TLS check connects to `https://login.v.lab.../tls-probe`. `{"tls":"forged"}` means the server presented the forged certificate and the browser accepted it. `{"tls":"valid"}` means the connection completed with a valid certificate. If the request fails, the page checks `controlUrl`; a reachable control host is consistent with certificate rejection, but does not prove it. The browser does not expose the certificate error itself.

For the DNS check to return `fake`, the forged nameserver must serve a valid certificate for the random probe name and the forged certificate for the MITM host. Otherwise the browser rejects the probe response before the page can read it.

The result shows the DNS and TLS states separately, including forged DNS with a failed TLS connection that is consistent with certificate rejection. The two checks are independent requests; the result does not observe a single connection.
