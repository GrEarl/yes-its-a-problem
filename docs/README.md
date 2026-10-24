# docs

[English](README.md) | [日本語](README.ja.md)

Static site. There is no build step. The page supports Japanese and English, and `?lang=ja` or `?lang=en` sets the initial language. Without a query parameter, the page uses the saved choice or the browser's preferred language. The static HTML is English when scripts are unavailable; `i18n.js` switches it after load.

## Publish

Run `node docs/test.js` from the repository root before publishing. This uses a small DOM and fetch substitute to check response validation, language changes, and pending/error states. It makes no network requests and does not verify DNS routing, CORS, certificate trust, or a public deployment. See [the deployment runbook](../poc/deploy/README.md) for the remaining DNS, VPS, and certificate prerequisites.

1. Push the repository to GitHub.
2. Open Settings, then Pages. Choose Deploy from a branch. Use `main` and `/docs`.
3. Set the custom domain to `yes-its-a-problem.iamwonderingif.com`. `docs/CNAME` already contains it.
4. In Cloudflare, create a CNAME record for `yes-its-a-problem` with `<owner>.github.io` as the value. Set it to DNS only.
5. Enable Enforce HTTPS.

## Config

`config.js` contains `releasesUrl`, `labDomain`, and `mitmHost`. Match `releasesUrl` to the GitHub owner/repo. Keep `labDomain` and `mitmHost` as the check hosts.

## Checks

The DNS check requests a random label under `v.lab...` over HTTPS. A response with matching `token` and `host` values and `"path":"fake"` reports the fake HTTPS server; `"path":"true"` reports the legitimate HTTPS server. The browser does not observe the DNS queries themselves. A failed request, redirect, or unusable response is inconclusive.

The TLS check connects to `https://login.v.lab.../tls-probe`. The response must echo the expected `host` and include a 64-character lowercase hexadecimal `leaf_sha256`. `"tls":"forged"` also requires an `issuer_spki_sha256` in that format and means the server reports serving a leaf signed by a known compromised CA. `"tls":"other"` reports a different certificate; it does not prove rejection of the compromised certificate. The page cannot read the browser's peer certificate, so it validates the response format without independently comparing those fingerprints to the connection. A failed request, redirect, missing or unknown status, or unusable response is inconclusive. The browser does not expose certificate errors to the page, so rejection and connection failure cannot be distinguished.

For the DNS check to return `fake`, the fake HTTPS server must serve a certificate the browser accepts for the random probe name. Otherwise the browser rejects the probe response before the page can read it. The MITM host's certificate is used only by the separate TLS check.

The page combines separate DNS and TLS connections. Their results do not show that both stages succeeded on one connection. The compromised intermediates have been revoked; consult the source linked on the page for current platform status. Results apply only to the browser that ran the check.

Serve the lab HTTPS endpoints directly from their configured TLS contexts. A CDN or reverse proxy that terminates TLS would make the backend's certificate report describe a different connection. Publishing the static page alone does not verify the lab endpoints; confirm their actual certificates, CORS responses, DNS paths, and browser behavior after deployment.

The [recorded third-party public DNS case](../artifacts/dns-authority-trace-2026-10-24.json) includes an ADDITIONAL A for an external NS name, not RFC 9471 sibling glue. Its scope and provenance are recorded in that file. It is separate from this repository's local comparison of authoritative DNS records and does not establish a complete DNS-to-TLS attack.
