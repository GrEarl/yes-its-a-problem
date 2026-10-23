# Security policy

This repository is a controlled lab, not a production service. Run it only
against names and systems you control.

The source includes a script that recovers the compromised eMudhra
intermediate CA private keys from their public certificates. The weak key
generation makes this reproducible, but the recovered keys can sign
certificates for arbitrary names in clients that still trust the
intermediates. The CA has revoked them and major platforms report blocking
them; how many clients still require updates is unquantified. The repository
does not include private keys; the recovery script writes them locally. Keep
them in ignored `secrets/`, do not copy CA keys to a public server, and use
only the lab names for the forged leaf certificate.

The positions shown here (misdirected resolution, and a client that accepts a
forged certificate) are also the delivery position for client-side code
execution. The two have been demonstrated separately, not on one path.
CVE-2026-111497 ("Node2Shell" / "HTTP2Shell") is an out-of-bounds write in
the Brotli decoder bundled with Node.js and the PyPI Brotli package, fixed in
Node 22.23.4 / 24.22.1 / 26.12.1 and Brotli 1.2.1 / brotlicffi 1.2.1.0. Keep
the runtimes and decoders you use patched per the linked advisories. For
Electron the patch criterion is the Chromium version, not the Node version:
Electron links Chromium's `//third_party/brotli`, so Electron 41 and below
(Chromium below 148) is affected and Electron 42 and above is not.

Report bugs in this repository's code or documentation through GitHub's
private security advisory feature. Do not include private keys or credentials
in an issue. The eMudhra intermediate CA compromise is already public and the
affected certificates are revoked; do not use this repository to test
third-party systems or serve forged certificates for names you do not control.

The software is provided under the MIT License, without warranty.
