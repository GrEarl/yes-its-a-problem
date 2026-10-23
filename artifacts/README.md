# Evidence bundle

Public evidence for the eMudhra intermediate-CA key-compromise finding:

* `proof/`: public intermediates, public keys, signatures, and the signed proof message.
* `impacted-intermediates.json`, `roots.json`: metadata.

Local-only working files, excluded from git:

* `chains/`: served certificate chains.
* `leaf/leaf.crt.pem`: public leaf certificate from the earlier demo.

Private key material is not in this directory. The recovered intermediate keys,
the recovered scalar table, the hex scalar, and the leaf private key are in
`../secrets/artifacts/` with owner-only permissions.

The public bundle can reproduce the key recovery: run
`poc/lab/certs/recover_keys.py` against any public intermediate.

The dates in `impacted-intermediates.json` are the revocation entries observed
in the issuing CA CRL at collection time. Re-query the CRL or OCSP before
citing a specific revocation date.
