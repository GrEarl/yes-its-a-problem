# Evidence bundle

Public evidence for the eMudhra intermediate-CA key-compromise finding:

* `proof/`, `proof.zip`: public intermediates, public keys, signatures,
  and the signed proof message.
* `impacted-intermediates.json`, `roots.json`: metadata.
* `keys/`: notes on the recovered-key layout (no key material).

No private keys are in this directory. The public material can reproduce the
key recovery: run `poc/lab/certs/recover_keys.py` against any public
intermediate.

The dates in `impacted-intermediates.json` are the revocation entries observed
in the issuing CA CRL at collection time. Re-query the CRL or OCSP before
citing a specific revocation date.
