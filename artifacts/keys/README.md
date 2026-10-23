# Recovered private keys

The eight recovered intermediate private keys and the scalar table are in
`../../secrets/artifacts/keys/`.

The public intermediates are in `../chains/` (local only) and `../proof/`.
Recover a key locally with:

    python3 poc/lab/certs/recover_keys.py <public-intermediate.pem>

The recovered key is written next to the input.
