# DNS + TLS MITM PoC: design

[English](PLAN.md) | [日本語](PLAN.ja.md)

## 1. Chain

1. A recursive resolver uses an ADDITIONAL A record from a parent zone referral. It uses the supplied address instead of resolving the nameserver name independently.
2. Some TLS clients accept a certificate forged with a recovered eMudhra intermediate CA private key.

## 2. Names

    public site:  https://yes-its-a-problem.iamwonderingif.com
    parent zone:  iamwonderingif.com (Cloudflare)
    lab zone:     lab.yes-its-a-problem.iamwonderingif.com -> IP1
    child zone:   v.lab.yes-its-a-problem.iamwonderingif.com
    probe:        <random>.v.lab.yes-its-a-problem.iamwonderingif.com
    MITM host:    login.v.lab.yes-its-a-problem.iamwonderingif.com

## 3. DNS roles

    IP1  provider  authoritative for the lab zone. Returns a referral with
                    NS ns<hash>.true.lab... and an ADDITIONAL A record
                    pointing at IP2. Also answers A for ns*.true.lab... = IP3.
    IP3  true NS   serves the real A records and a valid certificate for the
                    resolver probe.
    IP2  fake NS   serves forged A records and the forged eMudhra certificate
                    for the MITM host. It serves the valid wildcard
                    certificate for the random probe names, so the DNS check
                    can return path=fake.

Note: in this lab, IP1 is also authoritative for ns<hash>.true.<zone>, so
the ADDITIONAL A is authoritative data from the same provider. The model
shows the data flow, not a strict out-of-bailiwick failure.

Safe resolver

    resolver -> IP1: referral, NS nsX.true..., ADDITIONAL IP2
    resolver ignores ADDITIONAL
    resolver -> IP1: A nsX.true... = IP3
    resolver -> IP3: A <probe> = IP3
    probe response: {"path":"true"}

Vulnerable resolver

    resolver -> IP1: same referral
    resolver uses nsX.true... = IP2 from ADDITIONAL
    resolver -> IP2: A <probe> = IP2
    probe response: {"path":"fake"}

## 4. HTTP checks

    GET https://<random>.v.lab.../probe  -> {"path":"true"|"fake"}
    GET https://login.v.lab.../tls-probe -> {"tls":"forged"} from the forged context

DNS and TLS are checked separately. The page shows the result in the browser only.

## 5. Certificates

`poc/lab/certs/make_leaf.py` creates a leaf signed by the recovered EM DV TLS CA - G3B private key. The chain uses the AAA Certificate Services cross-signature. Private keys stay in `secrets/` and are not published.

The leaf is created by the recovered intermediate key, not by a public CA. The probe host uses the same leaf chain.

## 6. Demos

- `demo/electron-payment/`: KBC transfer screen. `legacy` uses Electron 36.9.5; `hardened` uses Electron 45.0.0.
- `demo/fake-pkg/`: Kirimochi, English-only package manager demo. It fetches a manifest and verifies its signature with a registry-supplied, unpinned key.

## 7. Deployment

1. Create the Cloudflare DNS records and delegation.
2. Start the three DNS roles and the HTTP servers on the VPS addresses. Pass `--bind 0.0.0.0` explicitly for the public HTTP servers.
3. Run `poc/lab/certs/make_leaf.py` with the recovered CA private key. Use the resulting leaf for the probe hosts.
4. Start one HTTP server with the valid certificate and one with the forged certificate.
5. Publish `docs/` with GitHub Pages.
6. Do not enable `lab_http.py --log` on the public lab; it records visitor IP addresses and User-Agent strings.
