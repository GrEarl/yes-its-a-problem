"use strict";
(function () {
  const dict = {
    ja: {
      siteName: "Yes, it's a problem",
      siteSub: "PoC: DNS と TLS の確認。空手形銀行と Kirimochi は架空のサービスで、実際の振込やインストールは行われません。",
      statusNote: "Beta: 公開環境は未検証です。ローカルの確認だけでは、公開 DNS の挙動やブラウザーの証明書受理を証明できません。",
      pocTitle: "この PoC について",
      pocBody: "このページは DNS 委任応答と TLS 証明書の扱いを試すラボです。ローカルの DNS 確認は、管理下の権威サーバーが返す委任応答と A レコードの比較です。再帰リゾルバの挙動や実際の欠陥を実証するものではありません。TLS の確認では、回収された eMudhra 中間 CA 鍵で署名した証明書についてサーバーが報告する結果を読みます。",
      pocBody2: "2 つのボタンは、別々のホストから HTTPS 応答を取得します。DNS は到達先の役割、TLS はサーバーの証明書報告を表示します。同じ通信で二段階の攻撃が成立した証拠にはなりません。fetch() は証明書エラーの内容を JavaScript に渡さないため、接続失敗の理由は判定できません。",
      certStatus: "対象の中間 CA は失効済みです。インシデント報告によると、Firefox と Chrome は 2026 年 10 月 17 日から、Microsoft 製品は 20 日から、Apple 製品は 22 日からブロックしています。失効情報や Certificate Transparency を使わないクライアントは、更新まで影響を受ける場合があります。この確認結果は使用中のブラウザーだけを示し、別のクライアントの結果を予測しません。",
      sourcesTitle: "出典と警告",
      sourceResearch: "元の調査と報告（第三者、報告者 Wayne）",
      sourceProof: "証明バンドル（8 本の中間 CA の署名）",
      sourceChains: "公開されている証明書チェーン（14 ホスト）",
      sourceMozillaBug: "Mozilla のインシデント報告",
      sourceMozillaThread: "Mozilla dev-security-policy の議論",
      sourceCrlsets: "Chromium の CRLSet",
      sourcePatched: "各 OS・ディストリの修正版",
      dnsSourcesTitle: "DNS の観測記録と背景",
      dnsSourcesNote: "公開事例について記録した委任応答には、外部 NS 名への ADDITIONAL A が含まれていました。これは RFC 9471 の sibling glue ではありません。記録の範囲と来歴はリンク先を参照してください。このラボのローカル確認とは別の観測です。",
      sourceDnsObservation: "公開 DNS 事例の観測記録（2026 年 10 月 24 日、範囲と来歴を含む）",
      sourceCloudflare: "Cloudflare Community: 無関係な ADDITIONAL がある場合に 1.1.1.1 が誤った A レコードを返す件",
      sourceStaleGlue: "Rethinking the Security Threats of Stale DNS Glue Records（USENIX Security 2024）",
      sourceStaleGlueTalk: "USENIX Security 2024 発表ページ",
      sourceIscStrictGlue: "ISC BIND: Operational Notification: Impact of Stricter Glue Checking",

      checkTitle: "確認",
      checkLead: "各ボタンを押すと、検証用エンドポイントへ HTTPS リクエストを 1 回送ります。結果はこのページ内に表示されます。",
      dnsCheckTitle: "DNS 経路",
      dnsCheckBody: "ランダムなサブドメインへ HTTPS で接続し、正規側・偽装側のどちらのサーバーに到達したかを表示します。DNS の問い合わせ自体をブラウザーから観測するものではありません。",
      dnsCheckBtn: "DNS を確認",
      tlsCheckTitle: "TLS 検証",
      tlsCheckBody: "MITM ホストは、提示したリーフ証明書の分類と SHA-256 指紋を返します。このページはブラウザーが受け取った証明書を直接読み取れません。接続失敗時は、証明書の拒否と通信の失敗を区別できません。",
      tlsCheckBtn: "TLS を確認",
      verdictTitle: "結果",
      demosTitle: "PoC",
      kbcName: "空手形銀行",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "確認中...",
      dnsPrefix: "DNS: ",
      tlsPrefix: "TLS: ",
      dnsSafe: "正規側の HTTPS サーバーに到達しました。",
      dnsBad: "偽装側の HTTPS サーバーに到達しました。",
      dnsUnknown: "検証用エンドポイントに接続できなかったか、応答が不正でした。",
      tlsBad: "HTTPS 応答を受け取りました。サーバーは、既知の危殆化 CA が署名した証明書を提示したと報告しています。",
      tlsGood: "HTTPS 応答を受け取りました。サーバーは別の証明書を報告しています。危殆化 CA の証明書を拒否するかは未判定です。",
      tlsUnknown: "有効な確認結果を得られませんでした。この結果だけでは、証明書の拒否、通信の失敗、応答の不備を区別できません。",
      verdictClean: "観測結果: DNS の確認は正規側へ到達し、TLS サーバーは別の証明書を報告しました。偽造証明書の拒否は未判定です。",
      verdictTlsOnly: "観測結果: DNS の確認は正規側へ到達し、TLS サーバーは危殆化 CA が署名した証明書を報告しました。",
      verdictDnsSafeTlsUnknown: "判定不能: 正規側へ到達しましたが、TLS の結果は判定できません。",
      verdictBadButValid: "注意: DNS の確認は偽装側へ到達し、TLS サーバーは別の証明書を報告しました。偽造証明書の拒否は未判定です。",
      verdictDanger: "観測結果: DNS の確認は偽装側へ到達し、TLS サーバーは危殆化 CA が署名した証明書を報告しました。別々の接続で得た結果です。",
      verdictStopped: "危険の可能性あり: DNS の確認は偽装側の HTTPS サーバーへ到達しましたが、TLS の結果は判定できません。",
      verdictUnknownDnsValid: "注意: TLS サーバーは別の証明書を報告しましたが、DNS の結果と偽造証明書の拒否は未判定です。",
      verdictTlsOnlyDnsUnknown: "観測結果: TLS サーバーは危殆化 CA が署名した証明書を報告しましたが、DNS の結果は判定できません。",
      verdictUnknown: "判定不能: どちらの結果も得られませんでした。",
      verdictNotRun: "未判定: もう一方の確認を実行すると、組み合わせた結果が表示されます。"
    },
    en: {
      siteName: "Yes, it's a problem",
      siteSub: "PoC: DNS and TLS checks. Karategata Banking and Kirimochi are fictional; no real transfer or installation is made.",
      statusNote: "Beta: The public deployment has not been verified. Local checks do not establish public DNS behavior or browser certificate acceptance.",
      pocTitle: "About this PoC",
      pocBody: "This page is a lab for DNS delegation responses and TLS certificate handling. The local DNS checks compare referrals and A records returned by controlled authoritative servers; they do not test a recursive resolver or prove a live resolver defect. The TLS check reads the server's report for a certificate signed with a recovered eMudhra intermediate CA key.",
      pocBody2: "The two buttons fetch HTTPS responses from separate hosts. The DNS check reports the server role reached; the TLS check displays the server's certificate report. These results do not prove that a two-stage attack succeeded on one connection. A failed fetch() does not expose the reason, so certificate rejection and connection failure cannot be distinguished.",
      certStatus: "The compromised intermediates have been revoked. The incident report says Firefox and Chrome block them from 17 October 2026, Microsoft platforms from 20 October, and Apple products from 22 October. Clients that do not use revocation information or Certificate Transparency may remain affected until updated. This check reports only this browser's connection and does not predict another client's result.",
      sourcesTitle: "Sources and advisories",
      sourceResearch: "Original research and report (third party, reporter Wayne)",
      sourceProof: "Proof bundle (eight intermediate CA signatures)",
      sourceChains: "Published certificate chains (14 hosts)",
      sourceMozillaBug: "Mozilla incident report",
      sourceMozillaThread: "Mozilla dev-security-policy thread",
      sourceCrlsets: "Chromium CRLSets",
      sourcePatched: "Patched versions by OS and distribution",
      dnsSourcesTitle: "DNS observations and background",
      dnsSourcesNote: "The recorded public-case referral included an ADDITIONAL A record for an external nameserver. This is not RFC 9471 sibling glue. See the linked record for scope and provenance; it is separate from this lab's local checks.",
      sourceDnsObservation: "Public DNS observation (24 October 2026, including scope and provenance)",
      sourceCloudflare: "Cloudflare Community: 1.1.1.1 returns a wrong A record with an unrelated ADDITIONAL",
      sourceStaleGlue: "Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)",
      sourceStaleGlueTalk: "USENIX Security 2024 presentation",
      sourceIscStrictGlue: "ISC BIND: Operational Notification: Impact of Stricter Glue Checking",

      checkTitle: "Checks",
      checkLead: "Each button sends one HTTPS request to a check endpoint. Results are shown on this page.",
      dnsCheckTitle: "DNS path",
      dnsCheckBody: "Connects to a random subdomain over HTTPS and reports which lab server was reached. The browser does not observe the DNS queries themselves.",
      dnsCheckBtn: "Check DNS",
      tlsCheckTitle: "TLS verification",
      tlsCheckBody: "The MITM host reports the classification and SHA-256 fingerprint of the leaf certificate it served. This page cannot read the browser's peer certificate directly. On connection failure, certificate rejection and network failure cannot be distinguished.",
      tlsCheckBtn: "Check TLS",
      verdictTitle: "Result",
      demosTitle: "PoC",
      kbcName: "Karategata Banking",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "Checking...",
      dnsPrefix: "DNS: ",
      tlsPrefix: "TLS: ",
      dnsSafe: "The legitimate HTTPS server was reached.",
      dnsBad: "The fake HTTPS server was reached.",
      dnsUnknown: "The check endpoint was unreachable or gave no usable response.",
      tlsBad: "An HTTPS response was received. The server reports serving a leaf signed by a known compromised CA.",
      tlsGood: "An HTTPS response was received. The server reports a different certificate. Rejection of the compromised certificate has not been tested.",
      tlsUnknown: "No usable check result was obtained. This result alone cannot distinguish certificate rejection, network failure, and an invalid response.",
      verdictClean: "OBSERVED: The DNS check reached the legitimate server, and the TLS server reported a different certificate. Rejection of the forged certificate has not been established.",
      verdictTlsOnly: "OBSERVED: The DNS check reached the legitimate server, and the TLS server reported a leaf signed by a compromised CA.",
      verdictDnsSafeTlsUnknown: "INCONCLUSIVE: The legitimate server was reached, but the TLS result is inconclusive.",
      verdictBadButValid: "WARNING: The DNS check reached the fake server, and the TLS server reported a different certificate. Rejection of the forged certificate has not been established.",
      verdictDanger: "OBSERVED: The DNS check reached the fake server, and the TLS server reported a leaf signed by a compromised CA. These results came from separate connections.",
      verdictStopped: "POSSIBLE DANGER: The DNS check reached the fake HTTPS server, but the TLS result is inconclusive.",
      verdictUnknownDnsValid: "WARNING: The TLS server reported a different certificate; DNS routing and rejection of the forged certificate remain inconclusive.",
      verdictTlsOnlyDnsUnknown: "OBSERVED: The TLS server reported a leaf signed by a compromised CA, but the DNS result is inconclusive.",
      verdictUnknown: "INCONCLUSIVE: Neither result could be determined.",
      verdictNotRun: "INCOMPLETE: Run the other check to see the combined result."
    }
  };

  let lang = "en";
  const query = new URLSearchParams(window.location.search).get("lang");
  let saved = null;
  try { saved = localStorage.getItem("yip-lang"); } catch (_) {}
  if (query === "ja" || query === "en") lang = query;
  else if (saved === "ja" || saved === "en") lang = saved;
  else {
    const first = String((navigator.languages && navigator.languages[0]) || navigator.language || "").toLowerCase();
    if (first.startsWith("ja")) lang = "ja";
  }

  function t(key) {
    return (dict[lang] && dict[lang][key]) || dict.en[key] || key;
  }
  function apply() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    document.documentElement.lang = lang;
    document.querySelectorAll(".lang-btn").forEach((b) => {
      b.classList.toggle("active", b.id === "lang-" + lang);
    });
  }
  function setLang(next) {
    if (next !== "ja" && next !== "en") return;
    lang = next;
    try { localStorage.setItem("yip-lang", lang); } catch (_) {}
    apply();
  }
  window.YIP_I18N = { t, apply, setLang };
})();
