"use strict";
(function () {
  const dict = {
    ja: {
      siteName: "Yes, it's a problem",
      siteSub: "PoC: DNS と TLS の確認。空手形銀行と Kirimochi は架空のサービスで、実際の振込やインストールは行われません。",
      pocTitle: "この PoC について",
      pocBody: "このページは、DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。委任応答に含まれる ADDITIONAL グルーを使うリゾルバは、正規のネームサーバーではなく攻撃者のネームサーバーへ到達します。攻撃者のサーバーは回収した eMudhra 中間 CA の秘密鍵で署名した証明書を提示し、TLS クライアントが受理する場合があります。このラボの provider は生成したネームサーバー名についても権威を持つため、この確認は provider が ADDITIONAL に誤った A レコードを入れる状況を模擬したものであり、厳密な out-of-bailiwick の失敗ではありません。",
      pocBody2: "上の 2 つのボタンで、それぞれの段階をこのブラウザーから実行できます。このページはそれぞれの結果と、DNS と TLS を組み合わせた結果を表示します。リクエストが失敗したとき、理由はこのページからは分かりません。fetch() は証明書エラーの内容を JavaScript に渡さないため、証明書の拒否と通信の失敗は区別できません。空手形銀行と Kirimochi は架空のサービスで、実際の振込やインストールは行われません。",
      researchLink: "元の調査（第三者による）",
      checkTitle: "確認",
      checkLead: "各ボタンを押すと、検証用エンドポイントへ HTTPS リクエストを 1 回送ります。結果はこのページ内に表示されます。",
      dnsCheckTitle: "DNS 経路",
      dnsCheckBody: "ランダムなサブドメインへ HTTPS で接続し、どちらのネームサーバーが応答したかを表示します。",
      dnsCheckBtn: "DNS を確認",
      tlsCheckTitle: "TLS 検証",
      tlsCheckBody: "MITM ホストへ接続します。接続が完了したときは、受理した証明書が偽造か正規かを表示します。完了しないときは、証明書の拒否と通信の失敗を区別できません。",
      tlsCheckBtn: "TLS を確認",
      verdictTitle: "結果",
      demosTitle: "デモ",
      kbcName: "空手形銀行",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "確認中...",
      dnsPrefix: "DNS: ",
      tlsPrefix: "TLS: ",
      dnsSafe: "正規のネームサーバーが応答しました。",
      dnsBad: "偽のネームサーバーが応答しました。",
      dnsUnknown: "検証用エンドポイントに接続できなかったか、応答が不正でした。",
      tlsBad: "偽造証明書を受理しました。",
      tlsGood: "正規の証明書を受理しました。",
      tlsUnknown: "接続が完了しませんでした。証明書の拒否と通信の失敗は区別できません。",
      verdictClean: "安全: 正規のネームサーバーが応答し、TLS は正規の証明書を受理しました。",
      verdictTlsOnly: "危険: 正規のネームサーバーが応答しましたが、TLS は偽造証明書を受理しました。",
      verdictDnsSafeTlsUnknown: "判定不能: 正規のネームサーバーが応答しましたが、TLS の結果は判定できません。",
      verdictBadButValid: "注意: 偽のネームサーバーが応答しましたが、TLS は正規の証明書を受理しました。",
      verdictDanger: "危険: 偽のネームサーバーが応答し、TLS は偽造証明書を受理しました。",
      verdictStopped: "危険の可能性あり: 偽のネームサーバーに到達したものの、TLS の確認は完了しませんでした。証明書の拒否と通信の失敗は区別できないため、どちらが起きたかはこのページからは分かりません。",
      verdictUnknownDnsValid: "注意: TLS は正規の証明書を受理しましたが、DNS の結果は判定できません。",
      verdictTlsOnlyDnsUnknown: "危険: TLS は偽造証明書を受理しましたが、DNS の結果は判定できません。",
      verdictUnknown: "判定不能: どちらの結果も得られませんでした。",
      verdictNotRun: "未判定: もう一方の確認を実行すると、組み合わせた結果が表示されます。"
    },
    en: {
      siteName: "Yes, it's a problem",
      siteSub: "PoC: DNS and TLS checks. Karategata Banking and Kirimochi are fictional; no real transfer or installation is made.",
      pocTitle: "About this PoC",
      pocBody: "This page is a PoC that combines DNS delegation responses with TLS certificate verification. A resolver that uses the ADDITIONAL glue in the delegation response reaches the attacker's nameserver instead of the legitimate one. The attacker's server presents a certificate signed with a recovered eMudhra intermediate CA private key, which a TLS client may accept. In this lab the provider is also authoritative for the generated nameserver name, so the check models a provider that puts a false A record in ADDITIONAL; it is not a strict out-of-bailiwick failure.",
      pocBody2: "The two buttons above run each step from this browser. The page shows each result and the combined DNS and TLS result. When a request fails, the page cannot say why: fetch() does not expose certificate errors, so certificate rejection and connection failure are indistinguishable. Karategata Banking and Kirimochi are fictional services. No real transfer or installation is made.",
      researchLink: "Original research (third party)",
      checkTitle: "Checks",
      checkLead: "Each button sends one HTTPS request to a check endpoint. Results are shown on this page.",
      dnsCheckTitle: "DNS path",
      dnsCheckBody: "Connects to a random subdomain over HTTPS and shows which nameserver answered.",
      dnsCheckBtn: "Check DNS",
      tlsCheckTitle: "TLS verification",
      tlsCheckBody: "Connects to the MITM host. If the connection completes, the page shows whether the accepted certificate was forged or legitimate. If it does not complete, certificate rejection and connection failure cannot be distinguished.",
      tlsCheckBtn: "Check TLS",
      verdictTitle: "Result",
      demosTitle: "Demos",
      kbcName: "Karategata Banking",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "Checking...",
      dnsPrefix: "DNS: ",
      tlsPrefix: "TLS: ",
      dnsSafe: "The legitimate nameserver answered.",
      dnsBad: "The fake nameserver answered.",
      dnsUnknown: "The check endpoint was unreachable or gave no usable response.",
      tlsBad: "The forged certificate was accepted.",
      tlsGood: "The legitimate certificate was accepted.",
      tlsUnknown: "The check did not complete. Certificate rejection and network failure cannot be distinguished.",
      verdictClean: "SAFE: The legitimate nameserver answered, and TLS accepted the legitimate certificate.",
      verdictTlsOnly: "DANGER: The legitimate nameserver answered, but TLS accepted the forged certificate.",
      verdictDnsSafeTlsUnknown: "INCONCLUSIVE: The legitimate nameserver answered, but the TLS result is inconclusive.",
      verdictBadButValid: "WARNING: The fake nameserver answered, but TLS accepted the legitimate certificate.",
      verdictDanger: "DANGER: The fake nameserver answered, and TLS accepted the forged certificate.",
      verdictStopped: "POSSIBLE DANGER: The DNS check reached the fake nameserver, but the TLS check did not complete. Certificate rejection and connection failure cannot be distinguished, so the page cannot say which happened.",
      verdictUnknownDnsValid: "WARNING: TLS accepted the legitimate certificate, but the DNS result is inconclusive.",
      verdictTlsOnlyDnsUnknown: "DANGER: TLS accepted the forged certificate, but the DNS result is inconclusive.",
      verdictUnknown: "INCONCLUSIVE: Neither result could be determined.",
      verdictNotRun: "INCOMPLETE: Run the other check to see the combined result."
    }
  };

  let lang = "en";
  try {
    const query = new URLSearchParams(window.location.search).get("lang");
    const saved = localStorage.getItem("yip-lang");
    if (query === "ja" || query === "en") lang = query;
    else if (saved === "ja" || saved === "en") lang = saved;
    else {
      const first = String((navigator.languages && navigator.languages[0]) || navigator.language || "").toLowerCase();
      if (first.startsWith("ja")) lang = "ja";
    }
  } catch (_) {}

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
