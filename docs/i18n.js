"use strict";
(function () {
  const dict = {
    ja: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS と TLS の確認",
      pocTitle: "この PoC について",
      pocBody: "このページは、DNS の委任応答と TLS の証明書検証を組み合わせた PoC です。委任応答に含まれる out-of-bailiwick の ADDITIONAL グルーを使うリゾルバは、正規ではなく攻撃者のネームサーバーへ到達します。攻撃者のサーバーは回収した eMudhra 中間 CA の秘密鍵で署名した証明書を提示し、TLS クライアントが受理する場合があります。",
      pocBody2: "下の 2 つのボタンは、それぞれの段階をこのブラウザーから実行します。このページはそれぞれの結果と、DNS と TLS を組み合わせた結果を表示します。リクエストが失敗したとき、理由はこのページからは分かりません。fetch() は証明書エラーの内容を JavaScript に渡さないため、証明書の拒否と通信の失敗は区別できません。",
      researchLink: "元の調査（第三者）",
      checkTitle: "確認",
      checkLead: "各ボタンは検証用エンドポイントへ HTTPS リクエストを 1 回送ります。結果はこのページ内に表示されます。",
      dnsCheckTitle: "DNS 経路",
      dnsCheckBody: "ランダムなサブドメインへ HTTPS で接続し、どちらのネームサーバーが応答したかを表示します。",
      dnsCheckBtn: "DNS を確認",
      tlsCheckTitle: "TLS 検証",
      tlsCheckBody: "偽造証明書を提示するホストへ接続します。接続が完了したときは、提示された証明書を表示します。完了しないときは、証明書の拒否と通信の失敗を区別できません。",
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
      dnsUnknown: "検証環境に接続できないか、応答が不正でした。",
      tlsBad: "偽造証明書を受理しました。",
      tlsGood: "正規の証明書を受理しました。",
      tlsUnknown: "接続が完了しませんでした。証明書の拒否と通信の失敗は区別できません。",
      verdictClean: "DNS は正規のネームサーバー、TLS は正規の証明書を受理しました。",
      verdictTlsOnly: "DNS は正規のネームサーバー、TLS は偽造証明書を受理しました。",
      verdictDnsSafeTlsUnknown: "DNS は正規のネームサーバー。TLS の結果は判定できません。",
      verdictBadButValid: "DNS は偽のネームサーバー、TLS は正規の証明書を受理しました。",
      verdictDanger: "DNS は偽のネームサーバー、TLS は偽造証明書を受理しました。",
      verdictStopped: "DNS の確認は偽のネームサーバーに到達しましたが、TLS の確認は完了しませんでした。証明書の拒否と通信の失敗は区別できないため、どちらが起きたかはこのページからは分かりません。",
      verdictUnknownDnsValid: "TLS は正規の証明書を受理しました。DNS の結果は判定できません。",
      verdictTlsOnlyDnsUnknown: "TLS は偽造証明書を受理しました。DNS の結果は判定できません。",
      verdictUnknown: "どちらも判定できませんでした。",
      dnsButtonBusy: "確認中...",
      tlsButtonBusy: "確認中..."
    },
    en: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS and TLS checks",
      pocTitle: "About this PoC",
      pocBody: "This page is a PoC that combines DNS delegation responses with TLS certificate verification. A resolver that uses the out-of-bailiwick ADDITIONAL glue in the delegation response reaches the attacker's nameserver instead of the legitimate one. The attacker's server presents a certificate signed with a recovered eMudhra intermediate CA private key, which a TLS client may accept.",
      pocBody2: "The two buttons below run each step from this browser. The page shows each result and the combined DNS and TLS result. When a request fails, the page cannot say why: fetch() does not expose certificate errors, so certificate rejection and connection failure are indistinguishable.",
      researchLink: "Original research (third party)",
      checkTitle: "Checks",
      checkLead: "Each button sends one HTTPS request to a check endpoint. Results are shown on this page.",
      dnsCheckTitle: "DNS path",
      dnsCheckBody: "Connects to a random subdomain over HTTPS and shows which nameserver answered.",
      dnsCheckBtn: "Check DNS",
      tlsCheckTitle: "TLS verification",
      tlsCheckBody: "Connects to the host that presents the forged certificate. If the connection completes, the page shows which certificate was presented. If it does not complete, certificate rejection and connection failure cannot be distinguished.",
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
      verdictClean: "DNS answered with the legitimate nameserver, and TLS accepted the legitimate certificate.",
      verdictTlsOnly: "DNS answered with the legitimate nameserver, and TLS accepted the forged certificate.",
      verdictDnsSafeTlsUnknown: "DNS answered with the legitimate nameserver. The TLS result is inconclusive.",
      verdictBadButValid: "DNS answered with the fake nameserver, and TLS accepted the legitimate certificate.",
      verdictDanger: "DNS answered with the fake nameserver, and TLS accepted the forged certificate.",
      verdictStopped: "The DNS check reached the fake nameserver, but the TLS check did not complete. Certificate rejection and connection failure cannot be distinguished, so the page cannot say which happened.",
      verdictUnknownDnsValid: "TLS accepted the legitimate certificate. The DNS result is inconclusive.",
      verdictTlsOnlyDnsUnknown: "TLS accepted the forged certificate. The DNS result is inconclusive.",
      verdictUnknown: "Neither result could be determined.",
      dnsButtonBusy: "Checking...",
      tlsButtonBusy: "Checking..."
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
    window.dispatchEvent(new CustomEvent("yip-lang", { detail: lang }));
  }
  window.YIP_I18N = { t, apply, setLang, getLang: () => lang };
})();
