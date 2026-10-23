"use strict";
(function () {
  const dict = {
    ja: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS と TLS の確認",
      checkTitle: "確認",
      checkLead: "各ボタンは検証環境のエンドポイントへ HTTPS リクエストを 1 回送ります。結果はこのページ内に表示されます。",
      dnsCheckTitle: "DNS 経路",
      dnsCheckBody: "ランダムなサブドメインを問い合わせ、どちらのネームサーバーが応答したかを表示します。",
      dnsCheckBtn: "DNS を確認",
      tlsCheckTitle: "TLS 検証",
      tlsCheckBody: "偽造証明書を提示するホストへ接続します。受理した場合だけ結果を表示し、拒否と通信失敗は判定不能とします。",
      tlsCheckBtn: "TLS を確認",
      verdictTitle: "結果",
      demosTitle: "デモ",
      kbcName: "空手形銀行",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "確認中...",
      dnsSafe: "正規のネームサーバーが応答しました。",
      dnsBad: "偽のネームサーバーが応答しました。",
      dnsUnknown: "検証環境に接続できないか、応答を確認できませんでした。",
      tlsBad: "偽造証明書を受理しました。",
      tlsUnknown: "証明書が拒否されたか、通信に失敗したかは区別できません。",
      verdictDanger: "DNS は偽のネームサーバー、TLS は偽造証明書を受理しました。",
      verdictMixed: "一方の結果のみ確認されました。",
      verdictUnknown: "どちらも判定できませんでした。",
      dnsButtonBusy: "確認中...",
      tlsButtonBusy: "確認中..."
    },
    en: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS and TLS checks",
      checkTitle: "Checks",
      checkLead: "Each button sends one HTTPS request to a check endpoint. Results are shown on this page.",
      dnsCheckTitle: "DNS path",
      dnsCheckBody: "Requests a random subdomain and shows which nameserver answered.",
      dnsCheckBtn: "Check DNS",
      tlsCheckTitle: "TLS verification",
      tlsCheckBody: "Connects to a host presenting the forged certificate. A result is shown only when it was accepted; rejection and connection failure are both inconclusive.",
      tlsCheckBtn: "Check TLS",
      verdictTitle: "Result",
      demosTitle: "Demos",
      kbcName: "Karategata Banking",
      kiriName: "Kirimochi",
      footerRepo: "Releases",
      checking: "Checking...",
      dnsSafe: "The legitimate nameserver answered.",
      dnsBad: "The forged nameserver answered.",
      dnsUnknown: "The check endpoint was unreachable or gave no usable response.",
      tlsBad: "The forged certificate was accepted.",
      tlsUnknown: "Certificate rejection and connection failure cannot be distinguished.",
      verdictDanger: "DNS answered with the forged nameserver, and TLS accepted the forged certificate.",
      verdictMixed: "Only one result was confirmed.",
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
