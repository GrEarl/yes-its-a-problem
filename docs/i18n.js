"use strict";
(function () {
  const dict = {
    ja: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS と TLS の確認",
      pocTitle: "この PoC について",
      pocBody: "このサイトは、DNS の委任応答に含まれる ADDITIONAL グルーと、回収した eMudhra 中間 CA の鍵で偽造した証明書を使う PoC を確認するページです。DNS と TLS は別々に確認します。",
      pocBody2: "再帰リゾルバが委任応答の ADDITIONAL グルーをそのまま使うと、偽のネームサーバーへ誘導されます。DNS が偽のネームサーバーを指しても、ブラウザが証明書を拒否すれば通信は成立しません。その中間状態も結果に表示します。",
      checkTitle: "確認",
      checkLead: "各ボタンは検証用エンドポイントへ HTTPS リクエストを送ります。結果はこのページ内に表示されます。",
      dnsCheckTitle: "DNS 経路",
      dnsCheckBody: "ランダムなサブドメインへ HTTPS で接続し、どちらのネームサーバーが応答したかを表示します。",
      dnsCheckBtn: "DNS を確認",
      tlsCheckTitle: "TLS 検証",
      tlsCheckBody: "偽造証明書を提示するホストへ接続し、証明書が受理されるかを確認します。接続できない場合は、有効な証明書の対照ホストへ接続できるかを調べ、証明書拒否と通信失敗の切り分けを試みます。",
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
      tlsRejected: "接続に失敗しました。有効な証明書のホストには接続できます。証明書が拒否された可能性が高いです。",
      tlsValid: "正規の証明書を受理しました。偽造証明書は提示されませんでした。",
      tlsUnknown: "接続に失敗しました。証明書拒否と通信失敗は区別できません。",
      dnsButtonBusy: "確認中...",
      tlsButtonBusy: "確認中..."
    },
    en: {
      siteName: "Yes, it's a problem",
      siteSub: "DNS and TLS checks",
      pocTitle: "About this PoC",
      pocBody: "This site checks a PoC that uses out-of-bailiwick ADDITIONAL glue in a DNS delegation response and a certificate forged with a recovered eMudhra intermediate CA private key. DNS and TLS are checked separately.",
      pocBody2: "If a recursive resolver trusts the glue, DNS is steered to a fake nameserver. Even then, the connection fails if the browser rejects the certificate. That intermediate state is shown in the result.",
      checkTitle: "Checks",
      checkLead: "Each button sends HTTPS requests to a check endpoint. Results are shown on this page.",
      dnsCheckTitle: "DNS path",
      dnsCheckBody: "Connects to a random subdomain over HTTPS and shows which nameserver answered.",
      dnsCheckBtn: "Check DNS",
      tlsCheckTitle: "TLS verification",
      tlsCheckBody: "Connects to a host presenting the forged certificate and checks whether the certificate is accepted. If the connection fails, a control request to a host with a valid certificate helps tell a certificate rejection apart from a network failure.",
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
      tlsRejected: "The connection failed. The valid certificate host is reachable; the certificate was likely rejected.",
      tlsValid: "A valid certificate was accepted; no forged certificate was presented.",
      tlsUnknown: "The connection failed. Certificate rejection and network failure cannot be distinguished.",
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
