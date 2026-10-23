"use strict";
/**
 * Update-stage policy for the yes-its-a-problem demo chain. Lab only.
 *
 * Shared by demo/electron-payment/main.js (the Electron update check) and
 * poc/lab/http/brotli_decode_probe.js (the same logic run under a pinned Node
 * runtime). It models the Squirrel-style update step of the demo chain: fetch
 * an update feed, fetch the update body, and decide whether that body reaches
 * a Brotli decoder.
 *
 * This file contains no exploit code and no malformed-stream generator. Every
 * body it decodes is a valid Brotli lab marker (see poc/lab/http/check_brotli.py).
 *
 * Two decode PATHS are modelled deliberately, because they decide which
 * pre-decode control is even possible (see poc/PLAN.md §1):
 *
 *   stack "node:zlib"        the app downloads a .br artifact and decompresses
 *                            it itself with node:zlib (streaming
 *                            createBrotliDecompress, the entry point class the
 *                            CVE-2026-111497 advisory names). The app sees the
 *                            compressed bytes, so verify-before-decode (Pair B)
 *                            is possible on this path.
 *   stack "chromium"         the body arrives with Content-Encoding: br and
 *                            net.fetch / the renderer decode it inside
 *                            Chromium. The app never sees the compressed bytes,
 *                            so the pre-decode control on this path is the
 *                            content-encoding policy (Pair C), not a digest.
 *
 * Which Brotli copy actually runs does NOT depend on the path: an Electron
 * binary links exactly one decoder - Chromium's //third_party/brotli (Electron's
 * GN patch replaces Node's deps/brotli with it), so both paths, plus global
 * fetch(), land in the same library and its fix status tracks the CHROMIUM
 * version (>= 148 fixed), not the Node version. In plain Node the decoder is
 * Node's own vendored deps/brotli and the fix status tracks the Node line.
 * decoderFingerprint() encodes exactly that rule.
 *
 * Decision markers (one per request):
 *   TLS_REJECTED, SIG_REJECTED, ENCODING_REJECTED, DECODED, ACCEPTED,
 *   INCONCLUSIVE
 */

const DECISION = Object.freeze({
  DECODED: "DECODED",
  ACCEPTED: "ACCEPTED",
  SIG_REJECTED: "SIG_REJECTED",
  ENCODING_REJECTED: "ENCODING_REJECTED",
  TLS_REJECTED: "TLS_REJECTED",
  INCONCLUSIVE: "INCONCLUSIVE"
});

// Fixed Node baselines for CVE-2026-111497. Applies to PLAIN Node, which
// vendors its own deps/brotli. It is the wrong test for Electron: Electron's GN
// patch (patches/node/build_add_gn_build_files.patch) replaces deps/brotli with
// Chromium's //third_party/brotli, so an Electron binary has ONE Brotli decoder
// shared by net.fetch, the renderer, global fetch() and node:zlib alike
// (see poc/PLAN.md §1).
const NODE_FIXED = Object.freeze([[22, 23, 4], [24, 22, 1], [26, 12, 1]]);
// For Electron/Chromium the fix boundary is the CHROMIUM major version:
// Chromium >= 148 (Electron >= 42) carries the fixed brotli pin cfa184a9;
// Chromium 147 and older carry the pre-fix snapshot.
const CHROMIUM_FIXED_MAJOR = 148;
// Electron builds used by the demo flavors, with the Brotli actually linked in.
const DEMO_ELECTRON = Object.freeze({
  legacy: { electron: "36.9.5", chrome: "136.0.7103.177", brotli: "1.0.9-era snapshot", status: "vulnerable" },
  hardened: { electron: "45.0.0", chrome: "156.0.8078.48", brotli: "cfa184a9", status: "fixed" }
});

function parseVersion(text) {
  if (typeof text !== "string") return null;
  const match = /([0-9]+)\.([0-9]+)\.([0-9]+)/.exec(text);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) < (b[i] || 0) ? -1 : 1;
  }
  return 0;
}

function nodeDecoderStatus(versionText) {
  const version = parseVersion(versionText);
  if (!version) return "unknown";
  const line = NODE_FIXED.find((fixed) => fixed[0] === version[0]);
  if (!line) return "unknown";
  return compare(version, line) >= 0 ? "fixed" : "vulnerable";
}

function chromiumDecoderStatus(versionText) {
  const version = parseVersion(versionText);
  if (!version) return "unknown";
  return version[0] >= CHROMIUM_FIXED_MAJOR ? "fixed" : "vulnerable";
}

/**
 * Which Brotli copy would be reached, and is it a copy the advisory covers.
 *
 * The identity keys on the runtime that OWNS the linked decoder:
 *   - Electron/Chromium (process.versions.chrome present): the one decoder in
 *     the binary is //third_party/brotli, and the fix boundary is the Chromium
 *     major version (>= 148 => fixed). The Node version is NOT the test here -
 *     Node's own deps/brotli is not compiled into Electron at all.
 *   - Plain Node: the decoder is Node's vendored deps/brotli, and the fix
 *     boundary is the Node line (>= 22.23.4 / 24.22.1 / 26.12.1).
 * "stack" only records HOW the body reached the decoder; in Electron both
 * stacks land in the same library.
 */
function decoderFingerprint(versions, stack) {
  const source = versions || {};
  const fingerprint = {
    decode_path: stack,
    node: source.node || null,
    electron: source.electron || null,
    chrome: source.chrome || null
  };
  if (source.chrome) {
    fingerprint.decoder = "chromium //third_party/brotli (single decoder: net.fetch, renderer, fetch(), node:zlib)";
    fingerprint.decoder_status = chromiumDecoderStatus(source.chrome);
    fingerprint.fix_boundary = "Chromium >= " + CHROMIUM_FIXED_MAJOR + " (Electron >= 42)";
    fingerprint.linkage = "electron";
  } else {
    fingerprint.decoder = stack === "node:zlib"
      ? "node:zlib (streaming createBrotliDecompress)"
      : "node fetch/undici (Content-Encoding: br)";
    fingerprint.decoder_status = nodeDecoderStatus(source.node);
    fingerprint.fix_boundary = "Node >= 22.23.4 / 24.22.1 / 26.12.1";
    fingerprint.linkage = "plain-node";
  }
  return fingerprint;
}

function sha256Hex(bytes, crypto) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * ECDSA P-256 / SHA-256, DER signature - the scheme demo/fake-pkg/server/
 * mock_registry.py signs with OpenSSL. The public key must be pinned by the
 * client; a key served by the same party as the payload proves nothing.
 */
function verifyArtifactSignature(deps) {
  const crypto = deps.crypto;
  try {
    const verifier = crypto.createVerify("sha256");
    verifier.update(deps.bytes);
    verifier.end();
    const ok = verifier.verify(deps.publicKeyPem, deps.signatureBase64, "base64");
    return { ok, detail: ok ? "signature valid under pinned key" : "signature invalid under pinned key" };
  } catch (error) {
    return { ok: false, detail: "signature check failed: " + String(error && error.message ? error.message : error) };
  }
}

/**
 * Streaming decode, fed in small chunks so the decoder's "need more input"
 * retry loop is entered repeatedly - the code path the advisory describes -
 * with a VALID stream. No malformed bytes are produced anywhere in this repo.
 */
function decodeBrotliStreaming(deps) {
  return new Promise((resolve, reject) => {
    const zlib = deps.zlib;
    const bytes = deps.bytes;
    const chunkSize = deps.chunkSize || 64;
    const decoder = zlib.createBrotliDecompress({
      flush: zlib.constants.BROTLI_OPERATION_FLUSH,
      finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH
    });
    const chunks = [];
    decoder.on("data", (chunk) => chunks.push(chunk));
    decoder.on("error", reject);
    decoder.on("end", () => {
      const parts = chunks.map((chunk) => Uint8Array.from(chunk));
      let total = 0;
      for (const part of parts) total += part.length;
      const out = new Uint8Array(total);
      let offset = 0;
      for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
      }
      resolve(out);
    });
    for (let i = 0; i < bytes.length; i += chunkSize) {
      decoder.write(bytes.subarray(i, i + chunkSize));
    }
    decoder.end();
  });
}

function normalizeEncoding(value) {
  const text = (value || "").split(",")[0].trim().toLowerCase();
  return (!text || text === "identity") ? "identity" : text;
}

function isAllowedEncoding(value, allowlist) {
  const list = (allowlist && allowlist.length ? allowlist : ["identity"]).map(normalizeEncoding);
  return list.indexOf(normalizeEncoding(value)) !== -1;
}

function classifyTransportError(error) {
  const message = String(error && error.message ? error.message : error);
  if (/ERR_CERT|CERT_|certificate/i.test(message)) return DECISION.TLS_REJECTED;
  return DECISION.INCONCLUSIVE;
}

function parseMarkerDoc(text) {
  try {
    const doc = JSON.parse(text);
    return (doc && typeof doc === "object") ? doc : null;
  } catch (_) {
    return null;
  }
}

/**
 * The whole update check. Returns the per-request evidence record.
 *
 * deps:
 *   flavor        "legacy" | "hardened"
 *   stack         "node:zlib" | "chromium"
 *   artifactName  "br" | "plain" (feed.artifacts key)
 *   pinnedKeyPem  pinned publisher key (hardened only; missing = fail closed)
 *   allowEncodings content-encoding allow-list for the hardened policy
 *   transport     { getFeed(), getArtifact(url) -> {status, contentEncoding, read()} }
 *   crypto, zlib, versions  injected so tests can observe the decoder
 */
async function runUpdateCheck(deps) {
  const flavor = deps.flavor === "hardened" ? "hardened" : "legacy";
  const stack = deps.stack === "chromium" ? "chromium" : "node:zlib";
  const artifactName = deps.artifactName === "plain" ? "plain" : "br";
  const evidence = {
    marker: null,
    decision: DECISION.INCONCLUSIVE,
    flavor,
    stack,
    artifact: artifactName,
    decode_calls: 0,
    decoder_reached: false,
    body_consumed: false,
    decoder: decoderFingerprint(deps.versions, stack),
    checks: [],
    nonce: null,
    variant: null,
    reason: null
  };
  const record = (name, ok, detail) => evidence.checks.push({ name, ok, detail });

  let feed;
  try {
    const response = await deps.transport.getFeed();
    if (response.status !== 200) {
      evidence.reason = "update feed returned HTTP " + response.status;
      return evidence;
    }
    feed = typeof response.json === "object" && response.json !== null ? response.json : parseMarkerDoc(response.text);
    if (!feed) {
      evidence.reason = "update feed is not a JSON object";
      return evidence;
    }
  } catch (error) {
    evidence.decision = classifyTransportError(error);
    evidence.reason = String(error && error.message ? error.message : error);
    return evidence;
  }

  const entry = feed.artifacts && feed.artifacts[artifactName];
  evidence.marker = feed.marker || null;
  if (!entry) {
    evidence.reason = "update feed has no artifact named " + artifactName;
    return evidence;
  }

  let response;
  try {
    response = await deps.transport.getArtifact(entry.url);
  } catch (error) {
    evidence.decision = classifyTransportError(error);
    evidence.reason = String(error && error.message ? error.message : error);
    return evidence;
  }
  if (response.status !== 200) {
    evidence.reason = "update body returned HTTP " + response.status;
    return evidence;
  }
  evidence.artifact_url = entry.url;
  evidence.content_encoding = normalizeEncoding(response.contentEncoding);

  // Hardened pre-decode control 1 (Pair C): content-encoding policy. On the
  // chromium stack this is the only pre-decode control available - the
  // compressed bytes are gone before the app can hash them.
  if (flavor === "hardened" && !isAllowedEncoding(response.contentEncoding, deps.allowEncodings)) {
    record("content-encoding policy", false, "Content-Encoding " +
      (response.contentEncoding || "identity") + " not in allow-list");
    evidence.decision = DECISION.ENCODING_REJECTED;
    evidence.reason = "content-encoding policy rejected the response before any decode";
    return evidence;
  }
  record("content-encoding policy", true, "Content-Encoding " + evidence.content_encoding + " accepted");

  let bytes;
  try {
    bytes = await response.read();
  } catch (error) {
    evidence.reason = "update body could not be read: " + String(error && error.message ? error.message : error);
    return evidence;
  }
  evidence.body_consumed = true;

  // Hardened pre-decode control 2 (Pair B): digest + signature over the
  // compressed bytes, verified against a PINNED publisher key before any
  // decoder sees them. Only possible where the app sees the compressed bytes.
  if (flavor === "hardened") {
    if (!deps.pinnedKeyPem) {
      record("pinned publisher key", false, "no pinned key configured; refusing to proceed");
      evidence.decision = DECISION.SIG_REJECTED;
      evidence.reason = "hardened policy requires a pinned publisher key (fail closed)";
      return evidence;
    }
    record("pinned publisher key", true, "pinned key configured");
    const digest = sha256Hex(bytes, deps.crypto);
    const digestOk = digest === entry.sha256;
    record("artifact digest", digestOk, "sha256 " + digest + " vs feed " + entry.sha256);
    const signature = verifyArtifactSignature({
      crypto: deps.crypto, bytes, signatureBase64: entry.signature, publicKeyPem: deps.pinnedKeyPem
    });
    record("artifact signature", signature.ok, signature.detail);
    if (!digestOk || !signature.ok) {
      evidence.decision = DECISION.SIG_REJECTED;
      evidence.reason = "artifact failed the pre-decode integrity check; no decoder was invoked";
      return evidence;
    }
  }

  const wantsDecode = artifactName === "br" || evidence.content_encoding === "br";
  if (!wantsDecode) {
    evidence.decision = DECISION.ACCEPTED;
    evidence.reason = "plain artifact accepted without a decode step";
    return evidence;
  }

  // The decode step itself.
  if (stack === "chromium") {
    // response.read() above consumed the body: the HTTP stack decoded
    // Content-Encoding: br on the way in. The app cannot count those decoder
    // invocations; it records that the decoder was reached and which build.
    evidence.decoder_reached = true;
    evidence.decode_calls = 0;
    const doc = parseMarkerDoc(new TextDecoder().decode(bytes));
    if (doc) {
      evidence.nonce = doc.nonce || null;
      evidence.variant = doc.variant || null;
      if (doc.marker) evidence.marker = doc.marker;
    }
  } else {
    try {
      const decoded = await decodeBrotliStreaming({ zlib: deps.zlib, bytes });
      evidence.decode_calls = 1;
      evidence.decoder_reached = true;
      const doc = parseMarkerDoc(new TextDecoder().decode(decoded));
      if (doc) {
        evidence.nonce = doc.nonce || null;
        evidence.variant = doc.variant || null;
        if (doc.marker) evidence.marker = doc.marker;
      }
    } catch (error) {
      evidence.reason = "Brotli decode failed: " + String(error && error.message ? error.message : error);
      return evidence;
    }
  }
  evidence.decision = DECISION.DECODED;
  evidence.reason = "attacker-supplied body reached the " + evidence.decoder.decoder + " decoder";
  return evidence;
}

module.exports = {
  DECISION,
  NODE_FIXED,
  CHROMIUM_FIXED_MAJOR,
  DEMO_ELECTRON,
  parseVersion,
  nodeDecoderStatus,
  chromiumDecoderStatus,
  decoderFingerprint,
  sha256Hex,
  verifyArtifactSignature,
  decodeBrotliStreaming,
  isAllowedEncoding,
  normalizeEncoding,
  runUpdateCheck
};
