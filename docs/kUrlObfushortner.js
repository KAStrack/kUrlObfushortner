/**
 * kUrlObfushortner.js
 * Clientside URL compression using DEFLATE (via pako) + URL-safe Base64.
 *
 * Dependencies: pako (https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js)
 *
 * Usage:
 *   const short = kUrlObfushortner.encode("https://example.com/?foo=bar&baz=qux...");
 *   const long  = kUrlObfushortner.decode("https://example.com/?_k=<token>");
 *   kUrlObfushortner.applyDecodedUrl({ replaceAddressBar: true });
 */

(function (global) {
  "use strict";

  // ── Constants ────────────────────────────────────────────────────────────────
  const PARAM_KEY = "_k"; // query-string key that carries the compressed payload
  const VERSION   = "1";  // single-char version prefix for future format changes

  // ── Internal helpers ─────────────────────────────────────────────────────────

  /**
   * Ensure pako is available (loaded globally or via module).
   */
  function requirePako() {
    if (typeof pako === "undefined") {
      throw new Error(
        "kUrlObfushortner requires pako. " +
        "Add <script src=\"https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js\"></script> " +
        "before kUrlObfushortner.js."
      );
    }
    return pako;
  }

  /**
   * Convert a Uint8Array to a URL-safe Base64 string.
   * Standard Base64 uses +, /, = which need percent-encoding in URLs.
   * URL-safe variant uses -, _, and omits padding.
   */
  function uint8ToUrlBase64(bytes) {
    // btoa works on binary strings
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  /**
   * Convert a URL-safe Base64 string back to a Uint8Array.
   */
  function urlBase64ToUint8(str) {
    // Restore standard Base64 characters and re-add padding
    const base64 = str
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Split a URL string into { base, search, hash }:
   *   base   — everything before the "?" (origin + path, or a relative path)
   *   search — the query string including the leading "?" (or "")
   *   hash   — the fragment including the leading "#" (or "")
   *
   * Pure string manipulation, so it works identically for absolute and
   * relative URLs and preserves the path byte-for-byte (no normalisation),
   * which is essential for lossless round-tripping. The fragment is split off
   * first so a "?" inside a fragment is never mistaken for the query delimiter.
   */
  function splitUrl(urlString) {
    let rest = urlString;
    let hash = "";
    const hashIdx = rest.indexOf("#");
    if (hashIdx >= 0) {
      hash = rest.slice(hashIdx);
      rest = rest.slice(0, hashIdx);
    }
    let search = "";
    const qIdx = rest.indexOf("?");
    if (qIdx >= 0) {
      search = rest.slice(qIdx); // includes leading "?"
      rest   = rest.slice(0, qIdx);
    }
    return { base: rest, search, hash };
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  const kUrlObfushortner = {

    /**
     * Encode a URL, compressing its query string into a single `_k` parameter.
     *
     * @param {string} longUrl  - The full URL to compress.
     * @returns {string}          The shortened URL with a single `_k=<token>` query param.
     */
    encode(longUrl) {
      const p = requirePako();

      const { base, search, hash } = splitUrl(longUrl);

      if (!search || search === "?") {
        // Nothing to compress — return as-is
        return longUrl;
      }

      // Compress the raw query string (including the leading "?")
      const compressed = p.deflateRaw(search, { level: 9 });
      // VERSION + URL-safe Base64 is already query-string safe, so no
      // percent-encoding is needed (it would only add bytes).
      const token = VERSION + uint8ToUrlBase64(compressed);

      // Rebuild URL: keep base + fragment, swap the query string for the token
      return base + "?" + PARAM_KEY + "=" + token + hash;
    },

    /**
     * Decode a shortened URL produced by `encode()`.
     *
     * @param {string} shortUrl  - The URL containing a `_k=<token>` query param.
     * @returns {string}           The reconstructed original URL.
     */
    decode(shortUrl) {
      const p = requirePako();

      const { base, search, hash } = splitUrl(shortUrl);
      const token = new URLSearchParams(search).get(PARAM_KEY);

      if (!token) {
        // No compressed payload found — return as-is
        return shortUrl;
      }

      // Strip version prefix (token.charAt(0) is reserved for future use)
      const payload = token.slice(1);

      const compressed   = urlBase64ToUint8(payload);
      const decompressed = p.inflateRaw(compressed, { to: "string" });

      // decompressed is the original query string (includes its leading "?")
      return base + decompressed + hash;
    },

    /**
     * If the current page was loaded with a compressed `_k` query param,
     * decode it and optionally rewrite the browser address bar.
     *
     * Dispatches a CustomEvent "kurlobfushortner:decoded" on window with
     * { detail: { original: <shortUrl>, decoded: <longUrl> } } so the page
     * can react (e.g. re-render, update state, etc.).
     *
     * @param {object}  [options]
     * @param {boolean} [options.replaceAddressBar=false]
     *   When true, replaces the current history entry with the decoded URL.
     *   The user sees the long URL in the address bar.
     * @returns {{ original: string, decoded: string } | null}
     *   Returns the before/after URLs if a compressed param was found, else null.
     */
    applyDecodedUrl(options) {
      const opts = Object.assign({ replaceAddressBar: false }, options);
      const currentUrl = window.location.href;
      const params = new URLSearchParams(window.location.search);

      if (!params.has(PARAM_KEY)) {
        return null; // Nothing to do
      }

      let decoded;
      try {
        decoded = kUrlObfushortner.decode(currentUrl);
      } catch (err) {
        console.error("kUrlObfushortner: failed to decode URL", err);
        return null;
      }

      if (opts.replaceAddressBar && window.history && window.history.replaceState) {
        window.history.replaceState(null, "", decoded);
      }

      // Fire a DOM event so the host page can react
      const event = new CustomEvent("kurlobfushortner:decoded", {
        detail: { original: currentUrl, decoded }
      });
      window.dispatchEvent(event);

      return { original: currentUrl, decoded };
    },

    // ── Utility / introspection ───────────────────────────────────────────────

    /**
     * Returns some stats about a URL pair for debugging/display.
     *
     * @param {string} longUrl
     * @returns {{ longUrl, shortUrl, longLen, shortLen, saving, savingPct }}
     */
    stats(longUrl) {
      const shortUrl  = kUrlObfushortner.encode(longUrl);
      const longLen   = longUrl.length;
      const shortLen  = shortUrl.length;
      const saving    = longLen - shortLen;
      const savingPct = longLen > 0
        ? ((saving / longLen) * 100).toFixed(1)
        : "0.0";
      return { longUrl, shortUrl, longLen, shortLen, saving, savingPct };
    },

    PARAM_KEY,
    VERSION,
  };

  // ── Export ───────────────────────────────────────────────────────────────────

  // CommonJS (Node / bundlers)
  if (typeof module !== "undefined" && module.exports) {
    module.exports = kUrlObfushortner;
  }

  // ESM (tree-shaking friendly — also set global for browser <script> usage)
  if (typeof exports !== "undefined") {
    exports.kUrlObfushortner = kUrlObfushortner;
  }

  // Browser global
  global.kUrlObfushortner = kUrlObfushortner;

})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this);
