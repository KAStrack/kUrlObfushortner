/**
 * kUrlObfushortner-secure.js
 * Encrypts URL query strings using RSA-OAEP via the Web Crypto API.
 * Decryption must happen server-side where the RSA private key is held.
 *
 * ── How it works ────────────────────────────────────────────────────────────
 *
 *  ENCODE (browser):
 *    1. Extract the raw query string from the URL (e.g. "?foo=bar&baz=qux")
 *    2. DEFLATE-compress it to raw bytes (same algorithm as base plugin)
 *    3. Prepend a single version byte (0x02)
 *    4. RSA-OAEP encrypt those raw bytes with the public key
 *       → ciphertext is always exactly keySize/8 bytes (256 for 2048-bit)
 *    5. Base64url-encode the ciphertext → placed in ?_ks=<token>
 *
 *  DECODE (server):
 *    1. Base64url-decode the ?_ks= value → ciphertext bytes
 *    2. RSA-OAEP decrypt with the private key → [versionByte, ...deflateBytes]
 *    3. DEFLATE-inflate the bytes (skip version byte) → original query string
 *
 * ── Why we don't reuse the base plugin's _k token ───────────────────────────
 *  The base plugin encodes raw DEFLATE bytes to Base64url first, producing
 *  a text string ~33% larger than the compressed bytes. Encrypting that string
 *  would push typical URLs over RSA-OAEP's plaintext limit for 2048-bit keys
 *  (190 bytes max). We compress and encrypt the raw bytes directly instead.
 *
 * ── RSA-OAEP plaintext size limits ──────────────────────────────────────────
 *  2048-bit key: max 190 bytes  (most typical URLs after DEFLATE fit here)
 *  4096-bit key: max 446 bytes  (for very long query strings)
 *  Use measureCompressed(url) to check before choosing a key size.
 *
 * ── Optional HMAC integrity ──────────────────────────────────────────────────
 *  Pass { hmacSecret: 'your-secret' } to encodeSecure() to append a
 *  HMAC-SHA256 signature as ?_kh=<sig>. Verify this server-side before
 *  attempting decryption to cheaply reject tampered tokens.
 *
 * ── Dependencies ─────────────────────────────────────────────────────────────
 *  - pako (loaded before this script)
 *  - kUrlObfushortner.js (loaded before this script)
 *  - Web Crypto API / SubtleCrypto (all modern browsers, Node.js 18+)
 *
 * ── Key formats ──────────────────────────────────────────────────────────────
 *  Public key:  PEM / SPKI  "-----BEGIN PUBLIC KEY-----"
 *  Private key: PEM / PKCS8 "-----BEGIN PRIVATE KEY-----"  ← server only
 */

(function (global) {
  "use strict";

  const SECURE_PARAM_KEY = "_ks";
  const HMAC_PARAM_KEY   = "_kh";
  const VERSION_BYTE     = 0x02; // 0x01 reserved for base _k format

  // ── Guards ────────────────────────────────────────────────────────────────

  function requirePako() {
    if (typeof pako === "undefined") {
      throw new Error("kUrlObfushortner-secure requires pako.");
    }
    return pako;
  }

  function requireCrypto() {
    const c =
      (typeof globalThis !== "undefined" && globalThis.crypto) ||
      (typeof window     !== "undefined" && window.crypto)     ||
      (typeof crypto     !== "undefined" && crypto);
    if (!c) {
      throw new Error(
        "kUrlObfushortner-secure requires the Web Crypto API. " +
        "Use a modern browser or Node.js 18+."
      );
    }
    if (!c.subtle) {
      // crypto exists but crypto.subtle is missing — this is almost always a
      // secure-context issue, not an old browser.
      throw new Error(
        "kUrlObfushortner-secure requires SubtleCrypto, which browsers only " +
        "expose in a secure context. Serve the page over HTTPS or via " +
        "http://localhost (http://127.0.0.1 also works). It will NOT work from " +
        "a file:// URL or over http:// on a LAN IP/hostname."
      );
    }
    return c;
  }

  // ── Binary / Base64 helpers ───────────────────────────────────────────────

  function uint8ToUrlBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function urlBase64ToUint8(str) {
    const b64    = str.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const bin    = atob(padded);
    const out    = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function pemToArrayBuffer(pem) {
    const b64 = pem
      .replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, "")
      .replace(/\s+/g, "");
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  // ── Key import helpers ────────────────────────────────────────────────────

  async function importPublicKey(pem) {
    return requireCrypto().subtle.importKey(
      "spki",
      pemToArrayBuffer(pem),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
  }

  async function importPrivateKey(pem) {
    return requireCrypto().subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(pem),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  }

  async function importHmacKey(secret) {
    return requireCrypto().subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }

  // ── URL parsing helpers ───────────────────────────────────────────────────

  function getBaseUrl(urlString) {
    try {
      const u = new URL(urlString);
      return u.origin + u.pathname;
    } catch (_) {
      const idx = urlString.indexOf("?");
      return idx >= 0 ? urlString.slice(0, idx) : urlString;
    }
  }

  function getQueryString(urlString) {
    try {
      return new URL(urlString).search || "";
    } catch (_) {
      const idx = urlString.indexOf("?");
      return idx >= 0 ? urlString.slice(idx) : "";
    }
  }

  // ── Public API ────────────────────────────────────────────────────────────

  const kUrlObfushortnerSecure = {

    /**
     * Compress and encrypt a URL's query string.
     *
     * The query string is DEFLATE-compressed to raw bytes, a version byte is
     * prepended, then the whole thing is RSA-OAEP encrypted with the public
     * key. The ciphertext is Base64url-encoded into a single ?_ks= parameter.
     *
     * @param {string} longUrl       Full URL whose query string should be encrypted.
     * @param {string} publicKeyPem  RSA public key in PEM / SPKI format.
     * @param {object} [options]
     * @param {string} [options.hmacSecret]  Shared secret for HMAC-SHA256 integrity tag.
     * @returns {Promise<string>}    Short URL with ?_ks=[&_kh=].
     */
    async encodeSecure(longUrl, publicKeyPem, options = {}) {
      const p      = requirePako();
      const crypto = requireCrypto();

      const qs = getQueryString(longUrl);
      if (!qs || qs === "?") return longUrl;

      // 1. DEFLATE-compress the query string to raw bytes
      const compressed = p.deflateRaw(qs, { level: 9 }); // Uint8Array

      // 2. Prefix with version byte
      const plaintext  = new Uint8Array(1 + compressed.length);
      plaintext[0]     = VERSION_BYTE;
      plaintext.set(compressed, 1);

      // 3. Validate key size vs plaintext size with a friendly error
      // (We can't know key size without importing, so we catch and re-throw below)

      // 4. RSA-OAEP encrypt
      let publicKey;
      try {
        publicKey = await importPublicKey(publicKeyPem);
      } catch (e) {
        throw new Error(
          "Failed to import public key. " +
          "Ensure it is PEM/SPKI format (-----BEGIN PUBLIC KEY-----).\n" +
          "Original error: " + e.message
        );
      }

      let cipherBuf;
      try {
        cipherBuf = await crypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          publicKey,
          plaintext
        );
      } catch (e) {
        const m = kUrlObfushortnerSecure.measureCompressed(longUrl);
        throw new Error(
          "RSA-OAEP encryption failed. " +
          "Plaintext is " + m.plaintextLen + " bytes. " +
          (m.fitsIn2048
            ? "Your key may be invalid or corrupted."
            : m.fitsIn4096
              ? "Use a 4096-bit key — this URL is too large for a 2048-bit key."
              : "This URL's query string is too large even for a 4096-bit key. Consider a server-side short code instead."
          ) +
          "\nOriginal error: " + e.message
        );
      }

      // cipherB64 (and the HMAC sig below) are URL-safe Base64, so they need
      // no percent-encoding — adding it would only inflate the token.
      const cipherB64 = uint8ToUrlBase64(new Uint8Array(cipherBuf));
      let   secureUrl = getBaseUrl(longUrl) +
                        "?" + SECURE_PARAM_KEY + "=" + cipherB64;

      // 5. Optional HMAC integrity signature
      if (options.hmacSecret) {
        const hmacKey = await importHmacKey(options.hmacSecret);
        const sig     = await crypto.subtle.sign(
          "HMAC",
          hmacKey,
          new TextEncoder().encode(cipherB64)
        );
        secureUrl += "&" + HMAC_PARAM_KEY + "=" +
                     uint8ToUrlBase64(new Uint8Array(sig));
      }

      return secureUrl;
    },

    /**
     * Decrypt a ?_ks= URL client-side.
     *
     * ⚠ FOR TESTING ONLY. Exposing a private key in browser JavaScript
     * completely undermines the security model. In production, decryption
     * must always happen server-side.
     *
     * @param {string} secureUrl     URL containing ?_ks=<ciphertext>.
     * @param {string} privateKeyPem RSA private key in PEM / PKCS8 format.
     * @returns {Promise<string>}    The original long URL.
     */
    async decodeSecure_TEST_ONLY(secureUrl, privateKeyPem) {
      const p      = requirePako();
      const crypto = requireCrypto();

      const params    = new URLSearchParams(getQueryString(secureUrl));
      const cipherB64 = params.get(SECURE_PARAM_KEY);
      if (!cipherB64) return secureUrl;

      const privateKey  = await importPrivateKey(privateKeyPem);
      const cipherBytes = urlBase64ToUint8(cipherB64);

      const plainBuf = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        cipherBytes
      );

      // Skip the version byte, then inflate
      const compressedBytes = new Uint8Array(plainBuf).slice(1);
      const qs = p.inflateRaw(compressedBytes, { to: "string" });

      return getBaseUrl(secureUrl) + qs;
    },

    /**
     * Generate an RSA-OAEP key pair via Web Crypto.
     * Returns PEM strings. Move the private key to your server immediately.
     *
     * @param {2048|4096} [modulusLength=2048]
     * @returns {Promise<{ publicKeyPem: string, privateKeyPem: string }>}
     */
    async generateKeyPair(modulusLength = 2048) {
      const crypto  = requireCrypto();
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      function toPem(buf, label) {
        const b64    = btoa(String.fromCharCode(...new Uint8Array(buf)));
        const chunks = b64.match(/.{1,64}/g).join("\n");
        return `-----BEGIN ${label}-----\n${chunks}\n-----END ${label}-----`;
      }

      const pubBuf  = await crypto.subtle.exportKey("spki",  keyPair.publicKey);
      const privBuf = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

      return {
        publicKeyPem:  toPem(pubBuf,  "PUBLIC KEY"),
        privateKeyPem: toPem(privBuf, "PRIVATE KEY"),
      };
    },

    /**
     * Verify the HMAC-SHA256 integrity signature on a secure URL.
     *
     * @param {string} secureUrl
     * @param {string} hmacSecret
     * @returns {Promise<boolean>}
     */
    async verifyHmac(secureUrl, hmacSecret) {
      const crypto    = requireCrypto();
      const params    = new URLSearchParams(getQueryString(secureUrl));
      const cipherB64 = params.get(SECURE_PARAM_KEY);
      const sigB64    = params.get(HMAC_PARAM_KEY);
      if (!cipherB64 || !sigB64) return false;

      const hmacKey  = await importHmacKey(hmacSecret);
      const sigBytes = urlBase64ToUint8(sigB64);
      return crypto.subtle.verify(
        "HMAC",
        hmacKey,
        sigBytes,
        new TextEncoder().encode(cipherB64)
      );
    },

    /**
     * Measure the compressed size of a URL's query string before encryption.
     * Use this to decide whether a 2048-bit or 4096-bit key is needed.
     *
     * @param {string} url
     * @returns {{ queryLen, compressedLen, plaintextLen, fitsIn2048, fitsIn4096 } | null}
     */
    measureCompressed(url) {
      const p  = requirePako();
      const qs = getQueryString(url);
      if (!qs) return null;
      const comp         = p.deflateRaw(qs, { level: 9 });
      const plaintextLen = 1 + comp.length; // version byte + compressed
      return {
        queryLen:      qs.length,
        compressedLen: comp.length,
        plaintextLen,
        fitsIn2048:    plaintextLen <= 190,
        fitsIn4096:    plaintextLen <= 446,
      };
    },

    /**
     * Return size stats for the original, base-compressed, and encrypted forms.
     *
     * @param {string} longUrl
     * @param {string} publicKeyPem
     * @returns {Promise<object>}
     */
    async stats(longUrl, publicKeyPem) {
      const baseCompressed =
        typeof kUrlObfushortner !== "undefined"
          ? kUrlObfushortner.encode(longUrl)
          : longUrl;
      const secureUrl   = await kUrlObfushortnerSecure.encodeSecure(longUrl, publicKeyPem);
      const measurement = kUrlObfushortnerSecure.measureCompressed(longUrl);
      return {
        longUrl,
        compressedUrl: baseCompressed,
        secureUrl,
        longLen:       longUrl.length,
        compressedLen: baseCompressed.length,
        secureLen:     secureUrl.length,
        measurement,
      };
    },

    SECURE_PARAM_KEY,
    HMAC_PARAM_KEY,
    VERSION_BYTE,
  };

  // ── Export ────────────────────────────────────────────────────────────────
  if (typeof module !== "undefined" && module.exports) {
    module.exports = kUrlObfushortnerSecure;
  }
  if (typeof exports !== "undefined") {
    exports.kUrlObfushortnerSecure = kUrlObfushortnerSecure;
  }
  global.kUrlObfushortnerSecure = kUrlObfushortnerSecure;

})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this);
