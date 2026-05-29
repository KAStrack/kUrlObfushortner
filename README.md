# kUrlObfushortner

> Serverless URL compression — and optional RSA-OAEP encryption — entirely in the browser.

Compress long query strings using DEFLATE + URL-safe Base64 into a single `?_k=` parameter that decodes client-side with no server, no database, and no round-trip. Pair with the `-secure` plugin to encrypt tokens so only your server can read them.

**Current version:** 0.1

**[View the Demo →](https://kastrack.github.io/kUrlObfushortner/)**

---

## Contents

- [How it works](#how-it-works)
- [Files](#files)
- [Quick start](#quick-start)
- [Base plugin — kUrlObfushortner.js](#base-plugin--kurlobfushortnerjs)
- [Secure plugin — kUrlObfushortner-secure.js](#secure-plugin--kurlobfushortner-securejs)
- [Server-side decryption](#server-side-decryption)
- [Choosing a key size](#choosing-a-key-size)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

---

## How it works

### Base plugin

```
Long URL  →  DEFLATE compress query string  →  URL-safe Base64  →  ?_k=<token>
```

The entire compressed query string is embedded in the token — no server lookup needed. Anyone who knows the scheme can decode it.

### Secure plugin

```
Long URL  →  DEFLATE compress  →  RSA-OAEP encrypt (public key)  →  Base64url  →  ?_ks=<token>
```

The public key lives in your front-end JavaScript. The private key lives on your server. Without the private key, the original URL is unrecoverable.

---

## Files

| File | Purpose |
|------|---------|
| `kUrlObfushortner.js` | Base compression library |
| `kUrlObfushortner-secure.js` | RSA-OAEP encryption plugin (requires base) |
| `index.html` | Full demo page with live encode/decode, key generation, and server-side code snippets |
| `index.css` | Stylesheet for the demo page |

---

## Quick start

### Browser

```html
<!-- 1. Load pako (DEFLATE library) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js"></script>

<!-- 2. Load the base plugin -->
<script src="kUrlObfushortner.js"></script>

<!-- 3. Optionally load the secure plugin -->
<script src="kUrlObfushortner-secure.js"></script>
```

### Node.js

```js
const pako = require('pako');       // npm install pako
global.pako = pako;                 // make it available as a global
global.btoa = (b) => Buffer.from(b, 'binary').toString('base64');
global.atob = (b) => Buffer.from(b, 'base64').toString('binary');

const { kUrlObfushortner }       = require('./kUrlObfushortner');
const { kUrlObfushortnerSecure } = require('./kUrlObfushortner-secure');
```

---

## Base plugin — kUrlObfushortner.js

### API

#### `kUrlObfushortner.encode(longUrl)`

Compress the query string of a URL. Returns the same URL with a single `?_k=<token>` query parameter.

```js
const short = kUrlObfushortner.encode(
  'https://example.com/?region=us&city=London&filters=a,b,c&page=2'
);
// → 'https://example.com/?_k=1BYBw...'
```

#### `kUrlObfushortner.decode(shortUrl)`

Decompress a `?_k=` URL and return the original.

```js
const long = kUrlObfushortner.decode('https://example.com/?_k=1BYBw...');
// → 'https://example.com/?region=us&city=London&filters=a,b,c&page=2'
```

#### `kUrlObfushortner.applyDecodedUrl(options?)`

Call on page load. Checks whether the current URL contains `?_k=`, decodes it, optionally rewrites the address bar, and fires a `kurlobfushortner:decoded` CustomEvent. Returns `{ original, decoded }` or `null`.

```js
// In a DOMContentLoaded handler:
const result = kUrlObfushortner.applyDecodedUrl({ replaceAddressBar: true });
if (result) {
  console.log('Decoded:', result.decoded);
}

// Or use the event:
window.addEventListener('kurlobfushortner:decoded', (e) => {
  console.log(e.detail.decoded);
});
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `replaceAddressBar` | `boolean` | `false` | Replace the browser history entry with the decoded URL |

#### `kUrlObfushortner.stats(longUrl)`

Returns compression statistics for display or debugging.

```js
const s = kUrlObfushortner.stats(longUrl);
// {
//   longUrl, shortUrl,
//   longLen: 284, shortLen: 220,
//   saving: 64, savingPct: '22.5'
// }
```

### Token format

```
?_k=<version><base64url(deflateRaw(queryString))>
```

- **`?_k=`** — fixed parameter name
- **version** — single ASCII character, currently `"1"`, reserved for format changes
- **base64url** — standard Base64 with `+→-`, `/→_`, padding stripped
- **deflateRaw** — raw DEFLATE (no zlib header/trailer), level 9

---

## Secure plugin — kUrlObfushortner-secure.js

Requires `kUrlObfushortner.js` to be loaded first.

### API

#### `kUrlObfushortnerSecure.encodeSecure(longUrl, publicKeyPem, options?)`

Compress and encrypt a URL's query string. Returns the URL with a `?_ks=<ciphertext>` parameter.

```js
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

const secureUrl = await kUrlObfushortnerSecure.encodeSecure(longUrl, publicKeyPem);
// → 'https://example.com/?_ks=Ab3Fg...'

// With optional HMAC integrity signature:
const signed = await kUrlObfushortnerSecure.encodeSecure(longUrl, publicKeyPem, {
  hmacSecret: 'your-shared-server-secret'
});
// → 'https://example.com/?_ks=Ab3Fg...&_kh=XyZ...'
```

#### `kUrlObfushortnerSecure.generateKeyPair(modulusLength?)`

Generate an RSA-OAEP key pair in the browser. Returns PEM strings. The private key should be moved to your server immediately.

```js
const { publicKeyPem, privateKeyPem } = await kUrlObfushortnerSecure.generateKeyPair(2048);
```

| Parameter | Default | Options |
|-----------|---------|---------|
| `modulusLength` | `2048` | `2048`, `4096` |

#### `kUrlObfushortnerSecure.measureCompressed(url)`

Check the compressed byte size of a URL's query string before choosing a key size.

```js
const m = kUrlObfushortnerSecure.measureCompressed(longUrl);
// {
//   queryLen: 239,       ← raw query string characters
//   compressedLen: 156,  ← DEFLATE output bytes
//   plaintextLen: 157,   ← bytes that will be encrypted (includes version byte)
//   fitsIn2048: true,    ← plaintextLen <= 190
//   fitsIn4096: true     ← plaintextLen <= 446
// }
```

#### `kUrlObfushortnerSecure.verifyHmac(secureUrl, hmacSecret)`

Verify a `?_kh=` HMAC-SHA256 integrity signature.

```js
const valid = await kUrlObfushortnerSecure.verifyHmac(secureUrl, 'your-shared-secret');
```

#### `kUrlObfushortnerSecure.decodeSecure_TEST_ONLY(secureUrl, privateKeyPem)`

⚠ **Testing only.** Decrypt a `?_ks=` URL client-side. Never use this in production — exposing a private key in browser JavaScript defeats the entire security model.

```js
const original = await kUrlObfushortnerSecure.decodeSecure_TEST_ONLY(secureUrl, privateKeyPem);
```

### Token format

```
?_ks=<base64url(RSA-OAEP-encrypt([0x02, ...deflateRaw(queryString)]))>
&_kh=<base64url(HMAC-SHA256(ciphertext))>   ← optional
```

- **`?_ks=`** — encrypted token parameter
- **`?_kh=`** — optional HMAC-SHA256 integrity signature over the ciphertext value
- **`0x02`** — version byte prepended to raw DEFLATE bytes before encryption
- The DEFLATE bytes are encrypted **directly** (not Base64-encoded first) to stay within RSA-OAEP size limits

---

## Server-side decryption

The decrypt steps in all languages are the same:

1. URL-safe Base64 decode `?_ks=` → ciphertext bytes
2. RSA-OAEP decrypt (SHA-256) with the private key → `[0x02, ...deflateBytes]`
3. Skip the first byte (version), DEFLATE-inflate the rest → original query string

### Node.js

```js
const crypto = require('crypto');
const pako   = require('pako');
const fs     = require('fs');

const privateKeyPem = fs.readFileSync('/etc/secrets/private.pem', 'utf8');

function kurlSecureDecode(encryptedToken) {
  const b64      = encryptedToken.replace(/-/g, '+').replace(/_/g, '/');
  const pad      = '='.repeat((4 - b64.length % 4) % 4);
  const cipher   = Buffer.from(b64 + pad, 'base64');

  const plain    = crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    cipher
  );

  // Skip version byte, inflate DEFLATE bytes
  const qs = pako.inflateRaw(plain.slice(1), { to: 'string' });
  return qs; // e.g. "?foo=bar&baz=qux"
}
```

### PHP

```php
function kurlSecureDecode(string $token): string {
  $pad     = str_repeat('=', (4 - strlen($token) % 4) % 4);
  $cipher  = base64_decode(strtr($token . $pad, '-_', '+/'));

  $privKey = openssl_pkey_get_private(file_get_contents('/etc/secrets/private.pem'));
  if (!openssl_private_decrypt($cipher, $plain, $privKey, OPENSSL_PKCS1_OAEP_PADDING)) {
    throw new RuntimeException('RSA decrypt failed: ' . openssl_error_string());
  }

  // Skip version byte, inflate
  return gzinflate(substr($plain, 1)); // returns "?foo=bar&baz=qux"
}
```

### Python

```python
import zlib, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

with open('/etc/secrets/private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

def kurl_secure_decode(token: str) -> str:
    pad    = '=' * ((4 - len(token) % 4) % 4)
    cipher = base64.urlsafe_b64decode(token + pad)

    plain  = private_key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Skip version byte, inflate
    return zlib.decompress(bytes(plain[1:]), -15).decode()
```

### C# / ASP.NET Core

```csharp
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

public static string KurlSecureDecode(string encryptedToken)
{
    var b64    = encryptedToken.Replace('-', '+').Replace('_', '/');
    var pad    = new string('=', (4 - b64.Length % 4) % 4);
    var cipher = Convert.FromBase64String(b64 + pad);

    using var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText("/etc/secrets/private.pem"));
    var plain = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    // Skip version byte, inflate
    using var ms = new MemoryStream(plain, 1, plain.Length - 1);
    using var ds = new DeflateStream(ms, CompressionMode.Decompress);
    using var sr = new StreamReader(ds, Encoding.UTF8);
    return sr.ReadToEnd(); // "?foo=bar&baz=qux"
}
```

---

## Choosing a key size

RSA-OAEP with SHA-256 has a hard plaintext size limit depending on key size. Use `measureCompressed()` to check your URL before committing to a key size.

| Key size | Max plaintext | Ciphertext (URL overhead) | Recommended for |
|----------|--------------|--------------------------|-----------------|
| 2048-bit | 190 bytes | ~344 chars in URL | Most typical URLs |
| 4096-bit | 446 bytes | ~688 chars in URL | Very long query strings |

The plaintext is `1 (version byte) + deflateRaw(queryString)`. A 239-character query string typically compresses to ~156 bytes, giving a 157-byte plaintext — comfortably within 2048-bit limits.

---

## Limitations

- **Base plugin is not encrypted.** `?_k=` tokens are compressed, not secret — anyone who knows the scheme can decode them. Use `-secure` if confidentiality matters.
- **RSA-OAEP ciphertext is always larger than the input.** The encrypted URL will be longer than the original. The tradeoff is confidentiality.
- **Server must cooperate.** The receiving server must recognise `?_k=` or `?_ks=` and either decode it server-side or serve the JavaScript that does.
- **Short query strings may grow.** Query strings under ~80 characters may expand slightly after Base64 encoding. Use `stats()` to check.
- **2048-bit keys cannot handle very long URLs.** If `measureCompressed()` shows `fitsIn2048: false`, use a 4096-bit key. If even that isn't enough, a server-side short-code fallback is the right solution.

---

## Roadmap

- Live secure decode demo (server + key configuration required)
- Server-side middleware packages (npm, Composer, PyPI)
- Configurable parameter key names
- npm package with proper ESM/CJS exports
- Optional fallback to server-stored short codes for URLs that don't compress well
- Signed (but not encrypted) tokens for tamper-evident public URLs
