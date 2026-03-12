const RSA = (() => {
  function b64urlToBytes(s) {
    const r = s.replace(/-/g, "+").replace(/_/g, "/");
    const p = r + "===".slice((r.length + 3) % 4);
    const b = atob(p);
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }

  function bytesToBigInt(bytes) {
    let hex = "0x";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return BigInt(hex);
  }

  function bigIntToBytes(n, len) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (len === undefined) return bytes;
    const out = new Uint8Array(len);
    out.set(bytes, len - bytes.length);
    return out;
  }

  function modpow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = result * base % mod;
      exp = exp / 2n;
      base = base * base % mod;
    }
    return result;
  }

  function mgf1(seed, len) {
    const SHA256_LEN = 32;
    const out = new Uint8Array(len);
    let pos = 0;
    let counter = 0;
    while (pos < len) {
      const C = new Uint8Array(4);
      new DataView(C.buffer).setUint32(0, counter++);
      const concat = new Uint8Array(seed.length + 4);
      concat.set(seed); concat.set(C, seed.length);
      const h = sha256Sync(concat);
      const chunk = Math.min(SHA256_LEN, len - pos);
      out.set(h.slice(0, chunk), pos);
      pos += chunk;
    }
    return out;
  }

  const SHA256_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ];

  function sha256Sync(data) {
    const msg = new Uint8Array(data);
    const bitLen = msg.length * 8;
    const padded = new Uint8Array(Math.ceil((msg.length + 9) / 64) * 64);
    padded.set(msg);
    padded[msg.length] = 0x80;
    new DataView(padded.buffer).setUint32(padded.length - 4, bitLen, false);
    new DataView(padded.buffer).setUint32(padded.length - 8, Math.floor(bitLen / 2**32), false);

    let [h0,h1,h2,h3,h4,h5,h6,h7] = SHA256_IV;
    const r = (x, n) => (x >>> n) | (x << (32 - n));

    for (let i = 0; i < padded.length; i += 64) {
      const w = new Uint32Array(64);
      for (let j = 0; j < 16; j++) w[j] = new DataView(padded.buffer).getUint32(i + j * 4);
      for (let j = 16; j < 64; j++) {
        const s0 = r(w[j-15],7) ^ r(w[j-15],18) ^ (w[j-15] >>> 3);
        const s1 = r(w[j-2],17) ^ r(w[j-2],19)  ^ (w[j-2] >>> 10);
        w[j] = (w[j-16] + s0 + w[j-7] + s1) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
      for (let j = 0; j < 64; j++) {
        const S1 = r(e,6) ^ r(e,11) ^ r(e,25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[j] + w[j]) >>> 0;
        const S0 = r(a,2) ^ r(a,13) ^ r(a,22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        [h,g,f,e,d,c,b,a] = [g,f,e,(d+t1)>>>0,c,b,a,(t1+t2)>>>0];
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }
    const out = new Uint8Array(32);
    [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i) => new DataView(out.buffer).setUint32(i*4, v));
    return out;
  }

  async function oaepDecrypt(privKey, cipherBytes) {
    const { n, d } = privKey;
    const k = bigIntToBytes(n).length;
    if (cipherBytes.length !== k) throw new Error("Длина шифртекста неверна");

    const m = modpow(bytesToBigInt(cipherBytes), d, n);
    const em = bigIntToBytes(m, k);

    const hLen = 32;
    if (em[0] !== 0) throw new Error("Расшифровка: неверный формат (Y != 0)");

    const maskedSeed = em.slice(1, 1 + hLen);
    const maskedDB   = em.slice(1 + hLen);

    const seedMask = mgf1(maskedDB, hLen);
    const seed     = maskedSeed.map((b, i) => b ^ seedMask[i]);
    const dbMask   = mgf1(seed, maskedDB.length);
    const db       = maskedDB.map((b, i) => b ^ dbMask[i]);

    const lHash = sha256Sync(new Uint8Array(0));
    for (let i = 0; i < hLen; i++) {
      if (db[i] !== lHash[i]) throw new Error("Расшифровка: хэш метки не совпадает");
    }

    let mStart = hLen;
    while (mStart < db.length && db[mStart] === 0) mStart++;
    if (mStart >= db.length || db[mStart] !== 1) throw new Error("Расшифровка: неверный разделитель");
    return db.slice(mStart + 1);
  }

  const SHA256_PKCS1_PREFIX = new Uint8Array([
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20,
  ]);

  async function pkcs1Sign(privKey, message) {
    const { n, d } = privKey;
    const k = bigIntToBytes(n).length;
    const hash = sha256Sync(message);
    const T = new Uint8Array(SHA256_PKCS1_PREFIX.length + hash.length);
    T.set(SHA256_PKCS1_PREFIX); T.set(hash, SHA256_PKCS1_PREFIX.length);
    const tLen = T.length;
    if (k < tLen + 11) throw new Error("Ключ слишком короткий");
    const em = new Uint8Array(k);
    em[0] = 0x00; em[1] = 0x01;
    for (let i = 2; i < k - tLen - 1; i++) em[i] = 0xff;
    em[k - tLen - 1] = 0x00;
    em.set(T, k - tLen);
    const sig = modpow(bytesToBigInt(em), d, n);
    return bigIntToBytes(sig, k);
  }

  function parsePrivateJwk(jwk) {
    return {
      n: bytesToBigInt(b64urlToBytes(jwk.n)),
      d: bytesToBigInt(b64urlToBytes(jwk.d)),
      e: bytesToBigInt(b64urlToBytes(jwk.e)),
    };
  }

  function parsePublicJwk(jwk) {
    return {
      n: bytesToBigInt(b64urlToBytes(jwk.n)),
      e: bytesToBigInt(b64urlToBytes(jwk.e)),
    };
  }

  function pkcs1Verify(pubKey, message, sigBytes) {
    const { n, e } = pubKey;
    const k = bigIntToBytes(n).length;
    if (sigBytes.length !== k) return false;
    const m = modpow(bytesToBigInt(sigBytes), e, n);
    const em = bigIntToBytes(m, k);
    if (em[0] !== 0x00 || em[1] !== 0x01) return false;
    let i = 2;
    while (i < em.length && em[i] === 0xff) i++;
    if (em[i] !== 0x00) return false;
    i++;
    const hashBytes = em.slice(i + SHA256_PKCS1_PREFIX.length);
    const hash = sha256Sync(message);
    if (hashBytes.length !== hash.length) return false;
    for (let j = 0; j < hash.length; j++) if (hashBytes[j] !== hash[j]) return false;
    return true;
  }

  let _keygenCache = null;

  async function fetchKeygen() {
    if (_keygenCache) return _keygenCache;
    const res = await fetch(`${window.location.origin}/auth/keygen`, { method: "POST" });
    if (!res.ok) throw new Error("keygen failed: " + res.status);
    _keygenCache = await res.json();
    return _keygenCache;
  }

  async function generateKeyPair() {
    const kg = await fetchKeygen();
    return {
      privateJwk: kg.sign_private_jwk,
      publicJwk:  kg.sign_public_jwk,
      _webcrypto: null,
    };
  }

  async function generateEncryptKeyPair() {
    const kg = await fetchKeygen();
    return {
      privateJwk: kg.enc_private_jwk,
      publicJwk:  kg.enc_public_jwk,
      _webcrypto: null,
    };
  }

  async function sign(privJwk, _unused, message) {
    return pkcs1Sign(parsePrivateJwk(privJwk), message);
  }

  async function decrypt(privJwk, _unused, cipherBytes) {
    return oaepDecrypt(parsePrivateJwk(privJwk), cipherBytes);
  }

  function verify(pubJwk, message, sigBytes) {
    return pkcs1Verify(parsePublicJwk(pubJwk), message, sigBytes);
  }

  return { generateKeyPair, generateEncryptKeyPair, sign, decrypt, verify, sha256Sync };
})();






