const PAGE_SIZE = 20;

const state = {
  jwks: new Map(),
  wallet: null,
  rows: [],
  page: 0,
};

const API = window.location.origin;

const el = {
  walletSelect: document.getElementById("walletSelect"),
  connectBtn:   document.getElementById("connectBtn"),
  walletStatus: document.getElementById("walletStatus"),
  txStatus:     document.getElementById("txStatus"),
  txBody:       document.getElementById("txBody"),
  loadBtn:      document.getElementById("loadBtn"),
  pagination:   document.getElementById("pagination"),
};

el.connectBtn.addEventListener("click", connectWallet);
el.loadBtn.addEventListener("click", loadTransactions);

async function connectWallet() {
  const walletID = el.walletSelect.value;
  setWalletStatus("⏳ Генерация ключевой пары…", "loading");
  el.connectBtn.disabled = true;

  try {
    const signKP = await RSA.generateKeyPair(2048);
    const encKP  = await RSA.generateEncryptKeyPair(2048);

    const kid    = deriveKidSync(signKP.publicJwk);
    const encKid = deriveKidSync(encKP.publicJwk);

    setWalletStatus("⏳ Получение challenge…", "loading");
    const challengeRes = await fetchJSON(`${API}/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet_id:      walletID,
        public_jwk:     { kty: signKP.publicJwk.kty, n: signKP.publicJwk.n, e: signKP.publicJwk.e, kid },
        encryption_jwk: { kty: encKP.publicJwk.kty,  n: encKP.publicJwk.n,  e: encKP.publicJwk.e,  kid: encKid },
      }),
    });

    setWalletStatus("⏳ Подпись challenge…", "loading");
    const challengeBytes = new TextEncoder().encode(challengeRes.challenge);
    const sigBytes = await RSA.sign(signKP.privateJwk, signKP._webcrypto?.signKey, challengeBytes);
    const sigB64   = toBase64Url(sigBytes);

    await fetchJSON(`${API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet_id:    walletID,
        challenge_id: challengeRes.challenge_id,
        signature:    sigB64,
      }),
    });

    state.wallet = {
      id:          walletID,
      decryptJwk:  encKP.privateJwk,
      decryptKey:  encKP._webcrypto?.decryptKey,
      kid,
    };
    setWalletStatus(`✅ Подключён как <strong>${walletID}</strong> · kid: <code>${kid.slice(0, 10)}…</code>`, "success");
  } catch (err) {
    setWalletStatus(`⚠ Ошибка: ${err.message}`, "error");
  } finally {
    el.connectBtn.disabled = false;
  }
}

async function loadJWKS() {
  const jwks = await fetchJSON(`${API}/getJWKS`);
  state.jwks.clear();
  for (const key of jwks.keys || []) {
    state.jwks.set(key.kid, key);
  }
}

async function loadTransactions() {
  try {
    await loadJWKS();
    const data         = await fetchJSON(`${API}/transactions`);
    const transactions = data.transactions || [];

    const rows = [];
    for (const tx of transactions) {
      const valid = verifyTxSignature(tx);
      rows.push({
        id:              tx.id,
        walletID:        tx.wallet_id,
        asset:           tx.asset,
        amount:          tx.amount,
        time:            new Date(tx.created_at).toLocaleString(),
        valid:           valid === null ? "N/A" : (valid ? "OK" : "BAD"),
        ciphertext:      tx.ciphertext,
        clientEncrypted: tx.client_encrypted,
      });
    }

    state.rows = rows;
    state.page = 0;
    renderPage();
    setTxStatus(`Получено транзакций: ${transactions.length}`);
  } catch (err) {
    setTxStatus(`Ошибка загрузки: ${err.message}`);
  }
}

function verifyTxSignature(tx) {
  const jwk = state.jwks.get(tx.kid);
  if (!jwk) return false;
  try {
    const payload   = base64UrlDecode(tx.payload_b64);
    const sigBytes  = base64UrlDecode(tx.signature);
    return RSA.verify(jwk, payload, sigBytes);
  } catch {
    return false;
  }
}

async function decryptWithPrivateKey(ciphertextB64) {
  const cipherBuf = base64UrlDecode(ciphertextB64);
  const plain = await RSA.decrypt(state.wallet.decryptJwk, state.wallet.decryptKey, cipherBuf);
  return new TextDecoder().decode(plain);
}

async function decryptWithServer(txID, ciphertextB64) {
  const data = await fetchJSON(`${API}/transactions/decrypt`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ tx_id: txID, ciphertext: ciphertextB64 }),
  });
  return data.note || "";
}

function renderPage() {
  const total      = state.rows.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  state.page = Math.min(state.page, totalPages - 1);
  const slice = state.rows.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
  renderRows(slice);
  renderPagination(totalPages);
}

function renderPagination(totalPages) {
  el.pagination.innerHTML = "";
  if (totalPages <= 1) return;

  const prev = document.createElement("button");
  prev.textContent = "←";
  prev.className = "page-btn";
  prev.disabled = state.page === 0;
  prev.addEventListener("click", () => { state.page--; renderPage(); });
  el.pagination.appendChild(prev);

  for (let i = 0; i < totalPages; i++) {
    const btn = document.createElement("button");
    btn.textContent = i + 1;
    btn.className = "page-btn" + (i === state.page ? " page-btn--active" : "");
    btn.addEventListener("click", () => { state.page = i; renderPage(); });
    el.pagination.appendChild(btn);
  }

  const next = document.createElement("button");
  next.textContent = "→";
  next.className = "page-btn";
  next.disabled = state.page === totalPages - 1;
  next.addEventListener("click", () => { state.page++; renderPage(); });
  el.pagination.appendChild(next);
}

function renderRows(rows) {
  el.txBody.innerHTML = "";

  for (const row of rows) {
    const tr          = document.createElement("tr");
    const isMine      = state.wallet && row.walletID === state.wallet.id;
    const shortCipher = row.ciphertext.slice(0, 20) + "…";

    tr.innerHTML = `
      <td>${escapeHtml(row.id)}</td>
      <td class="${isMine ? "wallet-mine" : ""}">${escapeHtml(String(row.walletID))}${isMine ? " 🔑" : ""}</td>
      <td><span class="badge badge--asset">${escapeHtml(String(row.asset))}</span></td>
      <td class="amount">${escapeHtml(String(row.amount))}</td>
      <td class="time">${escapeHtml(row.time)}</td>
      <td><span class="badge badge--${row.valid === "OK" ? "ok" : row.valid === "BAD" ? "bad" : "na"}">${escapeHtml(row.valid)}</span></td>
      <td><span class="cipher-preview" title="${escapeHtml(row.ciphertext)}">${escapeHtml(shortCipher)}</span></td>
    `;

    const decryptCell = document.createElement("td");
    const decryptBtn  = document.createElement("button");
    const result      = document.createElement("div");
    result.className  = "decrypt-result";

    if (row.clientEncrypted && !isMine) {
      decryptBtn.textContent = "🔒 Недоступно";
      decryptBtn.className   = "btn-decrypt btn-decrypt--locked";
      decryptBtn.disabled    = true;
      result.className       = "decrypt-result hint";
      result.textContent     = "Зашифровано чужим ключом";
    } else {
      decryptBtn.textContent = "Расшифровать";
      decryptBtn.className   = "btn-decrypt";

      decryptBtn.addEventListener("click", async () => {
        const isMineNow = state.wallet && row.walletID === state.wallet.id;

        if (row.clientEncrypted && !isMineNow) {
          result.className   = "decrypt-result error";
          result.textContent = "⚠ Зашифровано чужим ключом";
          return;
        }

        try {
          decryptBtn.disabled = true;
          result.className    = "decrypt-result loading";
          result.textContent  = "⏳ Расшифровка…";

          const note = (row.clientEncrypted && isMineNow)
            ? await decryptWithPrivateKey(row.ciphertext)
            : await decryptWithServer(row.id, row.ciphertext);

          result.className   = "decrypt-result success";
          result.textContent = note;
        } catch (err) {
          result.className   = "decrypt-result error";
          result.textContent = `⚠ ${err.message}`;
        } finally {
          decryptBtn.disabled = false;
        }
      });
    }

    decryptCell.appendChild(decryptBtn);
    decryptCell.appendChild(result);
    tr.appendChild(decryptCell);
    el.txBody.appendChild(tr);
  }
}

function deriveKidSync(jwk) {
  const nBytes = base64UrlDecode(jwk.n);
  const eBytes = base64UrlDecode(jwk.e);
  const concat = new Uint8Array(nBytes.length + eBytes.length);
  concat.set(nBytes);
  concat.set(eBytes, nBytes.length);
  const hash = RSA.sha256Sync(concat);
  return toBase64Url(hash.slice(0, 8));
}

async function fetchJSON(url, init = {}) {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

function setWalletStatus(html, type = "") {
  el.walletStatus.innerHTML = html;
  el.walletStatus.className = `wallet-status wallet-status--${type}`;
}

function setTxStatus(text) {
  el.txStatus.textContent = text;
}

function base64UrlDecode(s) {
  const normalized = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded     = normalized + "===".slice((normalized.length + 3) % 4);
  const str        = atob(padded);
  const bytes      = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escapeHtml(str) {
  return str
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}
