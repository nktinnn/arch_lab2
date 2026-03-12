package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (a *App) HandleTransactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.mu.RLock()
	res := make([]transaction, len(a.txs))
	for i := range a.txs {
		res[len(a.txs)-1-i] = a.txs[i]
	}
	a.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{"transactions": res})
}

func (a *App) HandleTransactionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/transactions/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	a.mu.RLock()
	tx, ok := a.txByID[id]
	a.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	writeJSON(w, http.StatusOK, tx)
}

func (a *App) HandleDecryptCiphertext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req decryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.TxID) == "" || strings.TrimSpace(req.Ciphertext) == "" {
		http.Error(w, "tx_id and ciphertext are required", http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	tx, ok := a.txByID[req.TxID]
	a.mu.RUnlock()
	if !ok || tx.Ciphertext != req.Ciphertext {
		http.Error(w, "transaction not found", http.StatusNotFound)
		return
	}

	if tx.ClientEncrypted {
		http.Error(w, "transaction is encrypted with client key", http.StatusForbidden)
		return
	}

	ciphertext, err := b64url.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}

	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, a.serverPriv, ciphertext, nil)
	if err != nil {
		if errors.Is(err, rsa.ErrDecryption) {
			http.Error(w, "decryption failed", http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, decryptResponse{Note: string(plain)})
}
