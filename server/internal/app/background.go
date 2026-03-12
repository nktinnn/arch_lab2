package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

func (a *App) GenerateTransactionsLoop() {
	ticker := time.NewTicker(a.cfg.GenerateInterval)
	defer ticker.Stop()

	for range ticker.C {
		a.mu.RLock()
		walletIDs := make([]string, 0, len(a.wallets))
		for id := range a.wallets {
			walletIDs = append(walletIDs, id)
		}
		a.mu.RUnlock()

		if len(walletIDs) == 0 {
			continue
		}

		sort.Strings(walletIDs)
		walletID := walletIDs[a.rng.Intn(len(walletIDs))]

		a.mu.RLock()
		wlt := a.wallets[walletID]
		a.mu.RUnlock()

		if wlt.PubKey == nil {
			continue
		}

		encKey := wlt.EncryptPubKey
		clientEncrypted := encKey != nil
		if !clientEncrypted {
			encKey = &a.serverPriv.PublicKey
		}

		note := fmt.Sprintf("tx approved for %s at %s", walletID, time.Now().UTC().Format(time.RFC3339))
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, encKey, []byte(note), nil)
		if err != nil {
			continue
		}

		a.mu.Lock()
		a.txCursor++
		txID := fmt.Sprintf("tx-%06d", a.txCursor)
		a.mu.Unlock()

		amount := math.Round((1+a.rng.Float64()*9)*100) / 100
		asset := []string{"BTC", "ETH", "USDT"}[a.rng.Intn(3)]
		payload := txPayload{
			TxID:            txID,
			WalletID:        walletID,
			Asset:           asset,
			Amount:          amount,
			CreatedUnix:     time.Now().UTC().Unix(),
			Ciphertext:      b64url.EncodeToString(ciphertext),
			ClientEncrypted: clientEncrypted,
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		h := sha256.Sum256(payloadJSON)
		sig, err := rsa.SignPKCS1v15(rand.Reader, a.serverPriv, crypto.SHA256, h[:])
		if err != nil {
			continue
		}

		tx := transaction{
			ID:              txID,
			WalletID:        walletID,
			Asset:           asset,
			Amount:          amount,
			CreatedAt:       time.Unix(payload.CreatedUnix, 0).UTC(),
			Ciphertext:      payload.Ciphertext,
			ClientEncrypted: clientEncrypted,
			PayloadB64:      b64url.EncodeToString(payloadJSON),
			Signature:       b64url.EncodeToString(sig),
			Kid:             a.serverKid,
		}

		a.mu.Lock()
		a.txs = append(a.txs, tx)
		a.txByID[tx.ID] = tx
		if len(a.txs) > 1000 {
			drop := a.txs[0]
			a.txs = a.txs[1:]
			delete(a.txByID, drop.ID)
		}
		a.mu.Unlock()
	}
}

func (a *App) CleanupLoop() {
	ticker := time.NewTicker(a.cfg.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().UTC()
		a.mu.Lock()
		for id, challenge := range a.challenges {
			if now.After(challenge.ExpiresAt) {
				delete(a.challenges, id)
			}
		}
		a.mu.Unlock()
	}
}
