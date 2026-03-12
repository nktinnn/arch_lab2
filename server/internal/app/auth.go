package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (a *App) HandleKeygen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	signPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}
	encPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}

	signPub := toPublicJWK(&signPriv.PublicKey, kidFromPublicKey(&signPriv.PublicKey))
	encPub := toPublicJWK(&encPriv.PublicKey, kidFromPublicKey(&encPriv.PublicKey))

	writeJSON(w, http.StatusOK, map[string]any{
		"sign_private_jwk": toPrivateJWK(signPriv, signPub.Kid),
		"sign_public_jwk":  signPub,
		"enc_private_jwk":  toPrivateJWK(encPriv, encPub.Kid),
		"enc_public_jwk":   encPub,
	})
}

func (a *App) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *App) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.WalletID) == "" {
		http.Error(w, "wallet_id is required", http.StatusBadRequest)
		return
	}

	pub, err := parsePublicJWK(req.PublicJWK)
	if err != nil {
		http.Error(w, "invalid public_jwk", http.StatusBadRequest)
		return
	}

	encPub, err := parsePublicJWK(req.EncryptionJWK)
	if err != nil {
		http.Error(w, "invalid encryption_jwk", http.StatusBadRequest)
		return
	}

	challengeID, err := randomToken(18)
	if err != nil {
		http.Error(w, "failed to create challenge", http.StatusInternalServerError)
		return
	}
	challengeValue, err := randomToken(32)
	if err != nil {
		http.Error(w, "failed to create challenge", http.StatusInternalServerError)
		return
	}

	kid := req.PublicJWK.Kid
	if strings.TrimSpace(kid) == "" {
		kid = kidFromPublicKey(pub)
	}

	expiresAt := time.Now().UTC().Add(a.cfg.ChallengeTTL)

	a.mu.Lock()
	a.wallets[req.WalletID] = wallet{ID: req.WalletID, PubKey: pub, EncryptPubKey: encPub, Kid: kid}
	a.challenges[challengeID] = authChallenge{ID: challengeID, WalletID: req.WalletID, Value: challengeValue, ExpiresAt: expiresAt}
	a.mu.Unlock()

	writeJSON(w, http.StatusOK, challengeResponse{ChallengeID: challengeID, Challenge: challengeValue, ExpiresAt: expiresAt})
}

func (a *App) HandleGetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	challenge, ok := a.challenges[req.ChallengeID]
	if ok {
		delete(a.challenges, req.ChallengeID)
	}
	wlt, wOk := a.wallets[req.WalletID]
	a.mu.Unlock()

	if !ok || !wOk || subtle.ConstantTimeCompare([]byte(challenge.WalletID), []byte(req.WalletID)) != 1 {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		http.Error(w, "challenge expired", http.StatusUnauthorized)
		return
	}

	sigBytes, err := b64url.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	h := sha256.Sum256([]byte(challenge.Value))
	if err := rsa.VerifyPKCS1v15(wlt.PubKey, crypto.SHA256, h[:], sigBytes); err != nil {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	expiresAt := time.Now().UTC().Add(a.cfg.TokenTTL)
	token, err := createJWT(a.serverPriv, a.serverKid, req.WalletID, expiresAt)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresAt: expiresAt})
}

func (a *App) HandleGetJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, jwksResponse{Keys: []publicJWK{toPublicJWK(&a.serverPriv.PublicKey, a.serverKid)}})
}
