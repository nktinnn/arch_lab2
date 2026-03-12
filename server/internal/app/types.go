package app

import (
	"crypto/rsa"
	"time"
)

type publicJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid,omitempty"`
}

type privateJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
	Dp  string `json:"dp"`
	Dq  string `json:"dq"`
	Qi  string `json:"qi"`
	Kid string `json:"kid,omitempty"`
}

type challengeRequest struct {
	WalletID      string    `json:"wallet_id"`
	PublicJWK     publicJWK `json:"public_jwk"`
	EncryptionJWK publicJWK `json:"encryption_jwk"`
}

type challengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type tokenRequest struct {
	WalletID    string `json:"wallet_id"`
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type jwksResponse struct {
	Keys []publicJWK `json:"keys"`
}

type txPayload struct {
	TxID            string  `json:"tx_id"`
	WalletID        string  `json:"wallet_id"`
	Asset           string  `json:"asset"`
	Amount          float64 `json:"amount"`
	CreatedUnix     int64   `json:"created_unix"`
	Ciphertext      string  `json:"ciphertext"`
	ClientEncrypted bool    `json:"client_encrypted"`
}

type transaction struct {
	ID              string    `json:"id"`
	WalletID        string    `json:"wallet_id"`
	Asset           string    `json:"asset"`
	Amount          float64   `json:"amount"`
	CreatedAt       time.Time `json:"created_at"`
	Ciphertext      string    `json:"ciphertext"`
	ClientEncrypted bool      `json:"client_encrypted"`
	PayloadB64      string    `json:"payload_b64"`
	Signature       string    `json:"signature"`
	Kid             string    `json:"kid"`
}

type wallet struct {
	ID            string
	PubKey        *rsa.PublicKey
	EncryptPubKey *rsa.PublicKey
	Kid           string
}

type authChallenge struct {
	ID        string
	WalletID  string
	Value     string
	ExpiresAt time.Time
}

type decryptRequest struct {
	TxID       string `json:"tx_id"`
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	Note string `json:"note"`
}
