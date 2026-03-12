package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

func createJWT(priv *rsa.PrivateKey, kid, sub string, expiresAt time.Time) (string, error) {
	head := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	payload := map[string]any{
		"iss": "blockchain-sim-server",
		"sub": sub,
		"iat": time.Now().UTC().Unix(),
		"exp": expiresAt.Unix(),
	}

	headJSON, err := json.Marshal(head)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	input := b64url.EncodeToString(headJSON) + "." + b64url.EncodeToString(payloadJSON)
	h := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64url.EncodeToString(sig), nil
}

func parsePublicJWK(jwk publicJWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("unsupported kty")
	}

	nBytes, err := b64url.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := b64url.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	if len(eBytes) == 0 {
		return nil, errors.New("empty exponent")
	}

	e := 0
	for _, b := range eBytes {
		e = (e << 8) + int(b)
	}
	if e < 3 {
		return nil, errors.New("invalid exponent")
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func toPublicJWK(pub *rsa.PublicKey, kid string) publicJWK {
	n := b64url.EncodeToString(pub.N.Bytes())
	e := b64url.EncodeToString(intToBytes(pub.E))
	return publicJWK{Kty: "RSA", N: n, E: e, Kid: kid}
}

func toPrivateJWK(priv *rsa.PrivateKey, kid string) privateJWK {
	return privateJWK{
		Kty: "RSA",
		N:   b64url.EncodeToString(priv.N.Bytes()),
		E:   b64url.EncodeToString(intToBytes(priv.E)),
		D:   b64url.EncodeToString(priv.D.Bytes()),
		P:   b64url.EncodeToString(priv.Primes[0].Bytes()),
		Q:   b64url.EncodeToString(priv.Primes[1].Bytes()),
		Dp:  b64url.EncodeToString(priv.Precomputed.Dp.Bytes()),
		Dq:  b64url.EncodeToString(priv.Precomputed.Dq.Bytes()),
		Qi:  b64url.EncodeToString(priv.Precomputed.Qinv.Bytes()),
		Kid: kid,
	}
}

func kidFromPublicKey(pub *rsa.PublicKey) string {
	thumb := sha256.Sum256(append(pub.N.Bytes(), intToBytes(pub.E)...))
	return b64url.EncodeToString(thumb[:8])
}

func intToBytes(v int) []byte {
	if v == 0 {
		return []byte{0}
	}

	buf := make([]byte, 0, 4)
	for v > 0 {
		buf = append([]byte{byte(v & 0xff)}, buf...)
		v >>= 8
	}
	return buf
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64url.EncodeToString(buf), nil
}
