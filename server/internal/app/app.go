package app

import (
	"blockchain/server/internal/config"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
)

var b64url = base64.RawURLEncoding

type App struct {
	mu sync.RWMutex

	wallets    map[string]wallet
	challenges map[string]authChallenge

	txs      []transaction
	txByID   map[string]transaction
	txCursor uint64

	serverPriv *rsa.PrivateKey
	serverKid  string
	rng        *mrand.Rand

	cfg config.Config
}

func New(cfg config.Config) (*App, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	a := &App{
		wallets:    make(map[string]wallet),
		challenges: make(map[string]authChallenge),
		txs:        make([]transaction, 0, 256),
		txByID:     make(map[string]transaction),
		serverPriv: priv,
		serverKid:  kidFromPublicKey(&priv.PublicKey),
		rng:        mrand.New(mrand.NewSource(time.Now().UnixNano())),
		cfg:        cfg,
	}

	a.seedWallets(8)
	return a, nil
}

func (a *App) seedWallets(count int) {
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("wallet-%03d", i)
		a.wallets[id] = wallet{ID: id, PubKey: nil, Kid: ""}
	}
	for i := 4; i <= count; i++ {
		id := fmt.Sprintf("wallet-%03d", i)
		a.wallets[id] = wallet{ID: id, PubKey: &a.serverPriv.PublicKey, EncryptPubKey: nil, Kid: a.serverKid}
	}
}
