package httpserver

import (
	"blockchain/server/internal/app"
	"net/http"
)

func SetupRoutes(mux *http.ServeMux, a *app.App) http.Handler {
	mux.HandleFunc("/health", a.HandleHealth)
	mux.HandleFunc("/auth/keygen", a.HandleKeygen)
	mux.HandleFunc("/auth/challenge", a.HandleChallenge)
	mux.HandleFunc("/auth/login", a.HandleGetToken)
	mux.HandleFunc("/getJWKS", a.HandleGetJWKS)
	mux.HandleFunc("/transactions", a.HandleTransactions)
	mux.HandleFunc("/transactions/decrypt", a.HandleDecryptCiphertext)
	mux.HandleFunc("/transactions/", a.HandleTransactionByID)

	return withCORS(mux)
}
