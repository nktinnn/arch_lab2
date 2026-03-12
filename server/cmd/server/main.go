package main

import (
	"blockchain/server/internal/app"
	"blockchain/server/internal/config"
	"blockchain/server/internal/httpserver"
	"fmt"
	"log"
	"net/http"
)

func main() {
	cfg := config.Load()

	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialize app: %v", err)
	}

	go application.GenerateTransactionsLoop()
	go application.CleanupLoop()

	mux := http.NewServeMux()
	httpserver.SetupRoutes(mux, application)

	port := fmt.Sprintf(":%s", cfg.Port)
	fmt.Printf("server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, mux))
}
