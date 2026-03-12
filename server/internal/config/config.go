package config

import (
	"os"
	"time"
)

type Config struct {
	Port              string
	ReadHeaderTimeout time.Duration
	ChallengeTTL      time.Duration
	TokenTTL          time.Duration
	GenerateInterval  time.Duration
	CleanupInterval   time.Duration
}

func Load() Config {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	return Config{
		Port:              port,
		ReadHeaderTimeout: 5 * time.Second,
		ChallengeTTL:      90 * time.Second,
		TokenTTL:          15 * time.Minute,
		GenerateInterval:  2 * time.Second,
		CleanupInterval:   30 * time.Second,
	}
}
