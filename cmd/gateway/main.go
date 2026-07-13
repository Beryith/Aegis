package main

import (
	"log"
	"os"

	"github.com/aegis/internal/gateway"
)

func main() {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		dbURL = "host=127.0.0.1 user=aegis password=aegis dbname=aegis sslmode=disable"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://aegis:aegis@localhost:4222"
	}

	g, err := gateway.New(dbURL, natsURL)
	if err != nil {
		log.Fatalf("[gateway] Erreur d'initialisation : %v", err)
	}

	log.Println("[gateway] Démarré sur :8080")
	if err := g.Start(":8080"); err != nil {
		log.Fatalf("[gateway] Erreur : %v", err)
	}
}
