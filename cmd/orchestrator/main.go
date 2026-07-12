package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegis/internal/orchestrator"
)

func main() {
	dbURL := "host=127.0.0.1 user=aegis password=aegis dbname=aegis sslmode=disable"
	natsURL := "nats://aegis:aegis@localhost:4222"

	o, err := orchestrator.New(dbURL, natsURL)
	if err != nil {
		log.Fatalf("[orchestrator] Erreur de démarrage : %v", err)
	}

	// Gestion de l'arrêt propre
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go o.Start()

	<-quit
	o.Stop()
}
