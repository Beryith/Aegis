package main

import (
	"log"

	"github.com/aegis/internal/gateway"
)

func main() {
	g := gateway.New()

	log.Println("[gateway] Démarré sur :8080")
	if err := g.Start(":8080"); err != nil {
		log.Fatalf("[gateway] Erreur : %v", err)
	}
}
