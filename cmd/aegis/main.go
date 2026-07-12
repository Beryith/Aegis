package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	natsURL = "nats://aegis:aegis@localhost:4222"
	dbURL   = "host=127.0.0.1 user=aegis password=aegis dbname=aegis sslmode=disable"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan()
	case "results":
		cmdResults()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  aegis scan --target <cible>")
	fmt.Println("  aegis results")
}

func cmdScan() {
	target := ""
	for i, arg := range os.Args {
		if arg == "--target" && i+1 < len(os.Args) {
			target = os.Args[i+1]
		}
	}

	if target == "" {
		log.Fatal("Erreur : --target requis")
	}

	scanID := uuid.New().String()

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("Erreur NATS : %v", err)
	}
	defer nc.Close()

	payload, _ := json.Marshal(map[string]string{
		"scan_id": scanID,
		"target":  target,
	})

	if err := nc.Publish("aegis.discovery.scan", payload); err != nil {
		log.Fatalf("Erreur publication : %v", err)
	}

	fmt.Printf("✓ Scan lancé\n")
	fmt.Printf("  Cible   : %s\n", target)
	fmt.Printf("  Scan ID : %s\n", scanID)
	fmt.Printf("  Heure   : %s\n", time.Now().Format("2006-01-02 15:04:05"))
}

func cmdResults() {
	fmt.Println("→ Commande 'results' — disponible à l'Étape 10")
}
