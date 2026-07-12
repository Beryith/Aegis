package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
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

	// Créer le scan en base
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Erreur PostgreSQL : %v", err)
	}
	defer db.Close()

	scope, _ := json.Marshal(map[string]interface{}{
		"targets":       []string{target},
		"excluded":      []string{},
		"authorized_by": "cli",
	})

	_, err = db.Exec(`
		INSERT INTO scans (id, status, profile, scope, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, scanID, "running", "active", string(scope), time.Now())
	if err != nil {
		log.Fatalf("Erreur création scan : %v", err)
	}

	// Publier sur NATS
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
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Erreur PostgreSQL : %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT f.title, f.severity, f.status, a.value, f.discovered_at
		FROM findings f
		JOIN assets a ON f.asset_id = a.id
		ORDER BY f.discovered_at DESC
		LIMIT 50
	`)
	if err != nil {
		log.Fatalf("Erreur requête : %v", err)
	}
	defer rows.Close()

	fmt.Println("\n=== AegiS — Findings ===\n")
	count := 0
	for rows.Next() {
		var title, severity, status, asset string
		var discoveredAt time.Time
		rows.Scan(&title, &severity, &status, &asset, &discoveredAt)
		fmt.Printf("[%s] %s\n", severity, title)
		fmt.Printf("  Asset    : %s\n", asset)
		fmt.Printf("  Statut   : %s\n", status)
		fmt.Printf("  Détecté  : %s\n\n", discoveredAt.Format("2006-01-02 15:04:05"))
		count++
	}

	if count == 0 {
		fmt.Println("Aucun finding trouvé.")
	} else {
		fmt.Printf("Total : %d finding(s)\n", count)
	}
}
