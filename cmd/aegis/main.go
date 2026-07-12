package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
)

const (
	natsURL  = "nats://aegis:aegis@localhost:4222"
	dbURL    = "host=127.0.0.1 user=aegis password=aegis dbname=aegis sslmode=disable"
	pageSize = 10
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
	case "report":
		cmdReport()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  aegis scan --target <cible>")
	fmt.Println("  aegis results")
	fmt.Println("  aegis results --target <cible>")
	fmt.Println("  aegis results --since <YYYY-MM-DD>")
	fmt.Println("  aegis results --page <n°>")
	fmt.Println("  aegis report --last")
	fmt.Println("  aegis report --scan <n°>")
}

func getArg(name string) string {
	for i, arg := range os.Args {
		if arg == name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == name {
			return true
		}
	}
	return false
}

func cmdScan() {
	target := getArg("--target")
	if target == "" {
		log.Fatal("Erreur : --target requis")
	}

	scanID := uuid.New().String()

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
	fmt.Printf("  Heure   : %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("→ Lance 'aegis report --last' pour voir le résultat\n")
}

func cmdResults() {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Erreur PostgreSQL : %v", err)
	}
	defer db.Close()

	// Paramètres
	target := getArg("--target")
	since := getArg("--since")
	page := 1
	if p := getArg("--page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	offset := (page - 1) * pageSize

	// Construction de la requête dynamique
	query := `
		SELECT s.id, s.status, s.profile, s.created_at,
		       COUNT(f.id) as total,
		       s.scope->>'targets' as targets
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if target != "" {
		query += fmt.Sprintf(" AND s.scope->>'targets' LIKE $%d", argIdx)
		args = append(args, "%"+target+"%")
		argIdx++
	}

	if since != "" {
		query += fmt.Sprintf(" AND s.created_at >= $%d", argIdx)
		args = append(args, since)
		argIdx++
	}

	query += fmt.Sprintf(`
		GROUP BY s.id
		ORDER BY s.created_at DESC
		LIMIT %d OFFSET %d
	`, pageSize, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Fatalf("Erreur requête : %v", err)
	}
	defer rows.Close()

	fmt.Println("\n=== AegiS — Scans récents ===")
	if target != "" {
		fmt.Printf("    Filtre cible  : %s\n", target)
	}
	if since != "" {
		fmt.Printf("    Filtre date   : depuis %s\n", since)
	}
	fmt.Printf("    Page          : %d\n\n", page)

	count := 0
	for rows.Next() {
		var id, status, profile, targets string
		var createdAt time.Time
		var total int
		rows.Scan(&id, &status, &profile, &createdAt, &total, &targets)
		fmt.Printf("  [%d] [%s] %s — %s — %d finding(s)\n",
			offset+count+1, status, createdAt.Format("2006-01-02 15:04"), targets, total)
		count++
	}

	if count == 0 {
		fmt.Println("  Aucun scan trouvé.")
	}

	fmt.Println("\n→ aegis report --last")
	fmt.Println("→ aegis report --scan <n°>")
	if count == pageSize {
		fmt.Printf("→ aegis results --page %d  (page suivante)\n", page+1)
	}
}

func printReport(db *sql.DB, scanID string) {
	var status, profile string
	var createdAt time.Time
	err := db.QueryRow(`
		SELECT status, profile, created_at FROM scans WHERE id = $1
	`, scanID).Scan(&status, &profile, &createdAt)
	if err != nil {
		log.Fatalf("Scan introuvable : %v", err)
	}

	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║         AegiS — Rapport de scan      ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("\nScan ID : %s\n", scanID)
	fmt.Printf("Profil  : %s\n", profile)
	fmt.Printf("Statut  : %s\n", status)
	fmt.Printf("Date    : %s\n", createdAt.Format("2006-01-02 15:04:05"))

	severities := []string{"critical", "high", "medium", "low", "info"}
	labels := map[string]string{
		"critical": "🔴 CRITIQUE",
		"high":     "🟠 ÉLEVÉ",
		"medium":   "🟡 MOYEN",
		"low":      "🟢 FAIBLE",
		"info":     "⚪ INFO",
	}

	totalFindings := 0
	for _, sev := range severities {
		rows, err := db.Query(`
			SELECT f.title, f.source, f.description, a.value
			FROM findings f
			JOIN assets a ON f.asset_id = a.id
			WHERE f.scan_id = $1 AND f.severity = $2
			ORDER BY f.discovered_at DESC
		`, scanID, sev)
		if err != nil {
			continue
		}

		var sevFindings []struct {
			title, source, description, asset string
		}
		for rows.Next() {
			var title, source, description, asset string
			rows.Scan(&title, &source, &description, &asset)
			sevFindings = append(sevFindings, struct {
				title, source, description, asset string
			}{title, source, description, asset})
		}
		rows.Close()

		if len(sevFindings) == 0 {
			continue
		}

		fmt.Printf("\n%s (%d)\n", labels[sev], len(sevFindings))
		fmt.Println("────────────────────────────────────────")
		for _, f := range sevFindings {
			fmt.Printf("  • %s\n", f.title)
			fmt.Printf("    Asset  : %s\n", f.asset)
			fmt.Printf("    Source : %s\n", f.source)
			if f.description != "" {
				desc := f.description
				if len(desc) > 120 {
					desc = desc[:120] + "..."
				}
				fmt.Printf("    Détail : %s\n", desc)
			}
			fmt.Println()
		}
		totalFindings += len(sevFindings)
	}

	fmt.Println("────────────────────────────────────────")
	fmt.Printf("Total : %d finding(s)\n\n", totalFindings)
}

func cmdReport() {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Erreur PostgreSQL : %v", err)
	}
	defer db.Close()

	if hasFlag("--last") {
		var scanID string
		err := db.QueryRow(`SELECT id FROM scans ORDER BY created_at DESC LIMIT 1`).Scan(&scanID)
		if err != nil {
			log.Fatal("Aucun scan trouvé")
		}
		printReport(db, scanID)
		return
	}

	scanNum := getArg("--scan")
	if scanNum == "" {
		log.Fatal("Erreur : --last ou --scan <n°> requis")
	}

	idx, err := strconv.Atoi(scanNum)
	if err != nil || idx < 1 {
		log.Fatal("Numéro invalide")
	}

	var scanID string
	err = db.QueryRow(`
		SELECT id FROM scans
		ORDER BY created_at DESC
		LIMIT 1 OFFSET $1
	`, idx-1).Scan(&scanID)
	if err != nil {
		log.Fatalf("Scan numéro %d introuvable", idx)
	}

	printReport(db, scanID)
}
