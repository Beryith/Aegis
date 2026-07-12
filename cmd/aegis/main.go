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
	case "ai":
		cmdAI()
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
	fmt.Println("  aegis ai status")
	fmt.Println("  aegis ai use <provider>")
	fmt.Println("  aegis ai config <provider> --key <clé>")
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
	fmt.Printf("⏳ Analyse en cours (Discovery → Intelligence → Corrélation → IA)...\n")

	waitForCompletion(db, scanID)
	printReport(db, scanID)
}

func countBySource(db *sql.DB, scanID string, source string) int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND source = $2", scanID, source).Scan(&count)
	return count
}

func getProviderTimeout() int {
	config := loadAegisConfig()
	ai, ok := config["ai"].(map[string]interface{})
	if !ok {
		return 900
	}
	provider, ok := ai["provider"].(string)
	if !ok {
		return 900
	}

	baseTimeouts := map[string]int{
		"ollama":    900,
		"groq":      60,
		"gemini":    60,
		"openai":    60,
		"anthropic": 60,
	}

	if t, ok := baseTimeouts[provider]; ok {
		return t
	}
	return 900
}

func countTotalFindings(db *sql.DB, scanID string) int {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM findings WHERE scan_id = $1", scanID).Scan(&count)
	return count
}

func waitForCompletion(db *sql.DB, scanID string) {
	providerTimeout := getProviderTimeout()

	// Plancher minimum pour la phase réseau (Discovery), indépendant du provider IA.
	// Un scan Nmap sur une cible filtrée/protégée peut à lui seul dépasser 100s.
	const discoveryFloor = 240
	baseTimeout := providerTimeout
	if baseTimeout < discoveryFloor {
		baseTimeout = discoveryFloor
	}

	maxWait := baseTimeout
	elapsed := 0
	interval := 2
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0

	stages := []struct {
		name     string
		source   string
		done     bool
		label    string
	}{
		{"discovery", "discovery", false, "Discovery"},
		{"intelligence", "intelligence", false, "Intelligence"},
		{"correlation", "correlation", false, "Corrélation"},
	}

	currentStage := 0

	for elapsed < maxWait {
		var status string
		db.QueryRow("SELECT status FROM scans WHERE id = $1", scanID).Scan(&status)

		if status == "completed" {
			fmt.Print("\r")
			for i := range stages {
				if !stages[i].done {
					count := countBySource(db, scanID, stages[i].source)
					fmt.Printf("✓ %-14s terminé  (%d finding(s))\n", stages[i].label, count)
				}
			}
			fmt.Println("✓ Analyse IA    terminée")
			fmt.Println()
			return
		}

		// Vérifier si l'étape courante est terminée (au moins 1 finding ou temps suffisant)
		if currentStage < len(stages) {
			count := countBySource(db, scanID, stages[currentStage].source)
			if count > 0 && currentStage < len(stages)-1 {
				fmt.Printf("\r✓ %-14s terminé  (%d finding(s))                    \n", stages[currentStage].label, count)
				stages[currentStage].done = true
				currentStage++

				// Recalcule le budget de temps une fois qu'on connaît le volume réel de findings
				if stages[currentStage-1].source == "intelligence" {
					total := countTotalFindings(db, scanID)
					bonus := 0
					if total > 10 {
						bonus = (total - 10) * 5
					}
					maxWait = baseTimeout + bonus
				}
			}
		}

		label := "Analyse IA (peut prendre plusieurs minutes)"
		if currentStage < len(stages) {
			label = stages[currentStage].label
		}

		fmt.Printf("\r%s %-14s en cours...                    ", spinner[spinIdx], label)
		spinIdx = (spinIdx + 1) % len(spinner)

		time.Sleep(time.Duration(interval) * time.Second)
		elapsed += interval
	}

	fmt.Println("\n⚠️  Délai dépassé — affichage des résultats partiels\n")
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

	printRecommendations(db, scanID)
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

func printRecommendations(db *sql.DB, scanID string) {
	rows, err := db.Query(`
		SELECT title, priority, findings_summary, recommendation, generated_at
		FROM recommendations
		WHERE scan_id = $1
		ORDER BY generated_at DESC
	`, scanID)
	if err != nil {
		return
	}
	defer rows.Close()

	priorities := map[string]string{
		"immediate":   "🚨 IMMÉDIAT",
		"short_term":  "⚡ COURT TERME",
		"medium_term": "📅 MOYEN TERME",
		"long_term":   "🔭 LONG TERME",
	}

	hasRec := false
	for rows.Next() {
		if !hasRec {
			fmt.Println("\n╔══════════════════════════════════════╗")
			fmt.Println("║      AegiS — Recommandations IA      ║")
			fmt.Println("╚══════════════════════════════════════╝")
			hasRec = true
		}

		var title, priority, findingsSummaryStr, recommendationStr string
		var generatedAt time.Time
		rows.Scan(&title, &priority, &findingsSummaryStr, &recommendationStr, &generatedAt)

		var rec map[string]string
		json.Unmarshal([]byte(recommendationStr), &rec)

		label := priorities[priority]
		if label == "" {
			label = priority
		}

		fmt.Printf("\n%s\n", label)
		fmt.Printf("  %s\n", title)
		fmt.Println("────────────────────────────────────────")

		if rec["context"] != "" {
			fmt.Printf("  Contexte : %s\n\n", rec["context"])
		}
		if rec["action"] != "" {
			fmt.Printf("  Action   : %s\n\n", rec["action"])
		}
		if rec["impact"] != "" {
			fmt.Printf("  Impact   : %s\n\n", rec["impact"])
		}
		if rec["effort"] != "" {
			fmt.Printf("  Effort   : %s\n", rec["effort"])
		}
		fmt.Printf("  Généré   : %s\n", generatedAt.Format("2006-01-02 15:04:05"))
	}
}

func cmdAI() {
	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  aegis ai status")
		fmt.Println("  aegis ai use <provider>")
		fmt.Println("  aegis ai config <provider> --key <clé>")
		return
	}

	switch os.Args[2] {
	case "status":
		cmdAIStatus()
	case "use":
		cmdAIUse()
	case "config":
		cmdAIConfig()
	default:
		fmt.Println("Commande inconnue")
	}
}

func loadAegisConfig() map[string]interface{} {
	home, _ := os.UserHomeDir()
	path := home + "/.aegis/config.json"
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{}
	}
	var config map[string]interface{}
	json.Unmarshal(data, &config)
	return config
}

func saveAegisConfig(config map[string]interface{}) {
	home, _ := os.UserHomeDir()
	path := home + "/.aegis/config.json"
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(path, data, 0600)
}

func cmdAIStatus() {
	config := loadAegisConfig()
	ai := config["ai"].(map[string]interface{})
	active := ai["provider"].(string)
	providers := ai["providers"].(map[string]interface{})

	descriptions := map[string]string{
		"ollama":    "local       — aucune donnée externe",
		"groq":      "rapide      — données envoyées à Groq",
		"gemini":    "rapide      — données envoyées à Google",
		"openai":    "très rapide — données envoyées à OpenAI",
		"anthropic": "très rapide — données envoyées à Anthropic",
	}

	fmt.Println("\n=== AegiS — Providers IA ===\n")
	for _, name := range []string{"ollama", "groq", "gemini", "openai", "anthropic"} {
		marker := "○"
		activeLabel := ""
		keyStatus := ""

		if name == active {
			marker = "✓"
			activeLabel = "[ACTIF] "
		}

		if name == "ollama" {
			keyStatus = "[disponible]   "
		} else {
			p, ok := providers[name].(map[string]interface{})
			if ok {
				key, _ := p["api_key"].(string)
				if key != "" {
					keyStatus = "[clé configurée]"
				} else {
					keyStatus = "[clé manquante] "
				}
			}
		}

		fmt.Printf("  %s %-10s %s %s  %s\n",
			marker, name, activeLabel, keyStatus, descriptions[name])
	}

	fmt.Println("\n→ aegis ai use <provider>              changer de provider")
	fmt.Println("→ aegis ai config <provider> --key <clé>  configurer une clé API")
}

func cmdAIUse() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: aegis ai use <provider>")
		return
	}

	provider := os.Args[3]
	validProviders := []string{"ollama", "groq", "gemini", "openai", "anthropic"}
	valid := false
	for _, p := range validProviders {
		if p == provider {
			valid = true
			break
		}
	}

	if !valid {
		fmt.Printf("Provider inconnu : %s\n", provider)
		fmt.Printf("Providers disponibles : %v\n", validProviders)
		return
	}

	// Avertissement pour les providers externes
	if provider != "ollama" {
		fmt.Printf("\n⚠️  Attention — Provider externe sélectionné\n")
		fmt.Printf("   Les findings de vos scans seront envoyés à %s.\n", provider)
		fmt.Printf("   Assurez-vous que cela est conforme à votre politique de confidentialité.\n")
		fmt.Printf("   Confirmer ? [o/N] ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "o" && confirm != "O" {
			fmt.Println("Annulé.")
			return
		}
	}

	config := loadAegisConfig()
	ai := config["ai"].(map[string]interface{})
	ai["provider"] = provider
	config["ai"] = ai
	saveAegisConfig(config)

	fmt.Printf("✓ Provider actif : %s\n", provider)
	if provider == "ollama" {
		fmt.Println("  Aucune donnée ne quitte votre infrastructure.")
	} else {
		fmt.Printf("  Redémarre le service AI pour appliquer le changement.\n")
	}
}

func cmdAIConfig() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: aegis ai config <provider> --key <clé>")
		return
	}

	provider := os.Args[3]
	key := getArg("--key")

	if key == "" {
		fmt.Println("Erreur : --key requis")
		return
	}

	config := loadAegisConfig()
	ai := config["ai"].(map[string]interface{})
	providers := ai["providers"].(map[string]interface{})
	p := providers[provider].(map[string]interface{})
	p["api_key"] = key
	providers[provider] = p
	ai["providers"] = providers
	config["ai"] = ai
	saveAegisConfig(config)

	fmt.Printf("✓ Clé API configurée pour %s\n", provider)
}
