package e2e

import (
	"database/sql"
	"os/exec"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

const (
	testDBURL = "host=127.0.0.1 user=aegis password=aegis dbname=aegis sslmode=disable"
	testTarget = "scanme.nmap.org"
)

func TestScanEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("test end-to-end ignoré en mode -short (nécessite l'infrastructure complète)")
	}

	db, err := sql.Open("postgres", testDBURL)
	if err != nil {
		t.Fatalf("connexion PostgreSQL échouée : %v", err)
	}
	defer db.Close()

	// Étape 1 — Lancer le scan via la CLI compilée
	cmd := exec.Command("aegis", "scan", "--target", testTarget)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("échec de la commande scan : %v\nSortie : %s", err, output)
	}

	outputStr := string(output)

	// Étape 2 — Vérifier que le scan a été lancé correctement
	if !strings.Contains(outputStr, "Scan lancé") {
		t.Errorf("la sortie ne confirme pas le lancement du scan :\n%s", outputStr)
	}

	// Étape 3 — Extraire le scan_id de la sortie pour vérification en base
	scanID := extractScanID(outputStr)
	if scanID == "" {
		t.Fatal("impossible d'extraire le scan_id de la sortie")
	}

	// Étape 4 — Vérifier que le scan est marqué "completed" en base
	var status string
	err = db.QueryRow("SELECT status FROM scans WHERE id = $1", scanID).Scan(&status)
	if err != nil {
		t.Fatalf("scan introuvable en base : %v", err)
	}
	if status != "completed" {
		t.Errorf("statut attendu 'completed', obtenu '%s'", status)
	}

	// Étape 5 — Vérifier qu'au moins un finding a été produit
	var findingsCount int
	db.QueryRow("SELECT COUNT(*) FROM findings WHERE scan_id = $1", scanID).Scan(&findingsCount)
	if findingsCount == 0 {
		t.Error("aucun finding produit pour un scan sur une cible connue pour avoir des ports ouverts")
	}

	// Étape 6 — Vérifier la présence de findings Discovery (ports ouverts)
	var discoveryCount int
	db.QueryRow("SELECT COUNT(*) FROM findings WHERE scan_id = $1 AND source = 'discovery'", scanID).Scan(&discoveryCount)
	if discoveryCount == 0 {
		t.Error("aucun finding Discovery — le scan Nmap n'a probablement pas fonctionné")
	}

	t.Logf("✓ Scan terminé avec succès : %d finding(s) au total, %d issus de Discovery", findingsCount, discoveryCount)
}

func TestReportGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("test end-to-end ignoré en mode -short")
	}

	// Vérifie que 'aegis report --last' fonctionne sans erreur après un scan
	cmd := exec.Command("aegis", "report", "--last")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("échec de la commande report : %v\nSortie : %s", err, output)
	}

	if !strings.Contains(string(output), "Rapport de scan") {
		t.Error("le rapport généré ne contient pas l'en-tête attendu")
	}
}

func TestExportFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("test end-to-end ignoré en mode -short")
	}

	formats := []string{"json", "markdown", "pdf"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			outputFile := "/tmp/aegis_test_export." + format
			cmd := exec.Command("aegis", "report", "--last", "--export", format, "--output", outputFile)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("échec de l'export %s : %v\nSortie : %s", format, err, output)
			}

			if !strings.Contains(string(output), "Rapport exporté") {
				t.Errorf("confirmation d'export manquante pour le format %s", format)
			}
		})
	}
}

func extractScanID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Scan ID") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
