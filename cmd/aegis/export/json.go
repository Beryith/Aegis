package export

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ScanReport struct {
	ScanID          string                   `json:"scan_id"`
	Target          string                   `json:"target"`
	Profile         string                   `json:"profile"`
	Status          string                   `json:"status"`
	CreatedAt       time.Time                `json:"created_at"`
	Findings        []FindingExport          `json:"findings"`
	Recommendations []RecommendationExport   `json:"recommendations"`
}

type FindingExport struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
	Asset       string `json:"asset"`
}

type RecommendationExport struct {
	Title       string    `json:"title"`
	Priority    string    `json:"priority"`
	Context     string    `json:"context"`
	Action      string    `json:"action"`
	Impact      string    `json:"impact"`
	Effort      string    `json:"effort"`
	GeneratedAt time.Time `json:"generated_at"`
}

func BuildScanReport(db *sql.DB, scanID string) (*ScanReport, error) {
	report := &ScanReport{ScanID: scanID}

	var scope string
	err := db.QueryRow(`
		SELECT status, profile, created_at, scope->>'targets' FROM scans WHERE id = $1
	`, scanID).Scan(&report.Status, &report.Profile, &report.CreatedAt, &scope)
	if err != nil {
		return nil, fmt.Errorf("scan introuvable : %w", err)
	}
	var targets []string
	if err := json.Unmarshal([]byte(scope), &targets); err == nil && len(targets) > 0 {
		report.Target = targets[0]
	} else {
		report.Target = scope
	}

	rows, err := db.Query(`
		SELECT f.title, f.severity, f.source, f.description, a.value
		FROM findings f
		JOIN assets a ON f.asset_id = a.id
		WHERE f.scan_id = $1
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var f FindingExport
		rows.Scan(&f.Title, &f.Severity, &f.Source, &f.Description, &f.Asset)
		report.Findings = append(report.Findings, f)
	}

	recRows, err := db.Query(`
		SELECT title, priority, recommendation, generated_at
		FROM recommendations
		WHERE scan_id = $1
		ORDER BY generated_at DESC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer recRows.Close()

	for recRows.Next() {
		var title, priority, recJSON string
		var generatedAt time.Time
		recRows.Scan(&title, &priority, &recJSON, &generatedAt)

		var recData map[string]string
		json.Unmarshal([]byte(recJSON), &recData)

		report.Recommendations = append(report.Recommendations, RecommendationExport{
			Title:       title,
			Priority:    priority,
			Context:     recData["context"],
			Action:      recData["action"],
			Impact:      recData["impact"],
			Effort:      recData["effort"],
			GeneratedAt: generatedAt,
		})
	}

	return report, nil
}

func ExportJSON(db *sql.DB, scanID string, outputPath string) error {
	report, err := BuildScanReport(db, scanID)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
