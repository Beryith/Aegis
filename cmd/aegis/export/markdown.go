package export

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

var severityLabels = map[string]string{
	"critical": "🔴 CRITIQUE",
	"high":     "🟠 ÉLEVÉ",
	"medium":   "🟡 MOYEN",
	"low":      "🟢 FAIBLE",
	"info":     "⚪ INFO",
}

var priorityLabels = map[string]string{
	"immediate":   "🚨 IMMÉDIAT",
	"short_term":  "⚡ COURT TERME",
	"medium_term": "📅 MOYEN TERME",
	"long_term":   "🔭 LONG TERME",
}

func BuildMarkdown(report *ScanReport) string {
	var b strings.Builder

	b.WriteString("# Rapport de scan AegiS\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID :** `%s`\n\n", report.ScanID))
	b.WriteString(fmt.Sprintf("**Cible :** %s\n\n", report.Target))
	b.WriteString(fmt.Sprintf("**Profil :** %s\n\n", report.Profile))
	b.WriteString(fmt.Sprintf("**Statut :** %s\n\n", report.Status))
	b.WriteString(fmt.Sprintf("**Date :** %s\n\n", report.CreatedAt.Format("2006-01-02 15:04:05")))
	b.WriteString("---\n\n")

	b.WriteString("## Résultats détaillés\n\n")

	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severityOrder {
		var group []FindingExport
		for _, f := range report.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("### %s (%d)\n\n", severityLabels[sev], len(group)))
		for _, f := range group {
			b.WriteString(fmt.Sprintf("- **%s**\n", f.Title))
			b.WriteString(fmt.Sprintf("  - Asset : %s\n", f.Asset))
			b.WriteString(fmt.Sprintf("  - Source : %s\n", f.Source))
			if f.Description != "" {
				desc := f.Description
				if len(desc) > 200 {
					desc = desc[:200] + "..."
				}
				b.WriteString(fmt.Sprintf("  - Détail : %s\n", desc))
			}
			b.WriteString("\n")
		}
	}

	if len(report.Recommendations) > 0 {
		b.WriteString("---\n\n")
		b.WriteString("## Recommandations IA\n\n")
		for _, r := range report.Recommendations {
			label := priorityLabels[r.Priority]
			if label == "" {
				label = r.Priority
			}
			b.WriteString(fmt.Sprintf("### %s — %s\n\n", label, r.Title))
			if r.Context != "" {
				b.WriteString(fmt.Sprintf("**Contexte :** %s\n\n", r.Context))
			}
			if r.Action != "" {
				b.WriteString(fmt.Sprintf("**Action :** %s\n\n", r.Action))
			}
			if r.Impact != "" {
				b.WriteString(fmt.Sprintf("**Impact :** %s\n\n", r.Impact))
			}
			if r.Effort != "" {
				b.WriteString(fmt.Sprintf("**Effort :** %s\n\n", r.Effort))
			}
			b.WriteString(fmt.Sprintf("*Généré le %s*\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05")))
			b.WriteString("---\n\n")
		}
	}

	b.WriteString(fmt.Sprintf("\n*Rapport généré par AegiS le %s*\n", report.CreatedAt.Format("2006-01-02 15:04:05")))

	return b.String()
}

func ExportMarkdown(db *sql.DB, scanID string, outputPath string) error {
	report, err := BuildScanReport(db, scanID)
	if err != nil {
		return err
	}

	markdown := BuildMarkdown(report)
	return os.WriteFile(outputPath, []byte(markdown), 0644)
}
