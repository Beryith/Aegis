package export

import (
	"database/sql"

	"github.com/mandolyte/mdtopdf"
)

func ExportPDF(db *sql.DB, scanID string, outputPath string) error {
	report, err := BuildScanReport(db, scanID)
	if err != nil {
		return err
	}

	markdown := BuildMarkdown(report)

	pf := mdtopdf.NewPdfRenderer("", "", outputPath, "", nil, mdtopdf.LIGHT)
	pf.Pdf.SetTitle("Rapport de scan AegiS", true)
	pf.Pdf.SetAuthor("AegiS", true)

	return pf.Process([]byte(markdown))
}
