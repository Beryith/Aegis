package gateway

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
)

type Gateway struct {
	router *gin.Engine
	db     *sql.DB
	nc     *nats.Conn
}

func New(dbURL string, natsURL string) (*Gateway, error) {
	// Mode "release" par défaut (logs de debug désactivés, moins verbeux) —
	// surchageable en dev via GIN_MODE=debug.
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	router := gin.Default()

	g := &Gateway{router: router, db: db, nc: nc}
	g.registerRoutes()

	return g, nil
}

func (g *Gateway) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")

		if apiKey == "" {
			g.logAuditFailure("Requête sans clé API")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "clé API requise (header X-API-Key)"})
			c.Abort()
			return
		}

		hash := sha256.Sum256([]byte(apiKey))
		hashHex := hex.EncodeToString(hash[:])

		var keyID string
		var active bool
		err := g.db.QueryRow(`
			SELECT id, active FROM api_keys WHERE key_hash = $1
		`, hashHex).Scan(&keyID, &active)

		if err != nil || !active {
			g.logAuditFailure("Clé API invalide ou révoquée")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "clé API invalide ou révoquée"})
			c.Abort()
			return
		}

		g.db.Exec(`UPDATE api_keys SET last_used_at = $1 WHERE id = $2`, time.Now(), keyID)
		c.Next()
	}
}

func (g *Gateway) logAuditFailure(description string) {
	g.db.Exec(`
		INSERT INTO audit_log (event_type, description, metadata)
		VALUES ($1, $2, '{}')
	`, "gateway_auth_failed", description)
}

func (g *Gateway) registerRoutes() {
	g.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "aegis-gateway",
		})
	})

	v1 := g.router.Group("/api/v1")
	v1.Use(g.authMiddleware())
	{
		v1.POST("/scan", g.handleCreateScan)
		v1.GET("/scan", g.handleListScans)
		v1.GET("/scan/:id", g.handleGetScan)
	}
}

type createScanRequest struct {
	Target string `json:"target" binding:"required"`
}

func (g *Gateway) handleCreateScan(c *gin.Context) {
	var req createScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "champ 'target' requis"})
		return
	}

	scanID := uuid.New().String()

	scope, _ := json.Marshal(map[string]interface{}{
		"targets":       []string{req.Target},
		"excluded":      []string{},
		"authorized_by": "api-gateway",
	})

	_, err := g.db.Exec(`
		INSERT INTO scans (id, status, profile, scope, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, scanID, "running", "active", string(scope), time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "erreur création scan"})
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"scan_id": scanID,
		"target":  req.Target,
	})
	if err := g.nc.Publish("aegis.discovery.scan", payload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "erreur publication scan"})
		return
	}

	g.db.Exec(`
		INSERT INTO audit_log (event_type, description, metadata)
		VALUES ($1, $2, $3)
	`, "scan_launched", "Scan lancé via API Gateway sur '"+req.Target+"'", "{}")

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"target":  req.Target,
		"status":  "running",
		"message": "scan lancé — pipeline en cours d'exécution",
	})
}

func (g *Gateway) handleListScans(c *gin.Context) {
	rows, err := g.db.Query(`
		SELECT s.id, s.status, s.profile, s.created_at,
		       COUNT(f.id) as total,
		       s.scope->>'targets' as targets
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		GROUP BY s.id
		ORDER BY s.created_at DESC
		LIMIT 20
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "erreur requête"})
		return
	}
	defer rows.Close()

	scans := []gin.H{}
	for rows.Next() {
		var id, status, profile, targets string
		var createdAt time.Time
		var total int
		rows.Scan(&id, &status, &profile, &createdAt, &total, &targets)

		scans = append(scans, gin.H{
			"scan_id":    id,
			"status":     status,
			"profile":    profile,
			"created_at": createdAt,
			"findings":   total,
			"targets":    targets,
		})
	}

	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

func (g *Gateway) handleGetScan(c *gin.Context) {
	scanID := c.Param("id")

	var status, profile string
	var createdAt time.Time
	err := g.db.QueryRow(`
		SELECT status, profile, created_at FROM scans WHERE id = $1
	`, scanID).Scan(&status, &profile, &createdAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan introuvable"})
		return
	}

	rows, err := g.db.Query(`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "erreur requête findings"})
		return
	}
	defer rows.Close()

	findings := []gin.H{}
	for rows.Next() {
		var title, severity, source, description, asset string
		rows.Scan(&title, &severity, &source, &description, &asset)
		findings = append(findings, gin.H{
			"title":       title,
			"severity":    severity,
			"source":      source,
			"description": description,
			"asset":       asset,
		})
	}

	recRows, err := g.db.Query(`
		SELECT title, priority, recommendation, generated_at
		FROM recommendations
		WHERE scan_id = $1
		ORDER BY generated_at DESC
	`, scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "erreur requête recommandations"})
		return
	}
	defer recRows.Close()

	recommendations := []gin.H{}
	for recRows.Next() {
		var title, priority, recJSON string
		var generatedAt time.Time
		recRows.Scan(&title, &priority, &recJSON, &generatedAt)

		var recData map[string]string
		json.Unmarshal([]byte(recJSON), &recData)

		recommendations = append(recommendations, gin.H{
			"title":        title,
			"priority":     priority,
			"context":      recData["context"],
			"action":       recData["action"],
			"impact":       recData["impact"],
			"effort":       recData["effort"],
			"generated_at": generatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":         scanID,
		"status":          status,
		"profile":         profile,
		"created_at":      createdAt,
		"findings":        findings,
		"recommendations": recommendations,
	})
}

func (g *Gateway) Start(addr string) error {
	return g.router.Run(addr)
}
