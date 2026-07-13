package gateway

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type Gateway struct {
	router *gin.Engine
	db     *sql.DB
}

func New(dbURL string) (*Gateway, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	router := gin.Default()

	g := &Gateway{router: router, db: db}
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
	// Health check — accessible sans authentification
	g.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "aegis-gateway",
		})
	})

	// API v1 — protégée par clé API
	v1 := g.router.Group("/api/v1")
	v1.Use(g.authMiddleware())
	{
		v1.POST("/scan", g.handleCreateScan)
		v1.GET("/scan", g.handleListScans)
	}
}

func (g *Gateway) handleCreateScan(c *gin.Context) {
	c.JSON(http.StatusAccepted, gin.H{
		"message": "scan reçu — en cours de traitement",
	})
}

func (g *Gateway) handleListScans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"scans": []interface{}{},
	})
}

func (g *Gateway) Start(addr string) error {
	return g.router.Run(addr)
}
