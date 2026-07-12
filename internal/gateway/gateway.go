package gateway

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Gateway struct {
	router *gin.Engine
}

func New() *Gateway {
	router := gin.Default()

	g := &Gateway{router: router}
	g.registerRoutes()

	return g
}

func (g *Gateway) registerRoutes() {
	// Health check
	g.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "aegis-gateway",
		})
	})

	// API v1
	v1 := g.router.Group("/api/v1")
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
