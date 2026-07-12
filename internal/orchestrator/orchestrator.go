package orchestrator

import (
	"database/sql"
	"log"

	"github.com/nats-io/nats.go"
	_ "github.com/lib/pq"
)

type Orchestrator struct {
	db   *sql.DB
	nats *nats.Conn
}

func New(dbURL string, natsURL string) (*Orchestrator, error) {
	// Connexion PostgreSQL
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	log.Println("[orchestrator] PostgreSQL connecté")

	// Connexion NATS
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}
	log.Println("[orchestrator] NATS connecté")

	return &Orchestrator{
		db:   db,
		nats: nc,
	}, nil
}

func (o *Orchestrator) Start() {
	log.Println("[orchestrator] Démarré — en attente d'instructions")
	select {}
}

func (o *Orchestrator) Stop() {
	o.db.Close()
	o.nats.Close()
	log.Println("[orchestrator] Arrêté")
}
