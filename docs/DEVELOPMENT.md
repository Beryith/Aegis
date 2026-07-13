# Guide de développement

## Structure du dépôt

- `cmd/aegis/` — CLI principale (Go)
- `cmd/gateway/` — point d'entrée du Gateway HTTP
- `cmd/aegis/export/` — génération de rapports JSON/Markdown/PDF
- `internal/gateway/` — logique du Gateway (routes, authentification)
- `internal/orchestrator/` — squelette de l'orchestrateur central
- `pkg/crypto/` — chiffrement des secrets, cache de session
- `services/discovery/` — scan Nmap (Python)
- `services/intelligence/` — enrichissement CVE, exploit-db, corrélation (Python)
- `services/ai/` — génération de recommandations (Python)
- `shared/schemas/` — modèles de données canoniques (JSON Schema)
- `deployments/` — Dockerfiles, docker-compose.yml, init SQL

## Lancer en local sans Docker

Nécessite NATS, PostgreSQL et Ollama installés localement.

```bash
# Terminal 1 — NATS
nats-server -c deployments/nats.conf

# Terminal 2 — Discovery
source services/discovery/venv/bin/activate
python3 services/discovery/main.py

# Terminal 3 — Intelligence
source services/intelligence/venv/bin/activate
python3 services/intelligence/main.py

# Terminal 4 — Correlator
source services/intelligence/venv/bin/activate
python3 services/intelligence/correlator.py

# Terminal 5 — AI Layer
source services/ai/venv/bin/activate
python3 services/ai/main.py

# Terminal 6 — CLI
go build -o aegis ./cmd/aegis/
./aegis scan --target scanme.nmap.org
```

## Lancer avec Docker Compose (recommandé)

```bash
cd deployments
docker compose up -d
docker compose logs -f
```

## Rebuild un service après modification

```bash
cd deployments
docker compose build <nom_du_service>
docker compose up -d --force-recreate <nom_du_service>
```

## Base de données

```bash
psql -U aegis -d aegis -h 127.0.0.1
```

Mot de passe : `aegis` (développement uniquement, à changer en
production).

Le schéma initial est dans `deployments/init.sql`. Les migrations
ultérieures (`pending_enrichments`, `audit_log`, `api_keys`,
`exploit_db`) ont été appliquées manuellement pendant le
développement — un vrai système de migrations versionnées
(ex: `golang-migrate`) serait nécessaire avant une mise en
production.

## Tests

Aucun test automatisé n'existe encore. C'est identifié comme
manquant pour la Phase 6 (MVP).

## Conventions de commit

Le projet suit approximativement les Conventional Commits :
`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`.
