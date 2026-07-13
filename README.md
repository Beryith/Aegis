# AegiS

**Moteur d'analyse et d'orchestration de sécurité assisté par intelligence artificielle.**

AegiS n'est pas un scanner de plus. C'est une couche de raisonnement qui orchestre des services spécialisés (Nmap, bases CVE, exploit-db) pour répondre à une question que les scanners classiques ne posent jamais :

> **Que signifie réellement ce que j'ai trouvé, et que dois-je faire ?**

---

## Ce qu'AegiS n'est pas

- Un scanner de vulnérabilités de plus
- Un framework de pentest
- Un SIEM ou un EDR

AegiS orchestre ces catégories d'outils, il ne les remplace pas.

---

## Fonctionnalités

- **Pipeline automatisé** — Discovery → Intelligence → Corrélation → Recommandations IA, déclenché en une commande
- **Matching CVE précis** — identification par CPE, pas par mot-clé approximatif
- **Détection d'exploits publics** — croisement avec une base exploit-db locale (27 000+ entrées)
- **IA multi-provider** — Ollama en local par défaut, Groq/OpenAI/Gemini/Anthropic en option
- **Recommandations ciblées** — une recommandation par groupe de risque, pas un résumé générique
- **Sécurité intégrée** — clés API chiffrées, audit log, authentification API Gateway
- **Rapports exportables** — JSON, Markdown, PDF

---

## Installation

### Prérequis

- Go 1.24+
- Docker (ou Podman) + Docker Compose
- Python 3.13+ (pour les services d'intelligence)

### Démarrage avec Docker Compose (recommandé)

```bash
git clone <repo>
cd aegis
cd deployments
docker compose up -d
```

### Installation de la CLI en local

```bash
cd aegis
./install.sh
```

Une fois installé, la commande `aegis` est disponible depuis n'importe quel dossier.

---

## Démarrage rapide

```bash
# Lancer un premier scan
aegis scan --target scanme.nmap.org

# Voir les scans passés
aegis results

# Revoir un rapport
aegis report --last

# Exporter en PDF
aegis report --last --export pdf
```

> `scanme.nmap.org` est une cible publique mise à disposition par les créateurs de Nmap pour les tests. **Ne scannez jamais une infrastructure sans autorisation légale.**

---

## Commandes disponibles

```bash
aegis help
```

Affiche la liste complète des commandes avec leurs options.

---

## Configuration de l'IA

Par défaut, AegiS utilise **Ollama en local** — aucune donnée ne quitte votre machine.

```bash
aegis ai status
```

Pour utiliser un provider externe (plus rapide, données envoyées à un tiers) :

```bash
aegis ai config groq --key <votre_clé>
aegis ai use groq
```

---

## Architecture

---

## Sécurité

- Les clés API sont chiffrées au repos (AES-256-GCM) et protégées par un mot de passe maître
- Toute action sensible est tracée dans un journal d'audit append-only (`aegis audit`)
- L'API Gateway nécessite une clé d'authentification (`aegis gateway generate-key`)

**Responsabilité légale** : AegiS ne vérifie pas l'autorisation légale de scanner une cible. C'est à l'utilisateur de s'assurer d'avoir le droit de le faire.

---

## Licence

À définir.
