# Architecture d'AegiS

## Vue d'ensemble

AegiS suit une architecture orientée services, coordonnée par messages asynchrones via NATS JetStream.
## Le pipeline

Un scan traverse quatre étapes, chaînées automatiquement via NATS :

1. **Discovery** (`services/discovery/main.py`)
   Lance Nmap sur la cible, extrait les ports ouverts et versions de services.
   Publie vers `aegis.intelligence.enrich` pour chaque service détecté.

2. **Intelligence** (`services/intelligence/main.py`)
   Pour chaque service : construit un identifiant CPE, interroge le NVD,
   croise avec la base exploit-db locale. Utilise un compteur
   `pending_enrichments` sur le scan pour savoir quand tous les
   enrichissements sont terminés avant de déclencher la corrélation.

3. **Corrélation** (`services/intelligence/correlator.py`)
   Applique des règles de corrélation (service vulnérable exposé,
   service d'administration exposé, surface d'attaque élargie),
   groupées par service pour éviter les doublons.

4. **AI Layer** (`services/ai/main.py`)
   Génère une recommandation par groupe de corrélation (pas une
   recommandation globale). Supporte plusieurs providers IA
   interchangeables (Ollama, Groq, Gemini, OpenAI, Anthropic).

## Pourquoi NATS plutôt que HTTP direct entre services

Le découplage par messages permet à chaque service de démarrer
indépendamment, de retenter automatiquement en cas d'échec temporaire
(voir `services/utils.py::connect_with_retry`), et de scaler
horizontalement si besoin (plusieurs instances d'un même service
peuvent consommer la même queue).

## Pourquoi PostgreSQL et pas un fichier plat

L'état du système (scans, findings, recommandations, clés API,
audit log) doit être interrogeable, filtrable, et durable. PostgreSQL
avec JSONB pour les champs semi-structurés (scope, metadata) donne
la flexibilité d'un document store tout en gardant les garanties
transactionnelles d'un SGBD relationnel.

## Le modèle de données canonique

Défini dans `shared/schemas/` (JSON Schema), utilisé comme référence
commune entre les composants Go et Python :

- `asset.json` — ce qu'on protège (hôte, domaine, réseau, URL)
- `finding.json` — une observation faite sur un asset
- `scan.json` — une exécution du pipeline sur une cible
- `recommendation.json` — une action concrète générée par l'IA

## Pourquoi le matching CVE par CPE et pas par mot-clé

Une recherche par mot-clé sur "ssh 6.6.1p1 Ubuntu 2ubuntu2.13" auprès
de l'API NVD retourne quasi systématiquement zéro résultat — l'API
cherche dans les descriptions, pas dans les métadonnées de version.

Le format CPE (`cpe:2.3:a:openbsd:openssh:6.6.1`) permet une
correspondance exacte. `services/cpe_mapper.py` extrait la version
numérique et devine le couple vendor/product à partir du nom de
service Nmap, avec un fallback sur la recherche par mot-clé si le
mapping échoue.

## Pourquoi une recommandation IA par corrélation

Un scan avec 25 findings couvrant plusieurs services (SSH, Apache)
noyé dans une seule recommandation générique perd toute sa valeur
actionnable. L'AI Layer génère plutôt une recommandation ciblée par
groupe de corrélation identifié par le Correlation Engine, avec
uniquement les findings pertinents à ce groupe dans le prompt.
