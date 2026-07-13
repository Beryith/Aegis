# Modèle de sécurité d'AegiS

## Périmètre d'autorisation

AegiS **ne vérifie pas** l'autorisation légale de scanner une cible.
Aucun outil ne peut le faire de façon fiable et automatique — c'est
un problème humain, pas technique.

La responsabilité de s'assurer d'avoir le droit de scanner une
infrastructure repose entièrement sur l'utilisateur d'AegiS.

Une commande `aegis scope` existe pour maintenir une liste de cibles
habituellement autorisées, mais elle n'est pas contraignante — elle
sert d'aide-mémoire, pas de garde-fou technique.

## Chiffrement des secrets

Les clés API des providers IA externes (Groq, OpenAI, Gemini,
Anthropic) sont chiffrées au repos avec AES-256-GCM.

- La clé de chiffrement est dérivée d'un mot de passe maître via
  PBKDF2 (100 000 itérations, SHA-256).
- Le mot de passe n'est jamais stocké, ni en clair ni hashé — seule
  une valeur de vérification chiffrée ("canari") permet de confirmer
  qu'un mot de passe saisi est correct, sans jamais le comparer
  directement.
- Une session en cache (`~/.aegis/.session`, permissions 600) évite
  de redemander le mot de passe pendant 15 minutes.

### Transmission aux conteneurs

Les conteneurs Docker (Discovery, Intelligence, Correlator, AI)
n'ont **jamais** accès au mot de passe maître ni aux clés chiffrées
stockées sur le disque hôte.

Au lancement d'un scan, la CLI déchiffre localement la clé du
provider actif et la transmet **une seule fois**, liée au `scan_id`,
via un message NATS dédié (`aegis.ai.credentials`). L'AI Layer la
garde en mémoire le temps du traitement, puis la purge — elle n'est
jamais écrite sur disque côté conteneur.

## Audit log

Toute action sensible est enregistrée dans la table `audit_log` :
- Lancement d'un scan
- Changement de provider IA
- Tentative de mot de passe incorrecte sur le vault
- Génération/révocation de clé API Gateway
- Échec d'authentification sur le Gateway
- Export de rapport

Cette table est **append-only au niveau base de données** — les
droits `UPDATE` et `DELETE` sont explicitement révoqués pour
l'utilisateur applicatif PostgreSQL, même un bug dans le code
Go/Python ne peut pas altérer ou supprimer une entrée existante.

```bash
aegis audit
aegis audit --type gateway_auth_failed --limit 50
```

## Authentification API Gateway

Le Gateway HTTP (`/api/v1/...`) exige une clé API sur chaque requête,
via le header `X-API-Key`. Seul `/health` reste accessible sans
authentification.

Les clés sont générées côté CLI, affichées **une seule fois** au
moment de leur création, puis stockées uniquement sous forme hashée
(SHA-256) en base — jamais en clair côté serveur.

```bash
aegis gateway generate-key --label "intégration CI/CD"
aegis gateway list-keys
aegis gateway revoke-key <id>
```

## Ce qui n'est pas encore couvert

- Chiffrement en transit entre les conteneurs (NATS et PostgreSQL
  tournent actuellement sans TLS sur le réseau Docker interne)
- Rotation automatique des clés API Gateway
- Rate limiting sur le Gateway
