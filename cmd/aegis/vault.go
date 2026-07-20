package main

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/aegis/pkg/crypto"
	"github.com/nats-io/nats.go"
	"golang.org/x/term"
)

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur de lecture du mot de passe :", err)
		os.Exit(1)
	}
	return string(bytePassword)
}

func promptConfirm(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')
	return line
}

// getMasterKey retourne la clé dérivée du mot de passe maître.
// Utilise le cache de session si valide (15 min), sinon demande le mot de passe.
const vaultCheckPlaintext = "aegis-vault-check-ok"

func getMasterKey() []byte {
	session := crypto.NewSessionCache()
	if key := session.Load(); key != nil {
		return key
	}

	config := loadAegisConfig()
	vault, hasVault := config["vault"].(map[string]interface{})

	if !hasVault {
		// Première utilisation — on définit le mot de passe maître
		fmt.Println("Aucun mot de passe maître configuré.")
		pw1 := promptPassword("Définissez un mot de passe pour chiffrer vos clés API : ")
		pw2 := promptPassword("Confirmez : ")
		if pw1 != pw2 {
			fmt.Println("✗ Les mots de passe ne correspondent pas.")
			os.Exit(1)
		}
		if pw1 == "" {
			fmt.Println("✗ Le mot de passe ne peut pas être vide.")
			os.Exit(1)
		}

		salt, err := crypto.GenerateSalt()
		if err != nil {
			fmt.Println("✗ Erreur génération du sel :", err)
			os.Exit(1)
		}

		key := crypto.DeriveKey(pw1, salt)
		check, err := crypto.Encrypt(key, vaultCheckPlaintext)
		if err != nil {
			fmt.Println("✗ Erreur d'initialisation du coffre :", err)
			os.Exit(1)
		}

		config["vault"] = map[string]interface{}{
			"salt":  base64Encode(salt),
			"check": check,
		}
		saveAegisConfig(config)

		session.Store(key)
		fmt.Println("✓ Mot de passe maître défini")
		return key
	}

	// Mot de passe déjà configuré — on le redemande, avec plusieurs tentatives
	saltB64, _ := vault["salt"].(string)
	salt := base64Decode(saltB64)
	checkValue, _ := vault["check"].(string)

	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pw := promptPassword("Mot de passe AegiS : ")
		key := crypto.DeriveKey(pw, salt)

		if checkValue != "" {
			if _, err := crypto.Decrypt(key, checkValue); err != nil {
				remaining := maxAttempts - attempt

				if db, dberr := sql.Open("postgres", dbURL); dberr == nil {
					writeAuditLog(db, "vault_auth_failed",
						fmt.Sprintf("Tentative de mot de passe incorrecte (%d/%d)", attempt, maxAttempts),
						map[string]interface{}{"attempt": attempt})
					db.Close()
				}

				if remaining > 0 {
					fmt.Printf("✗ Mot de passe incorrect (%d tentative(s) restante(s))\n", remaining)
					continue
				}
				fmt.Println("✗ Mot de passe incorrect. Abandon.")
				os.Exit(1)
			}
		}

		session.Store(key)
		return key
	}

	os.Exit(1)
	return nil
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func base64Decode(s string) []byte {
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data
	}
	// Compatibilité avec les vaults créés avant ce correctif, où le sel était
	// encodé via un détour par encoding/json (json.Marshal d'un []byte produit
	// aussi du base64, mais entouré de guillemets littéraux) au lieu de
	// encoding/base64 directement.
	var legacy []byte
	json.Unmarshal([]byte(s), &legacy)
	return legacy
}

// transmitProviderCredentials déchiffre localement la clé API du provider IA actif
// (si c'est un provider externe) et la transmet UNE FOIS à l'AI Layer via NATS,
// liée au scan_id. La clé n'est jamais écrite en clair sur disque côté conteneur.
func transmitProviderCredentials(nc *nats.Conn, scanID string) {
	config := loadAegisConfig()
	ai, ok := config["ai"].(map[string]interface{})
	if !ok {
		return
	}
	provider, ok := ai["provider"].(string)
	if !ok || provider == "ollama" {
		return // Ollama est local, aucun secret à transmettre
	}

	providers, ok := ai["providers"].(map[string]interface{})
	if !ok {
		return
	}
	p, ok := providers[provider].(map[string]interface{})
	if !ok {
		return
	}

	encryptedKey, _ := p["api_key"].(string)
	isEncrypted, _ := p["encrypted"].(bool)

	if encryptedKey == "" {
		return
	}

	var plainKey string
	if isEncrypted {
		masterKey := getMasterKey()
		decrypted, err := crypto.Decrypt(masterKey, encryptedKey)
		if err != nil {
			fmt.Println("✗ Erreur de déchiffrement de la clé API :", err)
			os.Exit(1)
		}
		plainKey = decrypted
	} else {
		// Ancienne clé non chiffrée (compatibilité transitoire)
		plainKey = encryptedKey
	}

	payload, _ := json.Marshal(map[string]string{
		"scan_id":  scanID,
		"provider": provider,
		"api_key":  plainKey,
	})

	nc.Publish("aegis.ai.credentials", payload)
}
