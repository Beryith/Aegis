package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/aegis/pkg/crypto"
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

		config["vault"] = map[string]interface{}{
			"salt": base64Encode(salt),
		}
		saveAegisConfig(config)

		key := crypto.DeriveKey(pw1, salt)
		session.Store(key)
		fmt.Println("✓ Mot de passe maître défini")
		return key
	}

	// Mot de passe déjà configuré — on le redemande
	saltB64, _ := vault["salt"].(string)
	salt := base64Decode(saltB64)

	pw := promptPassword("Mot de passe AegiS : ")
	key := crypto.DeriveKey(pw, salt)
	session.Store(key)
	return key
}

func base64Encode(data []byte) string {
	b, _ := json.Marshal(data)
	return string(b)
}

func base64Decode(s string) []byte {
	var data []byte
	json.Unmarshal([]byte(s), &data)
	return data
}
