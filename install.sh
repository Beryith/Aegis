#!/bin/bash
set -e

echo "=== Installation d'AegiS ==="
echo ""

# Compilation du binaire
echo "→ Compilation..."
go build -o aegis ./cmd/aegis/

# Installation dans le PATH système
INSTALL_DIR="/usr/local/bin"

if [ ! -w "$INSTALL_DIR" ]; then
    echo "→ Installation dans $INSTALL_DIR (sudo requis)"
    sudo cp aegis "$INSTALL_DIR/aegis"
    sudo chmod +x "$INSTALL_DIR/aegis"
else
    cp aegis "$INSTALL_DIR/aegis"
    chmod +x "$INSTALL_DIR/aegis"
fi

echo ""
echo "✓ AegiS installé avec succès"
echo ""
echo "Vous pouvez maintenant utiliser la commande 'aegis' depuis n'importe quel dossier :"
echo "  aegis help"
echo "  aegis scan --target <cible>"
echo ""
