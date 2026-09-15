#!/bin/bash
# 00_check_algorithms.sh — Vérifie les algorithmes PQC disponibles sur cette machine.
# À exécuter avant toute génération de certificat pour confirmer la disponibilité.

set -euo pipefail

echo "=============================================="
echo " Vérification des algorithmes disponibles"
echo "=============================================="
echo ""

echo "--- OpenSSL version ---"
openssl version
echo ""

echo "--- KEM (oqs-provider) ---"
openssl list -kem-algorithms -provider oqsprovider -provider default 2>&1 \
    | grep -iE "hqc|bike|frodo|kem" || echo "(aucun KEM PQC trouvé)"
echo ""

echo "--- Signatures (oqs-provider) ---"
openssl list -signature-algorithms -provider oqsprovider -provider default 2>&1 \
    | grep -iE "cross|falcon|mayo|mldsa|dilithium" || echo "(aucune signature PQC trouvée)"
echo ""

VENV_ACTIVATE="${1:-$(dirname "${BASH_SOURCE[0]}")/../../venv/bin/activate}"
if [[ -f "${VENV_ACTIVATE}" ]]; then
    echo "--- liboqs-python (via venv) ---"
    source "${VENV_ACTIVATE}"
    python3 << 'PYEOF'
import oqs
kems = oqs.get_enabled_kem_mechanisms()
sigs = oqs.get_enabled_sig_mechanisms()
print("KEM (%d disponibles):" % len(kems))
for k in kems:
    if any(x in k.lower() for x in ["hqc", "bike", "kem"]):
        print("  %s" % k)
print()
print("Signatures (%d disponibles):" % len(sigs))
for s in sigs:
    if any(x in s.lower() for x in ["cross", "falcon", "mayo", "ml-dsa"]):
        print("  %s" % s)
PYEOF
else
    echo "(venv introuvable à ${VENV_ACTIVATE}, skip liboqs-python)"
fi

echo ""
echo "=============================================="
echo " Récapitulatif des noms pour ce projet"
echo "=============================================="
echo "  OpenSSL KEM TLS group : hqc1"
echo "  OpenSSL sig algorithm : CROSSrsdp128balanced"
echo "  liboqs-python KEM     : HQC-1"
echo "  liboqs-python sig     : cross-rsdp-128-balanced"
echo "=============================================="
