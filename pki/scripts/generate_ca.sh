#!/bin/bash
# generate_ca.sh — Génère une autorité de certification (CA) racine.
#
# Usage :
#   ./generate_ca.sh                                       # RSA-3072 dans ../
#   ./generate_ca.sh CROSSrsdp128balanced ../../pki-pqc    # PQC
#
# Le premier argument est l'algorithme (défaut : rsa:3072).
# Le second est le répertoire PKI cible (défaut : pki/).

set -euo pipefail

ALGO="${1:-rsa:3072}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${2:-${SCRIPT_DIR}/..}"
mkdir -p "${PKI_DIR}"
PKI_DIR="$(cd "${PKI_DIR}" && pwd)"
DAYS="${CA_DAYS:-3650}"

CA_DIR="${PKI_DIR}/ca"
CA_KEY="${CA_DIR}/private/ca.key.pem"
CA_CERT="${CA_DIR}/certs/ca.cert.pem"

# --- Détection classique vs PQC ---
IS_PQC=false
PROVIDER_ARGS=()
if [[ "${ALGO}" != rsa:* && "${ALGO}" != ec:* && "${ALGO}" != ecdsa* ]]; then
    IS_PQC=true
    PROVIDER_ARGS=(-provider oqsprovider -provider default)
fi

# --- Garde : ne pas écraser une CA existante ---
if [[ -f "${CA_KEY}" || -f "${CA_CERT}" ]]; then
    echo "ATTENTION : une CA existe déjà dans ${CA_DIR}/"
    echo "  Clé  : ${CA_KEY}"
    echo "  Cert : ${CA_CERT}"
    read -p "Écraser ? (oui/non) " CONFIRM
    if [[ "${CONFIRM}" != "oui" ]]; then
        echo "Abandon."
        exit 0
    fi
fi

# --- Création de l'arborescence ---
mkdir -p "${CA_DIR}"/{certs,crl,csr,newcerts,private}
chmod 700 "${CA_DIR}/private"
touch "${CA_DIR}/index.txt"
echo "1000" > "${CA_DIR}/serial"
echo "1000" > "${CA_DIR}/crlnumber"

# --- Fichier de config temporaire avec extensions v3_ca ---
TMPCONF="$(mktemp)"
trap 'rm -f "${TMPCONF}"' EXIT

cat > "${TMPCONF}" << CNFEOF
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
C  = SN
ST = Dakar
L  = Dakar
O  = PQC-ZeroTrust-Thesis
OU = Root CA
CN = ca.ztpqc.lab

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
CNFEOF

echo "Génération de la CA (algorithme : ${ALGO})..."

# --- Étape 1 : génération de la clé ---
if [[ "${IS_PQC}" == "true" ]]; then
    openssl genpkey -algorithm "${ALGO}" \
        -out "${CA_KEY}" \
        "${PROVIDER_ARGS[@]}"
elif [[ "${ALGO}" == rsa:* ]]; then
    KEY_SIZE="${ALGO#rsa:}"
    openssl genpkey -algorithm RSA \
        -pkeyopt "rsa_keygen_bits:${KEY_SIZE}" \
        -out "${CA_KEY}"
else
    openssl genpkey -algorithm "${ALGO}" \
        -out "${CA_KEY}"
fi
chmod 400 "${CA_KEY}"

# --- Étape 2 : certificat auto-signé ---
openssl req -new -x509 \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -days "${DAYS}" \
    -config "${TMPCONF}" \
    -extensions v3_ca \
    "${PROVIDER_ARGS[@]}"
chmod 444 "${CA_CERT}"

echo ""
echo "=== CA générée avec succès ==="
echo "  Clé privée  : ${CA_KEY}"
echo "  Certificat   : ${CA_CERT}"
echo "  Algorithme   : ${ALGO}"
echo ""

echo "=== Vérification du certificat CA ==="
openssl x509 -in "${CA_CERT}" -noout -subject -issuer -dates \
    -ext basicConstraints,keyUsage \
    "${PROVIDER_ARGS[@]}"
