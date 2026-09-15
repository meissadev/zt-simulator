#!/bin/bash
# issue_cert.sh — Émet un certificat feuille signé par la CA du projet.
#
# Usage :
#   ./issue_cert.sh <composant> [algo] [pki_dir]
#
# Exemples :
#   ./issue_cert.sh idp                                    # RSA-3072, PKI classique
#   ./issue_cert.sh pep rsa:3072 ../../pki                 # explicite
#   ./issue_cert.sh idp CROSSrsdp128balanced ../../pki-pqc # PQC
#
# Le SAN est déduit automatiquement du nom du composant :
#   idp       -> DNS:idp.ztpqc.lab
#   pep       -> DNS:pep.ztpqc.lab
#   ressource -> DNS:ressource.ztpqc.lab
#   batch-service -> pas de SAN (client pur)
#
# Variables d'environnement optionnelles :
#   CERT_DAYS  : durée de validité (défaut : 825)
#   EXTRA_SAN  : SAN supplémentaire (ex. "IP:192.168.60.133")

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage : $0 <composant> [algo] [pki_dir]"
    echo "Exemple : $0 idp"
    exit 1
fi

COMPONENT_NAME="$1"
ALGO="${2:-rsa:3072}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${3:-${SCRIPT_DIR}/..}"
mkdir -p "${PKI_DIR}"
PKI_DIR="$(cd "${PKI_DIR}" && pwd)"
DAYS="${CERT_DAYS:-825}"

CA_KEY="${PKI_DIR}/ca/private/ca.key.pem"
CA_CERT="${PKI_DIR}/ca/certs/ca.cert.pem"

KEY_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.key"
CSR_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.csr"
CERT_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.crt"

# --- Détection classique vs PQC ---
IS_PQC=false
PROVIDER_ARGS=()
if [[ "${ALGO}" != rsa:* && "${ALGO}" != ec:* && "${ALGO}" != ecdsa* ]]; then
    IS_PQC=true
    PROVIDER_ARGS=(-provider oqsprovider -provider default)
fi

# --- Vérifications préalables ---
if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    echo "Erreur : CA introuvable dans ${PKI_DIR}/ca/"
    echo "  Exécutez d'abord : ./generate_ca.sh ${ALGO} ${PKI_DIR}"
    exit 1
fi

mkdir -p "${PKI_DIR}/certs"

# --- Construction du SAN ---
SERVER_COMPONENTS="idp pep ressource"
SAN=""
for srv in ${SERVER_COMPONENTS}; do
    if [[ "${COMPONENT_NAME}" == "${srv}" ]]; then
        SAN="DNS:${COMPONENT_NAME}.ztpqc.lab"
        break
    fi
done

if [[ -n "${EXTRA_SAN:-}" ]]; then
    if [[ -n "${SAN}" ]]; then
        SAN="${SAN},${EXTRA_SAN}"
    else
        SAN="${EXTRA_SAN}"
    fi
fi

# --- Fichier d'extensions temporaire ---
EXT_FILE="$(mktemp)"
trap 'rm -f "${EXT_FILE}"' EXIT

cat > "${EXT_FILE}" << EOF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
EOF

if [[ -n "${SAN}" ]]; then
    echo "subjectAltName=${SAN}" >> "${EXT_FILE}"
fi

# --- Étape 1 : génération de la clé ---
echo "Génération de la clé pour '${COMPONENT_NAME}' (algo: ${ALGO})..."

if [[ "${IS_PQC}" == "true" ]]; then
    openssl genpkey -algorithm "${ALGO}" \
        -out "${KEY_OUT}" \
        "${PROVIDER_ARGS[@]}"
elif [[ "${ALGO}" == rsa:* ]]; then
    KEY_SIZE="${ALGO#rsa:}"
    openssl genpkey -algorithm RSA \
        -pkeyopt "rsa_keygen_bits:${KEY_SIZE}" \
        -out "${KEY_OUT}"
else
    openssl genpkey -algorithm "${ALGO}" \
        -out "${KEY_OUT}"
fi

# --- Étape 2 : CSR ---
echo "Génération de la CSR..."

openssl req -new \
    -key "${KEY_OUT}" \
    -out "${CSR_OUT}" \
    -subj "/C=SN/O=PQC-ZeroTrust-Thesis/CN=${COMPONENT_NAME}.ztpqc.lab" \
    "${PROVIDER_ARGS[@]}"

# --- Étape 3 : signature par la CA ---
echo "Signature du certificat par la CA..."

openssl x509 -req \
    -in "${CSR_OUT}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -CAserial "${PKI_DIR}/ca/ca.srl" \
    -out "${CERT_OUT}" \
    -days "${DAYS}" \
    -extfile "${EXT_FILE}" \
    "${PROVIDER_ARGS[@]}"

echo ""
echo "=== Certificat émis pour '${COMPONENT_NAME}' ==="
echo "  Clé privée  : ${KEY_OUT}"
echo "  Certificat   : ${CERT_OUT}"
echo "  Algorithme   : ${ALGO}"
echo "  SAN          : ${SAN:-aucun (client pur)}"
echo ""

echo "=== Vérification de la chaîne de confiance ==="
openssl verify -CAfile "${CA_CERT}" "${PROVIDER_ARGS[@]}" "${CERT_OUT}"

echo ""
echo "=== Extensions du certificat ==="
openssl x509 -in "${CERT_OUT}" -noout \
    -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName \
    "${PROVIDER_ARGS[@]}"
