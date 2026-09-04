#!/bin/bash
# issue_cert.sh
# Émet un certificat pour un composant donné (idp, pep, ressource...),
# signé par la CA racine.
#
# Réutilisable pour les deux phases :
#   - Phase classique (par défaut) : RSA-3072.
#   - Phase PQC : ./issue_cert.sh <nom> cross128small [SAN]
#
# Usage : ./issue_cert.sh <nom_composant> [algo] [SAN]
# Exemples :
#   ./issue_cert.sh idp
#   ./issue_cert.sh pep rsa:3072 "DNS:pep.local,IP:127.0.0.1"
#   ./issue_cert.sh ressource cross128small

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage : $0 <nom_composant> [algo] [SAN]"
    echo "Exemple : $0 idp"
    exit 1
fi

# --- Configuration -------------------------------------------------------
COMPONENT_NAME="$1"
ALGO="${2:-${CERT_ALGO:-rsa:3072}}"
SAN="${3:-}"
DAYS="${CERT_DAYS:-825}"

PKI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/pki" && pwd)"
CA_KEY="${PKI_DIR}/intermediate/private/intermediate.key.pem"
CA_CERT="${PKI_DIR}/intermediate/certs/intermediate.cert.pem"

KEY_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.key"
CSR_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.csr"
CERT_OUT="${PKI_DIR}/certs/${COMPONENT_NAME}.crt"

# --- Détection classique vs PQC -----------------------------------------
# PROVIDER_ARGS=()
# if [[ "${ALGO}" != rsa:* && "${ALGO}" != ec:* && "${ALGO}" != ecdsa* ]]; then
#     PROVIDER_ARGS=(-provider oqsprovider -provider default)
# fi

# --- Vérifications préalables ---------------------------------------------
if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    echo "Erreur : CA introuvable dans ${PKI_DIR}/intermediate/"
    exit 1
fi

mkdir -p "${PKI_DIR}/certs"

# --- Génération de la clé + CSR du composant -------------------------------
echo "Génération de la clé et de la CSR pour '${COMPONENT_NAME}' (algorithme : ${ALGO})..."

openssl req -new \
    -newkey "${ALGO}" \
    -keyout "${KEY_OUT}" \
    -out "${CSR_OUT}" \
    -nodes \
    -subj "/C=SN/O=PQC-ZeroTrust-Thesis/CN=${COMPONENT_NAME}.ztpqc.lab"
# "${PROVIDER_ARGS[@]}"/
if [[ -n "${SAN}" ]]; then
    EXT_FILE="$(mktemp)"
    printf "subjectAltName=%s\n" "${SAN}" > "${EXT_FILE}"
    EXT_ARGS=(-extfile "${EXT_FILE}")
fi

# --- Signature par la CA ----------------------------------------------------
echo "Signature du certificat par la CA..."

openssl x509 -req \
    -in "${CSR_OUT}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -CAserial "${PKI_DIR}/intermediate/intermediate.srl" \
    -out "${CERT_OUT}" \
    -days "${DAYS}" \
    "${EXT_ARGS[@]}" \
    # "${PROVIDER_ARGS[@]}"

[[ -n "${EXT_FILE}" ]] && rm -f "${EXT_FILE}"

echo ""
echo "=== Certificat émis avec succès pour '${COMPONENT_NAME}' ==="
echo "Clé privée : ${KEY_OUT}"
echo "Certificat : ${CERT_OUT}"
echo ""
echo "=== Vérification de la chaîne de confiance ==="
# openssl verify -CAfile "${CA_CERT}" "${PROVIDER_ARGS[@]}" "${CERT_OUT}"
openssl verify -CAfile "${CA_CERT}" "${CERT_OUT}"