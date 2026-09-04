"""
config.py -- configuration centralisée de l'IdP.

CRYPTO_MODE bascule entre la baseline classique (RSA-3072) et le backend
post-quantique, sans toucher à app.py ni jwt_signer.py -- utile pour lancer
les deux phases de ton comparatif avec le même code applicatif.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.environ.get("PKI_DIR", os.path.join(BASE_DIR, "..", "pki"))

# --- TLS (transport du service IdP lui-même) -----------------------------
IDP_TLS_CERT = os.environ.get("IDP_TLS_CERT", os.path.join(PKI_DIR, "certs", "idp.crt"))
IDP_TLS_KEY = os.environ.get("IDP_TLS_KEY", os.path.join(PKI_DIR, "certs", "idp.key"))
CA_CERT = os.environ.get("CA_CERT", os.path.join(PKI_DIR, "ca", "ca.crt"))

HOST = os.environ.get("IDP_HOST", "0.0.0.0")
PORT = int(os.environ.get("IDP_PORT", "8444"))

# --- JWT --------------------------------------------------------------------
# Doit correspondre au CN/SAN du certificat TLS de l'IdP, pour que "iss"
# et l'identité TLS pointent vers la même entité.
ISSUER = os.environ.get("JWT_ISSUER", "https://idp.ztpqc.lab")
SIGNING_KID = os.environ.get("JWT_KID", "idp-key-1")
TOKEN_TTL_SECONDS = int(os.environ.get("JWT_TTL", "300"))

# --- Sélection du backend cryptographique -----------------------------------
# "classical" : RSA-3072 (baseline pour le comparatif)
# "pqc"       : signature post-quantique (PQC_SIG_ALG, ex. Dilithium3)
CRYPTO_MODE = os.environ.get("CRYPTO_MODE", "classical")
RSA_KEY_SIZE = int(os.environ.get("RSA_KEY_SIZE", "3072"))
PQC_SIG_ALG = os.environ.get("PQC_SIG_ALG", "Dilithium3")