"""
config.py -- configuration centralisée du PEP.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.environ.get("PKI_DIR", os.path.join(BASE_DIR, "..", "pki"))

# --- TLS du PEP lui-même (écoute entrante) --------------------------------
PEP_TLS_CERT = os.environ.get("PEP_TLS_CERT", os.path.join(PKI_DIR, "certs", "pep.crt"))
PEP_TLS_KEY = os.environ.get("PEP_TLS_KEY", os.path.join(PKI_DIR, "certs", "pep.key"))
CA_CERT = os.environ.get("CA_CERT", os.path.join(PKI_DIR, "ca", "ca.crt"))

HOST = os.environ.get("PEP_HOST", "0.0.0.0")
PORT = int(os.environ.get("PEP_PORT", "8443"))

# --- IdP (vérification JWT) -------------------------------------------------
JWKS_PATH = os.environ.get("JWKS_PATH", "/jwks")
JWKS_CACHE_TTL = int(os.environ.get("JWKS_CACHE_TTL", "300"))
JWKS_FETCH_TIMEOUT = float(os.environ.get("JWKS_FETCH_TIMEOUT", "2.0"))

# Liste blanche des issuers de confiance -- vérifiée AVANT tout appel réseau
# vers l'URL "iss" fournie par le token (mitigation SSRF).
TRUSTED_ISSUERS = [
    v.strip() for v in os.environ.get("TRUSTED_ISSUERS", "https://idp.ztpqc.lab").split(",")
]

# Algorithme attendu, fixé côté PEP (pas déduit aveuglément du token) --
# évite une attaque par confusion d'algorithme.
EXPECTED_JWT_ALG = os.environ.get("EXPECTED_JWT_ALG", "RSA3072-PSS-SHA384")

# --- PDP (OPA) ---------------------------------------------------------------
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181/v1/data/authz/allow")
OPA_TIMEOUT_SECONDS = float(os.environ.get("OPA_TIMEOUT_SECONDS", "2.0"))

# --- Ressource (backend protégé, appelé en mTLS par le PEP) -----------------
RESOURCE_BASE_URL = os.environ.get("RESOURCE_BASE_URL", "https://localhost:8446")
RESOURCE_TIMEOUT_SECONDS = float(os.environ.get("RESOURCE_TIMEOUT_SECONDS", "5.0"))