"""
config.py -- configuration centralisée du PEP.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.environ.get("PKI_DIR", os.path.join(BASE_DIR, "..", "pki"))

# --- TLS du PEP lui-même (écoute entrante) --------------------------------
PEP_TLS_CERT = os.environ.get("PEP_TLS_CERT", os.path.join(PKI_DIR, "certs", "pep.crt"))
PEP_TLS_KEY = os.environ.get("PEP_TLS_KEY", os.path.join(PKI_DIR, "certs", "pep.key"))
CA_CERT = os.environ.get("CA_CERT", os.path.join(PKI_DIR, "ca", "certs", "ca.cert.pem"))

HOST = os.environ.get("PEP_HOST", "0.0.0.0")
PORT = int(os.environ.get("PEP_PORT", "8443"))

# --- IdP (vérification JWT) -------------------------------------------------
JWKS_CACHE_TTL = int(os.environ.get("JWKS_CACHE_TTL", "300"))
JWKS_FETCH_TIMEOUT = float(os.environ.get("JWKS_FETCH_TIMEOUT", "2.0"))

# Mapping "iss" (identité logique, valeur portée par le token) -> URL
# RÉELLEMENT joignable pour récupérer /jwks.
#
# Volontairement découplé : "iss" ne doit jamais être utilisé pour dériver
# une adresse réseau (ni littéralement, ni via une convention type
# "iss + /.well-known/..."), car (a) ça ouvrirait un risque de SSRF si un
# jour "iss" provenait d'une source moins fiable, et (b) l'identité logique
# de l'IdP (le nom qui doit correspondre à son certificat) n'a pas de raison
# de coïncider avec l'adresse réseau utilisée en environnement de test
# (localhost multi-port sur un même hôte, alors qu'en production ce serait
# un nom DNS interne différent encore).
ISSUER_JWKS_ENDPOINTS = {
    "https://idp.ztpqc.lab": os.environ.get("IDP_JWKS_URL", "https://idp.ztpqc.lab:8444/jwks"),
}

TRUSTED_ISSUERS = list(ISSUER_JWKS_ENDPOINTS.keys())

# Algorithme attendu, fixé côté PEP (pas déduit aveuglément du token) --
# évite une attaque par confusion d'algorithme.
EXPECTED_JWT_ALG = os.environ.get("EXPECTED_JWT_ALG", "RSA3072-PSS-SHA384")

# --- PDP (OPA) ---------------------------------------------------------------
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181/v1/data/authz/allow")
OPA_TIMEOUT_SECONDS = float(os.environ.get("OPA_TIMEOUT_SECONDS", "2.0"))

# --- Ressource (backend protégé, appelé en mTLS par le PEP) -----------------
RESOURCE_BASE_URL = os.environ.get("RESOURCE_BASE_URL", "https://ressource.ztpqc.lab:8446")
RESOURCE_TIMEOUT_SECONDS = float(os.environ.get("RESOURCE_TIMEOUT_SECONDS", "5.0"))