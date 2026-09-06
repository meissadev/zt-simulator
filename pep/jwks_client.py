"""
jwks_client.py -- récupération et mise en cache des clés publiques de
vérification exposées par l'IdP (endpoint /jwks).

Sécurité : l'issuer ("iss") extrait du token est vérifié contre une liste
blanche AVANT toute résolution réseau -- sans ça, un attaquant pourrait
fournir un "iss" arbitraire et forcer le PEP à effectuer une requête vers
une URL de son choix (SSRF).

Performance : mise en cache en mémoire avec TTL, pour éviter un aller-retour
réseau vers l'IdP à chaque requête -- pertinent pour ta mesure de latence
(H2) : sans cache, chaque requête utilisateur paierait le coût d'un appel
HTTP supplémentaire en plus de la vérification de signature elle-même.
"""

import time

import requests

import config
import jwt_signer


class UntrustedIssuerError(Exception):
    pass


class JWKSFetchError(Exception):
    pass


_cache: dict = {}  # iss -> {"keys": {kid: {"alg":..., "pub": bytes}}, "fetched_at": float}


def get_verification_key(issuer: str, kid: str) -> tuple[bytes, str]:
    """
    Retourne (clé_publique_bytes, alg) pour le (issuer, kid) donné.
    Lève UntrustedIssuerError si l'issuer n'est pas dans TRUSTED_ISSUERS.
    """
    if issuer not in config.TRUSTED_ISSUERS:
        raise UntrustedIssuerError(f"Issuer non approuvé : {issuer!r}")

    cached = _cache.get(issuer)
    now = time.time()

    if cached is None or (now - cached["fetched_at"]) > config.JWKS_CACHE_TTL:
        cached = _fetch_jwks(issuer)
        _cache[issuer] = cached

    key_entry = cached["keys"].get(kid)
    if key_entry is None:
        # kid absent du cache -- peut indiquer une rotation de clé côté IdP :
        # un seul rafraîchissement forcé avant d'abandonner.
        cached = _fetch_jwks(issuer)
        _cache[issuer] = cached
        key_entry = cached["keys"].get(kid)
        if key_entry is None:
            raise JWKSFetchError(f"kid {kid!r} introuvable pour l'issuer {issuer!r}")

    return key_entry["pub"], key_entry["alg"]


def _fetch_jwks(issuer: str) -> dict:
    # "issuer" est une identité de confiance, PAS une adresse réseau -- on
    # résout l'URL réelle via un mapping explicite, jamais en dérivant
    # l'adresse depuis la valeur de "iss" elle-même (cf. config.py).
    url = config.ISSUER_JWKS_ENDPOINTS[issuer]
    try:
        response = requests.get(url, verify=config.CA_CERT, timeout=config.JWKS_FETCH_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise JWKSFetchError(f"Échec de récupération JWKS depuis {url} : {exc}") from exc

    data = response.json()
    keys = {}
    for entry in data.get("keys", []):
        keys[entry["kid"]] = {
            "alg": entry["alg"],
            "pub": jwt_signer.b64url_decode(entry["pub"]),
        }
    return {"keys": keys, "fetched_at": time.time()}