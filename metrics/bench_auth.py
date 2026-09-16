"""
bench_auth.py -- mesure du temps d'authentification (chaîne IdP -> PEP).

Mesure strictement, en millisecondes :

    T_auth = t_fin_auth - t_debut_auth

où t_debut_auth = instant juste avant le début de la procédure
d'authentification et t_fin_auth = instant juste après sa fin.
Chronomètre monotone haute résolution : time.perf_counter().

Périmètre mesuré (authentification complète, SANS autorisation ni accès) :
  1. t_debut_auth juste avant l'envoi de POST /authenticate à l'IdP --
     vérification des identifiants + émission du JWS (échange HTTP + opération
     cryptographique de signature, exécutés par l'IdP du simulateur) ;
  2. validation du token obtenu EXACTEMENT comme le fait le PEP dans
     authenticate_request() (branche JWT, pep/app.py) : décode header/payload,
     contrôle alg/issuer, récupération de la clé publique via /jwks (échange
     HTTP avec l'IdP) puis vérification cryptographique de la signature --
     via les modules existants du simulateur pep/jwt_signer.py et
     pep/jwks_client.py (aucune logique réécrite) ;
  3. t_fin_auth juste après la fin de la vérification de signature.

Le PDP (autorisation, étape 2 du PEP) et la Ressource (flux d'accès, étape 3)
sont volontairement HORS du chronométrage : ce sont des étapes
d'autorisation/d'accès, pas d'authentification.

Indépendant de l'algorithme : le même code mesure la phase classique
(RSA-3072) et la phase PQC (CROSS/HQC) sans modification -- l'algorithme
attendu est injecté via --expected-alg (équivalent de EXPECTED_JWT_ALG,
tel que configuré pour le PEP).

Aucun service ni aucune logique existante n'est modifié : ce script est un
client de mesure qui réutilise les fonctions d'authentification existantes.
À chaque itération, une authentification INDEPENDANTE est mesurée : le cache
JWKS du PEP est vidé (chaque échange nécessaire est inclus) et chaque appel
HTTP ouvre une nouvelle connexion HTTPS (pas de réutilisation de connexion,
ni Keep-Alive, ni resumption).

Usage (phase classique) :
    venv/bin/python metrics/bench_auth.py --n 50

Usage (phase PQC) :
    venv/bin/python metrics/bench_auth.py --n 50 \
        --ca-cert pki-pqc/ca/certs/ca.cert.pem \
        --expected-alg cross-rsdp-128-balanced
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
PEP_DIR = BASE_DIR / "pep"
sys.path.insert(0, str(PEP_DIR))

import config  # pep/config.py -- configuration du PEP (reused telle quelle)
import jwt_signer  # pep/jwt_signer.py -- fonctions JWS du simulateur
import jwks_client  # pep/jwks_client.py -- récupération de la clé publique


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure du temps d'authentification (chaîne IdP -> PEP), en millisecondes"
    )
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (endpoints /authenticate et /jwks)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la vérification TLS")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'authentifications indépendantes (N)")
    parser.add_argument("--expected-alg", default=None,
                        help="algorithme attendu côté PEP (ex. RSA3072-PSS-SHA384 ou "
                             "cross-rsdp-128-balanced) ; défaut : EXPECTED_JWT_ALG "
                             "du config PEP")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def idp_authenticate(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    """
    Première moitié de l'authentification : réutilise l'endpoint existant
    POST /authenticate de l'IdP (vérification des identifiants + émission du
    JWS). Retourne l'access_token.
    """
    response = requests.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def pep_validate_token(token: str) -> dict:
    """
    Seconde moitié de l'authentification : reproduit le chemin EXACT de
    authenticate_request() du PEP, branche JWT (pep/app.py) -- seule la
    lecture de l'en-tête HTTP, propre à Flask, est remplacée par l'argument
    `token`. Aucune logique cryptographique n'est réécrite.
    """
    decoded = jwt_signer.decode_unverified(token)
    issuer = decoded.payload.get("iss")
    kid = decoded.header.get("kid")
    alg = decoded.header.get("alg")

    if alg != config.EXPECTED_JWT_ALG:
        raise ValueError(f"Algorithme non autorisé : {alg!r} (attendu {config.EXPECTED_JWT_ALG!r})")
    if issuer not in config.TRUSTED_ISSUERS:
        raise ValueError(f"Issuer non approuvé : {issuer!r} (trusted: {config.TRUSTED_ISSUERS})")

    public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
    if jwks_alg != alg:
        raise ValueError(f"Incohérence d'algorithme entre le token ({alg!r}) et le JWKS ({jwks_alg!r})")

    return jwt_signer.verify_jwt(token, public_key, alg)


def summarize(samples_ms: list) -> dict:
    return {
        "metric": "temps_authentification",
        "unit": "ms",
        "n": len(samples_ms),
        "mean": round(statistics.mean(samples_ms), 3),
        "median": round(statistics.median(samples_ms), 3),
        "stdev": round(statistics.stdev(samples_ms), 3) if len(samples_ms) > 1 else 0.0,
        "min": round(min(samples_ms), 3),
        "max": round(max(samples_ms), 3),
    }


def run(args: argparse.Namespace) -> dict:
    # Aligne la configuration du PEP sur l'IdP réelle et l'algorithme visé,
    # sans toucher au code de vérification lui-même.
    if args.idp_url:
        jwks_url = args.idp_url.rstrip("/") + "/jwks"
        config.ISSUER_JWKS_ENDPOINTS = {iss: jwks_url for iss in config.ISSUER_JWKS_ENDPOINTS}
        config.TRUSTED_ISSUERS = list(config.ISSUER_JWKS_ENDPOINTS.keys())
    if args.expected_alg:
        config.EXPECTED_JWT_ALG = args.expected_alg
    if args.ca_cert:
        config.CA_CERT = args.ca_cert

    samples_ms = []
    for i in range(1, args.n + 1):
        # Chaque itération = une authentification indépendante : cache JWKS
        # vidé (tous les échanges nécessaires à l'authentification sont
        # mesurés), et nouvelle connexion HTTPS pour chaque appel HTTP.
        jwks_client._cache.clear()

        t_debut_auth = time.perf_counter()

        token = idp_authenticate(
            args.idp_url, args.ca_cert, args.username, args.password, args.timeout
        )
        pep_validate_token(token)

        t_fin_auth = time.perf_counter()

        temps_auth_ms = (t_fin_auth - t_debut_auth) * 1000
        samples_ms.append(temps_auth_ms)
        print(f"[{i}/{args.n}] T_auth = {temps_auth_ms:.3f} ms", file=sys.stderr)

    return summarize(samples_ms)


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit être >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))