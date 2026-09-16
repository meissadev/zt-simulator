"""
bench_throughput.py -- mesure du DEBIT (3e metrique experimentale).

    D = N / T_total            (requetes par seconde)

avec :

    N       = nombre total de requetes executees
    T_total = duree totale entre le debut de la premiere requete et la fin
              de la derniere requete, mesuree avec time.perf_counter()

Deux debits mesures, avec EXACTEMENT le meme chemin d'execution que les
benchmarks precedents :

1. Debit d'authentification -- meme processus que bench_auth.py, pour
   chaque requete : POST /authenticate vers l'IdP (verification des
   identifiants + emission du JWS) puis validation du token par le code du
   PEP (recuperation de la cle via /jwks + verification de la signature),
   cache JWKS vide a chaque iteration.

2. Debit d'acces -- meme processus que bench_access.py (Client -> PEP ->
   PDP -> Ressource -> Client) : GET /api/data via le PEP avec un JWT
   obtenu au prealable (hors chronometrage), pour chaque requete.

Conditions strictes, identiques pour RSA et PQC :
- requetes SEQUENTIELLES (aucune concurrence) ;
- nouvelle connexion HTTPS a chaque requete (pas de Keep-Alive, pas de
  resumption, pas de session requests reutilisee) ;
- aucune optimisation ajoutee ;
- aucun composant (IdP, PEP, PDP, Ressource, PKI) modifie.

Gestion des erreurs : une requete echouee est signalee clairement, n'est
PAS comptee comme requete traitee correctement, et est comptabilisee dans
failed_requests. Le debit est calcule strictement selon D = N / T_total,
N etant le nombre de requetes executees (tentees).

Usage (phase PQC) :
    OPENSSL_CONF=ressource/openssl_pqc.cnf \
        python3 metrics/bench_throughput.py --n 50 \
            --ca-cert pki-pqc/ca/certs/ca.cert.pem \
            --expected-alg cross-rsdp-128-balanced

Usage (phase classique) :
    python3 metrics/bench_throughput.py --n 50 \
        --ca-cert pki/ca/certs/ca.cert.pem \
        --expected-alg RSA3072-PSS-SHA384
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
PEP_DIR = BASE_DIR / "pep"
sys.path.insert(0, str(PEP_DIR))

import config  # pep/config.py -- configuration du PEP (reused telle quelle)
import jwt_signer  # pep/jwt_signer.py -- fonctions JWS du simulateur
import jwks_client  # pep/jwks_client.py -- recuperation de la cle publique


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure du debit (req/s) : authentification et acces, D = N / T_total"
    )
    parser.add_argument("--n", type=int, default=50,
                        help="nombre de requetes executees (N)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la verification TLS")
    parser.add_argument("--expected-alg", default=None,
                        help="algorithme attendu cote PEP (ex. RSA3072-PSS-SHA384 ou "
                             "cross-rsdp-128-balanced) ; defaut : EXPECTED_JWT_ALG du config PEP")
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (endpoints /authenticate et /jwks)")
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces)")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


# --- Chemin d'execution IDENTIQUE a bench_auth.py ---------------------------

def idp_authenticate(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    """
    Premiere moitie de l'authentification : reutilise l'endpoint existant
    POST /authenticate de l'IdP (verification des identifiants + emission du
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
    Seconde moitie de l'authentification : reproduit le chemin EXACT de
    authenticate_request() du PEP, branche JWT (pep/app.py) -- seule la
    lecture de l'en-tete HTTP, propre a Flask, est remplacee par l'argument
    `token`. Aucune logique cryptographique n'est reecrite.
    """
    decoded = jwt_signer.decode_unverified(token)
    issuer = decoded.payload.get("iss")
    kid = decoded.header.get("kid")
    alg = decoded.header.get("alg")

    if alg != config.EXPECTED_JWT_ALG:
        raise ValueError(f"Algorithme non autorise : {alg!r} (attendu {config.EXPECTED_JWT_ALG!r})")
    if issuer not in config.TRUSTED_ISSUERS:
        raise ValueError(f"Issuer non approuve : {issuer!r} (trusted: {config.TRUSTED_ISSUERS})")

    public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
    if jwks_alg != alg:
        raise ValueError(f"Incoherence d'algorithme entre le token ({alg!r}) et le JWKS ({jwks_alg!r})")

    return jwt_signer.verify_jwt(token, public_key, alg)


# --- Chemin d'execution IDENTIQUE a bench_access.py -------------------------

def get_access_token(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    """
    Obtient un JWT via POST /authenticate (phase d'authentification INITIALE) :
    volontairement HORS du chronometrage de debit d'acces.
    """
    response = requests.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def access_request(pep_url: str, token: str, ca_cert: str, timeout: float) -> None:
    """Un acces bout en bout : GET /api/data via le PEP (Client -> PEP -> PDP -> Ressource)."""
    response = requests.get(
        pep_url.rstrip("/") + "/api/data",
        headers={"Authorization": f"Bearer {token}"},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()


# --- Mesures ----------------------------------------------------------------

def measure_auth_throughput(args: argparse.Namespace) -> dict:
    """
    Debit d'authentification : N authentifications successives (meme chemin
    que bench_auth.py), T_total = perf_counter(start -> end).
    """
    successful = 0
    failed = 0

    start = time.perf_counter()
    for i in range(1, args.n + 1):
        # Chaque iteration = une authentification independante : cache JWKS
        # vide (tous les echanges necessaires sont inclus), nouvelle
        # connexion HTTPS (pas de reutilisation de connexion).
        jwks_client._cache.clear()
        try:
            token = idp_authenticate(args.idp_url, args.ca_cert, args.username, args.password, args.timeout)
            pep_validate_token(token)
            successful += 1
        except Exception as exc:
            failed += 1
            print(f"[!] authentification {i}/{args.n} ECHOUEE : {exc}", file=sys.stderr)
    end = time.perf_counter()

    total_time_s = end - start
    return {
        "throughput": round(args.n / total_time_s, 3),
        "total_time_s": round(total_time_s, 6),
        "successful_requests": successful,
        "failed_requests": failed,
    }


def measure_access_throughput(args: argparse.Namespace, token: str) -> dict:
    """
    Debit d'acces : N demandes d'acces successives via le PEP (meme chemin
    que bench_access.py), T_total = perf_counter(start -> end). Le token est
    obtenu au prealable, hors chronometrage.
    """
    successful = 0
    failed = 0

    start = time.perf_counter()
    for i in range(1, args.n + 1):
        try:
            access_request(args.pep_url, token, args.ca_cert, args.timeout)
            successful += 1
        except Exception as exc:
            failed += 1
            print(f"[!] acces {i}/{args.n} ECHOUEE : {exc}", file=sys.stderr)
    end = time.perf_counter()

    total_time_s = end - start
    return {
        "throughput": round(args.n / total_time_s, 3),
        "total_time_s": round(total_time_s, 6),
        "successful_requests": successful,
        "failed_requests": failed,
    }


def run(args: argparse.Namespace) -> dict:
    # Aligne la configuration du PEP sur l'IdP reelle, l'algorithme vise et la
    # CA, sans toucher au code de verification lui-meme.
    if args.idp_url:
        jwks_url = args.idp_url.rstrip("/") + "/jwks"
        config.ISSUER_JWKS_ENDPOINTS = {iss: jwks_url for iss in config.ISSUER_JWKS_ENDPOINTS}
        config.TRUSTED_ISSUERS = list(config.ISSUER_JWKS_ENDPOINTS.keys())
    if args.expected_alg:
        config.EXPECTED_JWT_ALG = args.expected_alg
    if args.ca_cert:
        config.CA_CERT = args.ca_cert

    if args.n < 1:
        raise ValueError("--n doit etre >= 1")

    auth = measure_auth_throughput(args)

    # Phase d'authentification initiale (non mesuree) pour obtenir le JWT du
    # debit d'acces -- meme approche que bench_access.py.
    token = get_access_token(args.idp_url, args.ca_cert, args.username, args.password, args.timeout)
    access = measure_access_throughput(args, token)

    return {
        "metric": "debit",
        "unit": "req/s",
        "n": args.n,
        "authentication": auth,
        "access": access,
    }


if __name__ == "__main__":
    args = parse_args()
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))