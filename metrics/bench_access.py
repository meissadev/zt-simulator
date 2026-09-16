"""
bench_access.py -- mesure de la latence d'acces bout en bout.

Chaîne Zero Trust mesurée, du client a la ressource puis retour au client :

    Client -> PEP -> PDP -> Ressource -> Client

Mesure strictement, en millisecondes :

    L = t_fin_acces - t_debut_acces

avec

* t_debut_acces : instant juste avant l'envoi de la requete d'acces au PEP
  (GET /api/data avec l'en-tete Authorization: Bearer <JWT>) ;
* t_fin_acces   : instant ou la reponse FINALE de la ressource est recue par
  le client, c'est-a-dire l'arrivee de la reponse HTTP complete relayee par
  le PEP apres l'appel PDP et le relais mTLS vers la Ressource.

Contenu chronometre : envoi de la requete, traitement PEP (y compris la
validation du JWT realisee dans le traitement de la requete d'acces), appel
du PDP pour la decision d'autorisation, relais mTLS vers la Ressource,
traitement de la Ressource, et retour de la reponse au client.

EXCLU de la mesure (phase d'authentification initiale) :
le token JWT est obtenu au prealable via POST /authenticate, HORS
chronometrage. Chaque iteration mesure UN acces independant : nouvelle
connexion HTTPS (pas de session requests, donc pas de Keep-Alive ni de
reutilisation de connexion).

Chronometre monotone haute resolution : time.perf_counter().

Independant de l'algorithme : le meme code mesure la phase classique
(RSA) et la phase PQC (CROSS/HQC) -- la diversite se situe dans le
deploiement (IdP/PEP/PDP/Ressource), pas dans la methode de mesure.

Usage (classique) :
    python3 metrics/bench_access.py --n 50

Usage (PQC, ne pas oublier OPENSSL_CONF pour offrir hqc1) :
    OPENSSL_CONF=ressource/openssl_pqc.cnf \
        python3 metrics/bench_access.py --n 50 \
            --ca-cert pki-pqc/ca/certs/ca.cert.pem
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure de la latence d'acces bout en bout (Client -> PEP -> PDP -> Ressource), en millisecondes"
    )
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces)")
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444",
                        help="URL de l'IdP (endpoint /authenticate pour obtenir le JWT, HORS chronometrage)")
    parser.add_argument("--ca-cert", default=str(BASE_DIR / "pki" / "ca" / "certs" / "ca.cert.pem"),
                        help="certificat de la CA pour la verification TLS")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'acces independants (N)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def get_access_token(idp_url: str, ca_cert: str, username: str, password: str,
                     timeout: float) -> str:
    """
    Obtient un JWT via POST /authenticate (phase d'authentification INITIALE) :
    volontairement HORS du chronometrage de latence d'acces.
    """
    response = requests.post(
        idp_url.rstrip("/") + "/authenticate",
        json={"username": username, "password": password},
        verify=ca_cert,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def measure_latency(pep_url: str, token: str, ca_cert: str, n: int, timeout: float) -> list:
    """
    Chronometre N acces bout en bout (GET /api/data via le PEP, Bearer JWT).
    Retourne la liste des L_i en millisecondes.
    """
    url = pep_url.rstrip("/") + "/api/data"
    headers = {"Authorization": f"Bearer {token}"}
    samples_ms = []

    for i in range(1, n + 1):
        t_debut_acces = time.perf_counter()

        response = requests.get(url, headers=headers, verify=ca_cert, timeout=timeout)

        t_fin_acces = time.perf_counter()

        response.raise_for_status()

        latence_ms = (t_fin_acces - t_debut_acces) * 1000
        samples_ms.append(latence_ms)
        print(f"[{i}/{n}] L = {latence_ms:.3f} ms", file=sys.stderr)

    return samples_ms


def summarize(samples_ms: list) -> dict:
    return {
        "metric": "latence_acces_bout_en_bout",
        "unit": "ms",
        "n": len(samples_ms),
        "mean": round(statistics.mean(samples_ms), 3),
        "median": round(statistics.median(samples_ms), 3),
        "stdev": round(statistics.stdev(samples_ms), 3) if len(samples_ms) > 1 else 0.0,
        "min": round(min(samples_ms), 3),
        "max": round(max(samples_ms), 3),
    }


def run(args: argparse.Namespace) -> dict:
    # Phase d'authentification initiale (non mesurée) : on récupère un JWT.
    token = get_access_token(args.idp_url, args.ca_cert, args.username, args.password, args.timeout)

    samples_ms = measure_latency(args.pep_url, token, args.ca_cert, args.n, args.timeout)
    return summarize(samples_ms)


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit être >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))