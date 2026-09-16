"""
bench_s2s_throughput.py -- mesure du debit service -> service (S2S).

Chaine Zero Trust mesuree (une demande d'acces S2S complete par iteration) :

    Service A -> PEP -> PDP -> Service B (Ressource) -> Service A

OBJECTIF :
Compter combien de demandes d'acces Service -> Service peuvent etre
traitees par seconde.

DEFINITION :

    D_S2S = successful_requests / T_total

avec
* successful_requests : nombre de demandes d'acces S2S terminees avec
  succes (une demande echouee n'est JAMAIS comptee comme reussie) ;
* T_total : temps ecoule entre le debut de la premiere demande et la fin
  de la derniere demande (time.perf_counter(), chronometre monotone haute
  resolution -- PAS time.time()).

METHODE (explicitement lineaire et sequentielle) :
  requete 1 -> reponse
  requete 2 -> reponse
  ...
  requete N -> reponse
Aucun thread, aucun multiprocessing, aucun asyncio, aucune concurrence :
chaque demande ne part que lorsque la reponse de la precedente est recue.

Le debit est calcule directement par la formule D = success / T_total,
et NON par 1 / latence_moyenne.

POUR LE PORTEE MESUREE :
Il s'agit du DEBIT D'ACCES S2S. Comme dans bench_s2s_latency.py, les
services s'authentifient par mTLS a chaque nouvelle connexion HTTPS
(connexion fraiche par iteration, pas de Session requests, pas de
Keep-Alive, pas de resumption) : l'authentification S2S est donc
effectuee conformement au fonctionnement normal de l'implementation, a
l'interieur de chaque demande d'acces mesuree -- elle n'est ni
artificiellement ajoutee, ni prefetchee.

CHEMIN REEL REUTILISE (identique a bench_s2s_latency.py) :
  Service A = identite certificat client du simulateur (batch-service,
  cf. README) -> PEP (branche mTLS d'authenticate_request) -> PDP (OPA)
  -> Service B (Ressource /api/data, relais mTLS) -> reponse -> Service A.

Independant de l'algorithme : le meme code mesure la phase classique
(RSA/ECDH) et la phase PQC (CROSS/HQC). Le groupe TLS est pilote par
/usr/local/ssl/openssl.cnf.

Usage (classique) :
    venv/bin/python metrics/bench_s2s_throughput.py --mode classical --n 50

Usage (PQC) :
    venv/bin/python metrics/bench_s2s_throughput.py --mode pqc --n 50
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent

_PKI_BY_MODE = {
    "classical": "pki",
    "pqc": "pki-pqc",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure du debit service -> service (Service A -> PEP -> "
                    "PDP -> Service B), en requetes/seconde"
    )
    parser.add_argument(
        "--mode", choices=["classical", "pqc"], required=True,
        help="configuration cryptographique mesuree (classical : RSA/ECDH ; "
             "pqc : CROSS/HQC-1)"
    )
    parser.add_argument("--n", type=int, default=50,
                        help="nombre de demandes d'acces S2S (N)")
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443",
                        help="URL du PEP (endpoint d'acces S2S)")
    parser.add_argument("--ca-cert", default=None,
                        help="certificat de la CA (defaut : pki[-pqc]/ca/certs/"
                             "ca.cert.pem selon --mode)")
    parser.add_argument("--client-cert", default=None,
                        help="certificat client de Service A (defaut : "
                             "pki[-pqc]/certs/batch-service.crt selon --mode)")
    parser.add_argument("--client-key", default=None,
                        help="cle privee correspondante (defaut : "
                             "pki[-pqc]/certs/batch-service.key selon --mode)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout HTTP (secondes)")
    return parser.parse_args()


def _resolve_paths(args: argparse.Namespace) -> dict:
    pki_dir = BASE_DIR / _PKI_BY_MODE[args.mode]
    return {
        "ca_cert": Path(args.ca_cert or pki_dir / "ca" / "certs" / "ca.cert.pem"),
        "client_cert": Path(args.client_cert or pki_dir / "certs" / "batch-service.crt"),
        "client_key": Path(args.client_key or pki_dir / "certs" / "batch-service.key"),
    }


def run(args: argparse.Namespace) -> dict:
    paths = _resolve_paths(args)
    for label, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(f"{label} introuvable : {path}")

    url = args.pep_url.rstrip("/") + "/api/data"

    successful = 0
    failed = 0

    # Chronometre monotone haute resolution : debut de la premiere demande
    # jusqu'a la fin de la derniere demande.
    t_debut = time.perf_counter()
    for i in range(1, args.n + 1):
        try:
            # Connexion HTTPS fraiche a chaque iteration (pas de Session,
            # donc pas de Keep-Alive) : handshake mTLS naturel, comme dans
            # le fonctionnement reel de l'architecture.
            response = requests.get(
                url,
                cert=(str(paths["client_cert"]), str(paths["client_key"])),
                verify=str(paths["ca_cert"]),
                timeout=args.timeout,
            )
            response.raise_for_status()
            successful += 1
        except requests.RequestException as exc:
            failed += 1
            print(f"[{i}/{args.n}] ECHEC : {exc}", file=sys.stderr)
    t_fin = time.perf_counter()

    total_time_s = t_fin - t_debut
    throughput = successful / total_time_s if total_time_s > 0 else 0.0

    if failed > 0:
        print(f"AVERTISSEMENT : {failed} iteration(s) en echec sur {args.n}",
              file=sys.stderr)

    return {
        "metric": "debit_service_service",
        "unit": "req/s",
        "n": args.n,
        "throughput": round(throughput, 3),
        "total_time_s": round(total_time_s, 6),
        "successful_requests": successful,
        "failed_requests": failed,
    }


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))