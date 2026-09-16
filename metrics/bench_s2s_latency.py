"""
bench_s2s_latency.py -- mesure de la latence d'acces bout-en-bout SERVICE -> SERVICE.

Chaine Zero Trust mesuree, de Service A a la Ressource puis retour a Service A :

    Service A -> PEP -> PDP -> Service B (Ressource) -> Service A

Mesure strictement, en millisecondes :

    L_S2S = t_fin_acces - t_debut_acces

avec

* t_debut_acces : instant juste avant l'envoi de la demande d'acces de
  Service A au PEP (GET /api/data, avec certificat client presente en mTLS) ;
* t_fin_acces   : instant ou Service A recoit la reponse finale de
  Service B relayee par le PEP (apres validation mTLS, appel PDP et relais
  mTLS vers la Ressource).

Contenu chronometre : envoi de la requete, authentification mTLS de
Service A (validee par le PEP dans le traitement de la requete -- branche
SSL_CLIENT_CN d'authenticate_request), appel du PDP pour la decision
d'autorisation, relais mTLS vers Service B, traitement de Service B, et
retour de la reponse a Service A.

Chemin reel reutilise (aucun chemin artificiel) :
  Service A = identite certificate client du simulateur (batch-service,
  cf. README, flux S2S) -> PEP (pep/...) -> PDP (OPA) -> Service B
  (Ressource, /api/data, mTLS CERT_REQUIRED).

AUTHENTIFICATION DANS LA MESURE (documentation exigee par le cadrage) :
L'architecture n'a PAS de jeton S2S prefetche : Service A s'authentifie
au PEP par mTLS a CHAQUE nouvelle connexion HTTPS (connexion fraiche par
iteration -- pas de Session requests, pas de Keep-Alive, pas de
resumption). Cette authentification est donc naturellement incluse dans
chaque L_S2S mesuree, exactement comme l'architecture s'execute en
production. Aucune authentification n'est artificiellement ajoutee.

EXCLU de la mesure : rien d'autre que la demande d'acces elle-meme. Le
debit et les tailles cryptographiques font l'objet d'autres benchmarks.

Chronometre monotone haute resolution : time.perf_counter().

Independant de l'algorithme : le meme code mesure la phase classique
(RSA/ECDH) et la phase PQC (CROSS/HQC) -- la diversite se situe dans le
deploiement (certs basses couches, openssl.cnf systeme), pas dans la
methode. Le groupe TLS est pilote par /usr/local/ssl/openssl.cnf.

Usage (classique) :
    venv/bin/python metrics/bench_s2s_latency.py --mode classical --n 50

Usage (PQC) :
    venv/bin/python metrics/bench_s2s_latency.py --mode pqc --n 50
"""

import argparse
import json
import statistics
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
        description="Mesure de la latence d'acces bout-en-bout service -> service "
                    "(Service A -> PEP -> PDP -> Service B), en millisecondes"
    )
    parser.add_argument(
        "--mode", choices=["classical", "pqc"], required=True,
        help="configuration cryptographique mesuree (classical : RSA/ECDH ; "
             "pqc : CROSS/HQC-1)"
    )
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'acces S2S independants (N)")
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


def summarize(samples_ms: list, successful: int, failed: int) -> dict:
    return {
        "metric": "latence_acces_service_service",
        "unit": "ms",
        "n": len(samples_ms),
        "mean": round(statistics.mean(samples_ms), 3),
        "median": round(statistics.median(samples_ms), 3),
        "stdev": round(statistics.stdev(samples_ms), 3) if len(samples_ms) > 1 else 0.0,
        "min": round(min(samples_ms), 3),
        "max": round(max(samples_ms), 3),
        "successful_requests": successful,
        "failed_requests": failed,
    }


def run(args: argparse.Namespace) -> dict:
    paths = _resolve_paths(args)
    for label, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(f"{label} introuvable : {path}")

    url = args.pep_url.rstrip("/") + "/api/data"
    samples_ms = []
    successful = 0
    failed = 0

    for i in range(1, args.n + 1):
        t_debut_acces = time.perf_counter()
        error = None
        try:
            # Connexion HTTPS fraiche a chaque iteration (pas de Session
            # requests, donc pas de Keep-Alive) : l'handshake mTLS de
            # Service A (certificat client) a lieu a chaque acces, comme
            # dans le comportement reel de l'architecture.
            response = requests.get(
                url,
                cert=(str(paths["client_cert"]), str(paths["client_key"])),
                verify=str(paths["ca_cert"]),
                timeout=args.timeout,
            )
            t_fin_acces = time.perf_counter()
            response.raise_for_status()
        except requests.RequestException as exc:
            t_fin_acces = time.perf_counter()
            error = exc

        latence_ms = (t_fin_acces - t_debut_acces) * 1000
        if error is None:
            successful += 1
            samples_ms.append(latence_ms)
            print(f"[{i}/{args.n}] L_S2S = {latence_ms:.3f} ms", file=sys.stderr)
        else:
            failed += 1
            print(f"[{i}/{args.n}] ECHEC : {error}", file=sys.stderr)

    if failed > 0:
        print(f"AVERTISSEMENT : {failed} iteration(s) en echec sur {args.n}",
              file=sys.stderr)

    return summarize(samples_ms, successful, failed)


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit etre >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))