"""
bench_s2s_auth.py -- mesure du temps d'authentification SERVICE -> SERVICE.

Mesure strictement, en millisecondes :

    T_auth_S2S = t_fin_auth - t_debut_auth

où t_debut_auth = instant juste avant l'ouverture de la connexion TLS et
t_fin_auth = instant juste après la fin de l'handshake mTLS (l'identité de
Service A a alors été établie ET validée par Service B).

Périmètre mesuré (UNIQUEMENT l'authentification S2S) :
  Service A (rôle client, identité PEP) -- authentification mTLS -->
  Service B (Ressource, ssl.CERT_REQUIRED)

Le chronomètre couvre exactement l'établissement et la validation de
l'identité : poignée de main TLS 1.3 avec certificat client présenté par
Service A et exigé/validé par Service B contre la CA commune (mêmes PEM,
même CA, même URL réelle que le flux PEP -> Ressource du simulateur,
pep/app.py étape 3). Aucune requête HTTP n'est émise, afin de NE PAS
inclure : évaluation PDP, autorisation d'accès, traitement métier de
Service B, réponse métier, débit, latence bout-en-bout.

Exclusions volontaires (conformité au cadrage) :
  - PDP / autorisation : hors périmètre (ce benchmark ne fait que
    s'authentifier, il ne demande AUCUN accès à une ressource) ;
  - traitement métier / réponse : aucune requête applicative n'est émise ;
  - la ressource applicative n'est jamais sollicitée.

Réutilisation des composants existants (aucune architecture parallèle) :
  - pep/config.py : chemins PKI, URL de la Ressource (RESOURCE_BASE_URL) ;
  - pep/mtls_handler.py.resource_client_cert() : l'identité (cert/clé) que
    Service A présente réellement (idem PEP vers Ressource) ;
  - Ressource (/ressource) : le Service B réel, exécuté tel quel.

Méthodologie de mesure :
  - time.perf_counter() (chronomètre monotone haute résolution) ;
  - une nouvelle connexion TLS par itération (socket frais, pas de
    Keep-Alive, pas de resumption, pas de session réutilisée) ;
  - le groupe TLS (ECDH x25519 en classique, HQC-1 en PQC) est piloté par
    le openssl.cnf système (/usr/local/ssl/openssl.cnf) : il DOIT être
    positionné par l'utilisateur selon la phase mesurée (x25519:P-256 pour
    classique, hqc1 pour PQC), exactement comme pour les autres benchmarks.

Usage (phase classique) :
    venv/bin/python metrics/bench_s2s_auth.py --mode classical --n 50

Usage (phase PQC) :
    venv/bin/python metrics/bench_s2s_auth.py --mode pqc --n 50
"""

import argparse
import json
import socket
import ssl
import statistics
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PEP_DIR = BASE_DIR / "pep"
sys.path.insert(0, str(PEP_DIR))

import config  # pep/config.py -- configuration du PEP (reused telle quelle)
import mtls_handler  # pep/mtls_handler.py -- identité mTLS sortante du PEP


# --- chemins PKI par mode ----------------------------------------------------
_PKI_BY_MODE = {
    "classical": "pki",
    "pqc": "pki-pqc",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure du temps d'authentification service -> service "
                    "(mTLS), en millisecondes"
    )
    parser.add_argument(
        "--mode", choices=["classical", "pqc"], required=True,
        help="configuration cryptographique mesurée (classical : RSA-ECDH ; "
             "pqc : CROSS/HQC-1)"
    )
    parser.add_argument("--n", type=int, default=50,
                        help="nombre d'authentifications S2S indépendantes (N)")
    parser.add_argument("--ca-cert", default=None,
                        help="certificat de la CA (défaut : pki[-pqc]/ca/certs/"
                             "ca.cert.pem selon --mode)")
    parser.add_argument("--client-cert", default=None,
                        help="certificat(client) présenté par Service A "
                             "(défaut : pki[-pqc]/certs/pep.crt selon --mode)")
    parser.add_argument("--client-key", default=None,
                        help="clé privée correspondante (défaut : "
                             "pki[-pqc]/certs/pep.key selon --mode)")
    parser.add_argument("--ressource-url", default=config.RESOURCE_BASE_URL,
                        help="URL de Service B (Ressource), défaut : "
                             "https://ressource.ztpqc.lab:8446")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout de connexion/handshake (secondes)")
    return parser.parse_args()


def _resolve_paths(args: argparse.Namespace) -> dict:
    pki_dir = BASE_DIR / _PKI_BY_MODE[args.mode]
    return {
        "ca_cert": Path(args.ca_cert or pki_dir / "ca" / "certs" / "ca.cert.pem"),
        "client_cert": Path(args.client_cert or pki_dir / "certs" / "pep.crt"),
        "client_key": Path(args.client_key or pki_dir / "certs" / "pep.key"),
    }


def summarize(samples_ms: list, successful: int, failed: int) -> dict:
    return {
        "metric": "temps_authentification_service_service",
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

    # Aligne le config du PEP sur les chemins réels (même mécanique que
    # bench_auth.py) afin de réutiliser la fonction d'identité existante.
    config.CA_CERT = str(paths["ca_cert"])
    config.PEP_TLS_CERT = str(paths["client_cert"])
    config.PEP_TLS_KEY = str(paths["client_key"])

    client_identity = mtls_handler.resource_client_cert()  # (cert, key) réels

    host, port = _split_host_port(args.ressource_url)

    # Contexte client TLS 1.3 : présente l'identité de Service A et vérifie
    # le certificat serveur de Service B contre la CA commune -- exactement
    # comme le fait le PEP dans le flux réel (cert=..., verify=CA).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=client_identity[0], keyfile=client_identity[1])
    ctx.load_verify_locations(cafile=str(paths["ca_cert"]))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    samples_ms = []
    successful = 0
    failed = 0

    for i in range(1, args.n + 1):
        t_debut_auth = time.perf_counter()
        error = None
        try:
            with socket.create_connection((host, port), timeout=args.timeout) as sock:
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        # L'handshake TLS 1.3 mTLS (établissement + validation
                        # de l'identité) est terminé ici. Aucune requête HTTP :
                        # le service B est authentifié comme partenaire (son
                        # certificat a été vérifié côté client) et Service A
                        # vient d'être authentifié auprès de lui (son
                        # certificat a été exigé et validé, CERT_REQUIRED).
                        pass
                except ssl.SSLError as exc:
                    error = exc
        except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
            error = exc
        t_fin_auth = time.perf_counter()

        temps_ms = (t_fin_auth - t_debut_auth) * 1000
        if error is None:
            successful += 1
            samples_ms.append(temps_ms)
            print(f"[{i}/{args.n}] T_auth_S2S = {temps_ms:.3f} ms", file=sys.stderr)
        else:
            failed += 1
            print(f"[{i}/{args.n}] ECHEC : {error}", file=sys.stderr)

    if failed > 0:
        print(f"AVERTISSEMENT : {failed} itération(s) en échec sur "
              f"{args.n}", file=sys.stderr)

    return summarize(samples_ms, successful, failed)


def _split_host_port(url: str) -> tuple:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"URL Service B invalide (https attendu) : {url!r}")
    return parsed.hostname, parsed.port or 443


if __name__ == "__main__":
    args = parse_args()
    if args.n < 1:
        raise ValueError("--n doit être >= 1")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))