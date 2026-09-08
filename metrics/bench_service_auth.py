"""
bench_service_auth.py -- Benchmarks du flux d'authentification
service-to-service (mTLS), phase classique (RSA-3072).

Différence structurelle avec bench_auth.py (flux JWT) : il n'existe pas
d'endpoint /authenticate séparé en mTLS -- l'authentification EST le
handshake TLS mutuel lui-même (échange + vérification de certificats des
deux côtés). "Temps d'authentification" est donc mesuré ici au niveau
socket (connexion TCP + handshake TLS), séparément de l'appel HTTP complet,
pour rester conceptuellement comparable à la mesure côté JWT (qui isolait
déjà la vérification d'identifiants + signature, sans le reste de la chaîne).

Métriques (mêmes 4 catégories que bench_auth.py) :
  1. Temps d'authentification : connexion TCP + handshake TLS mutuel pur,
     mesuré au niveau socket (aucune requête HTTP envoyée).
  2. Latence bout en bout       : GET /api/data via le PEP, avec certificat
     client mTLS -- inclut le handshake + appel PDP + relais Ressource.
  3. Débit                      : sur les deux mesures ci-dessus séparément.
  4. Taille des clés            : certificat/clé du service appelant.

Usage :
    python bench_service_auth.py --pep-host pep.ztpqc.lab --pep-port 8443 \
                                  --client-cert ../pki/certs/batch-service.crt \
                                  --client-key ../pki/certs/batch-service.key \
                                  --ca-cert ../pki/ca/ca.crt \
                                  --n-latency 200 \
                                  --duration-throughput 10 \
                                  --concurrency 10
"""

import argparse
import csv
import json
import os
import socket
import ssl
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests


# --- Utilitaires statistiques (identiques à bench_auth.py, pour comparabilité directe) ---

def percentile(values: list, p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def summarize(name: str, values_seconds: list, unit: str = "ms") -> dict:
    factor = 1000.0 if unit == "ms" else 1.0
    ms = [v * factor for v in values_seconds]
    return {
        "metric": name,
        "unit": unit,
        "n": len(ms),
        "mean": round(statistics.mean(ms), 3) if ms else None,
        "median": round(statistics.median(ms), 3) if ms else None,
        "stdev": round(statistics.stdev(ms), 3) if len(ms) > 1 else 0.0,
        "p95": round(percentile(ms, 95), 3),
        "p99": round(percentile(ms, 99), 3),
        "min": round(min(ms), 3) if ms else None,
        "max": round(max(ms), 3) if ms else None,
    }


# --- 1. Temps d'authentification (handshake mTLS pur, niveau socket) --------

def build_client_ssl_context(client_cert: str, client_key: str, ca_cert: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    context.load_verify_locations(cafile=ca_cert)
    return context


def measure_mtls_handshake_latency(host: str, port: int, context: ssl.SSLContext, n: int) -> list:
    """
    Chronomètre n connexions TCP + handshakes TLS mutuels, SANS envoyer de
    requête HTTP -- isole le coût cryptographique/protocolaire de
    l'authentification elle-même (nouvelle connexion à chaque itération,
    pas de réutilisation de session TLS).
    """
    durations = []
    for _ in range(n):
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.getpeercert()  # force la confirmation que le handshake est bien terminé
        elapsed = time.perf_counter() - start
        durations.append(elapsed)
    return durations


# --- 2. Latence bout en bout (GET /api/data via le PEP, mTLS) ---------------

def measure_access_latency(pep_url: str, client_cert: str, client_key: str, ca_cert: str, n: int) -> list:
    url = pep_url.rstrip("/") + "/api/data"
    durations = []
    for _ in range(n):
        start = time.perf_counter()
        response = requests.get(url, cert=(client_cert, client_key), verify=ca_cert, timeout=10)
        elapsed = time.perf_counter() - start
        response.raise_for_status()
        durations.append(elapsed)
    return durations


# --- 3. Débit -----------------------------------------------------------------

@dataclass
class ThroughputResult:
    completed: int = 0
    failed: int = 0
    durations: list = field(default_factory=list)
    wall_time_s: float = 0.0

    @property
    def requests_per_second(self) -> float:
        return self.completed / self.wall_time_s if self.wall_time_s > 0 else 0.0


def measure_throughput(request_fn, duration_s: float, concurrency: int) -> ThroughputResult:
    result = ThroughputResult()
    stop_at = time.perf_counter() + duration_s
    wall_start = time.perf_counter()

    def worker():
        local_durations = []
        local_failed = 0
        while time.perf_counter() < stop_at:
            try:
                local_durations.append(request_fn())
            except Exception:
                local_failed += 1
        return local_durations, local_failed

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker) for _ in range(concurrency)]
        for future in as_completed(futures):
            durations, failed = future.result()
            result.durations.extend(durations)
            result.failed += failed

    result.completed = len(result.durations)
    result.wall_time_s = time.perf_counter() - wall_start
    return result


# --- 4. Tailles ----------------------------------------------------------------

def measure_sizes(client_cert_path: str, client_key_path: str) -> dict:
    sizes = {}
    if os.path.exists(client_cert_path):
        sizes["certificat_service_bytes"] = os.path.getsize(client_cert_path)
    if os.path.exists(client_key_path):
        sizes["cle_privee_service_bytes"] = os.path.getsize(client_key_path)
    return sizes


# --- Orchestration ---------------------------------------------------------------

def run_benchmark(args) -> dict:
    context = build_client_ssl_context(args.client_cert, args.client_key, args.ca_cert)

    print("=== 1. Temps d'authentification (handshake mTLS, niveau socket) ===")
    handshake_durations = measure_mtls_handshake_latency(args.pep_host, args.pep_port, context, args.n_latency)
    handshake_summary = summarize("temps_authentification_mtls", handshake_durations)
    print(json.dumps(handshake_summary, indent=2, ensure_ascii=False))

    print("\n=== 2. Latence bout en bout (GET /api/data via PEP, mTLS) ===")
    pep_url = f"https://{args.pep_host}:{args.pep_port}"
    access_durations = measure_access_latency(pep_url, args.client_cert, args.client_key, args.ca_cert, args.n_latency)
    access_summary = summarize("latence_acces_bout_en_bout", access_durations)
    print(json.dumps(access_summary, indent=2, ensure_ascii=False))

    print("\n=== 3. Débit -- handshake mTLS seul ===")
    def request_handshake():
        s = time.perf_counter()
        with socket.create_connection((args.pep_host, args.pep_port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=args.pep_host) as ssock:
                ssock.getpeercert()
        return time.perf_counter() - s

    throughput_handshake = measure_throughput(request_handshake, args.duration_throughput, args.concurrency)
    print(f"Connexions complétées : {throughput_handshake.completed}, échecs : {throughput_handshake.failed}")
    print(f"Débit : {throughput_handshake.requests_per_second:.2f} handshakes/s "
          f"(concurrence={args.concurrency}, durée={args.duration_throughput}s)")

    print("\n=== 3bis. Débit -- GET /api/data via PEP (mTLS complet) ===")
    def request_access():
        s = time.perf_counter()
        r = requests.get(pep_url + "/api/data", cert=(args.client_cert, args.client_key), verify=args.ca_cert, timeout=10)
        r.raise_for_status()
        return time.perf_counter() - s

    throughput_access = measure_throughput(request_access, args.duration_throughput, args.concurrency)
    print(f"Requêtes complétées : {throughput_access.completed}, échecs : {throughput_access.failed}")
    print(f"Débit : {throughput_access.requests_per_second:.2f} req/s "
          f"(concurrence={args.concurrency}, durée={args.duration_throughput}s)")

    print("\n=== 4. Tailles ===")
    sizes = measure_sizes(args.client_cert, args.client_key)
    print(json.dumps(sizes, indent=2, ensure_ascii=False))

    return {
        "crypto_mode": "classical",
        "alg": "RSA-3072-PSS-SHA384",
        "flux": "service-to-service (mTLS)",
        "temps_authentification_mtls": handshake_summary,
        "latence_acces_bout_en_bout": access_summary,
        "debit_handshake_s": round(throughput_handshake.requests_per_second, 2),
        "debit_access_req_s": round(throughput_access.requests_per_second, 2),
        "tailles": sizes,
    }


def save_results(results: dict, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"bench_service_auth_{results['crypto_mode']}_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nRésultats détaillés : {json_path}")

    csv_path = os.path.join(output_dir, "bench_service_auth_summary.csv")
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp", "crypto_mode", "alg",
                "handshake_mean_ms", "handshake_p95_ms", "handshake_p99_ms",
                "access_mean_ms", "access_p95_ms", "access_p99_ms",
                "debit_handshake_s", "debit_access_req_s",
                "certificat_service_bytes",
            ])
        writer.writerow([
            timestamp, results["crypto_mode"], results["alg"],
            results["temps_authentification_mtls"]["mean"], results["temps_authentification_mtls"]["p95"], results["temps_authentification_mtls"]["p99"],
            results["latence_acces_bout_en_bout"]["mean"], results["latence_acces_bout_en_bout"]["p95"], results["latence_acces_bout_en_bout"]["p99"],
            results["debit_handshake_s"], results["debit_access_req_s"],
            results["tailles"].get("certificat_service_bytes"),
        ])
    print(f"Résumé cumulatif (CSV) : {csv_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark du flux d'authentification service-to-service (mTLS)")
    parser.add_argument("--pep-host", default="pep.ztpqc.lab")
    parser.add_argument("--pep-port", type=int, default=8443)
    parser.add_argument("--client-cert", default="../pki/certs/batch-service.crt")
    parser.add_argument("--client-key", default="../pki/certs/batch-service.key")
    parser.add_argument("--ca-cert", default="../pki/ca/certs/ca.cert.pem")
    parser.add_argument("--n-latency", type=int, default=200)
    parser.add_argument("--duration-throughput", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--output-dir", default="results")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    results = run_benchmark(args)
    save_results(results, args.output_dir)