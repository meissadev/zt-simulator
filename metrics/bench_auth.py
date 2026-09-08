"""
bench_auth.py -- Benchmarks du flux d'authentification utilisateur -> service
(JWT), phase classique (RSA-3072) -- baseline avant comparaison PQC.

Métriques mesurées (section 1.1 du plan expérimental) :
  1. Temps d'authentification : latence de POST /authenticate (IdP seul) --
     vérification des identifiants + signature du JWT.
  2. Latence (bout en bout)   : latence de GET /api/data via le PEP --
     vérification JWT + JWKS + appel PDP + relais mTLS vers la Ressource.
  3. Débit                    : requêtes/seconde en charge concurrente, sur
     les deux endpoints ci-dessus séparément.
  4. Taille des clés          : tailles réelles (octets) des clés, du
     certificat et du token JWT -- mesure statique, pas de timing.

Principe méthodologique : chaque requête HTTP est chronométrée côté client
avec time.perf_counter() (haute résolution, insensible aux ajustements
d'horloge système) ; les mesures de charge utilisent des threads car les
appels sont dominés par de l'attente réseau/TLS, pas par du calcul Python
(le GIL n'est donc pas un facteur limitant significatif ici).

Usage :
    python bench_auth.py --idp-url https://idp.ztpqc.lab:8444 \
                          --pep-url https://pep.ztpqc.lab:8443 \
                          --ca-cert ../pki/ca/ca.crt \
                          --n-latency 200 \
                          --duration-throughput 10 \
                          --concurrency 10
"""

import argparse
import csv
import json
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests


# --- Utilitaires statistiques ------------------------------------------------

def percentile(values: list, p: float) -> float:
    """Percentile simple par interpolation linéaire (sans dépendance externe)."""
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def summarize(name: str, values_seconds: list, unit: str = "ms") -> dict:
    """Convertit une liste de durées (secondes) en résumé statistique (ms)."""
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


# --- 1. Temps d'authentification (POST /authenticate, IdP seul) -------------

def measure_authenticate_latency(idp_url: str, ca_cert: str, n: int, username: str, password: str) -> list:
    """Chronomètre n appels séquentiels à /authenticate. Retourne une liste de durées (s)."""
    url = idp_url.rstrip("/") + "/authenticate"
    payload = {"username": username, "password": password}
    durations = []
    for _ in range(n):
        start = time.perf_counter()
        response = requests.post(url, json=payload, verify=ca_cert, timeout=10)
        elapsed = time.perf_counter() - start
        response.raise_for_status()
        durations.append(elapsed)
    return durations


# --- 2. Latence bout en bout (GET /api/data via le PEP) ---------------------

def measure_access_latency(pep_url: str, token: str, ca_cert: str, n: int) -> list:
    """Chronomètre n appels séquentiels à /api/data via le PEP. Retourne une liste de durées (s)."""
    url = pep_url.rstrip("/") + "/api/data"
    headers = {"Authorization": f"Bearer {token}"}
    durations = []
    for _ in range(n):
        start = time.perf_counter()
        response = requests.get(url, headers=headers, verify=ca_cert, timeout=10)
        elapsed = time.perf_counter() - start
        response.raise_for_status()
        durations.append(elapsed)
    return durations


# --- 3. Débit (requêtes concurrentes pendant une durée fixe) ----------------

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
    """
    Exécute request_fn() en boucle sur `concurrency` threads pendant
    duration_s secondes. request_fn doit effectuer UNE requête et retourner
    sa durée (secondes) ou lever une exception en cas d'échec.
    """
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


# --- 4. Taille des clés / certificat / token ---------------------------------

def measure_sizes(idp_cert_path: str, idp_key_path: str, sample_token: str) -> dict:
    sizes = {}
    if os.path.exists(idp_cert_path):
        sizes["certificat_idp_bytes"] = os.path.getsize(idp_cert_path)
    if os.path.exists(idp_key_path):
        sizes["cle_privee_idp_bytes"] = os.path.getsize(idp_key_path)
    if sample_token:
        sizes["token_jwt_bytes"] = len(sample_token.encode("utf-8"))
        header_b64, payload_b64, sig_b64 = sample_token.split(".")
        sizes["token_header_b64_bytes"] = len(header_b64)
        sizes["token_payload_b64_bytes"] = len(payload_b64)
        sizes["token_signature_b64_bytes"] = len(sig_b64)
    return sizes


# --- Orchestration -------------------------------------------------------------

def run_benchmark(args) -> dict:
    print("=== 1. Temps d'authentification (POST /authenticate) ===")
    auth_durations = measure_authenticate_latency(
        args.idp_url, args.ca_cert, args.n_latency, args.username, args.password
    )
    auth_summary = summarize("temps_authentification", auth_durations)
    print(json.dumps(auth_summary, indent=2, ensure_ascii=False))

    # Récupère un token pour les étapes suivantes
    token_response = requests.post(
        args.idp_url.rstrip("/") + "/authenticate",
        json={"username": args.username, "password": args.password},
        verify=args.ca_cert,
        timeout=10,
    )
    token_response.raise_for_status()
    token = token_response.json()["access_token"]

    print("\n=== 2. Latence bout en bout (GET /api/data via PEP) ===")
    access_durations = measure_access_latency(args.pep_url, token, args.ca_cert, args.n_latency)
    access_summary = summarize("latence_acces_bout_en_bout", access_durations)
    print(json.dumps(access_summary, indent=2, ensure_ascii=False))

    print("\n=== 3. Débit -- POST /authenticate ===")
    def request_authenticate():
        s = time.perf_counter()
        r = requests.post(
            args.idp_url.rstrip("/") + "/authenticate",
            json={"username": args.username, "password": args.password},
            verify=args.ca_cert, timeout=10,
        )
        r.raise_for_status()
        return time.perf_counter() - s

    throughput_auth = measure_throughput(request_authenticate, args.duration_throughput, args.concurrency)
    print(f"Requêtes complétées : {throughput_auth.completed}, échecs : {throughput_auth.failed}")
    print(f"Débit : {throughput_auth.requests_per_second:.2f} req/s "
          f"(concurrence={args.concurrency}, durée={args.duration_throughput}s)")

    print("\n=== 3bis. Débit -- GET /api/data via PEP ===")
    def request_access():
        s = time.perf_counter()
        r = requests.get(
            args.pep_url.rstrip("/") + "/api/data",
            headers={"Authorization": f"Bearer {token}"},
            verify=args.ca_cert, timeout=10,
        )
        r.raise_for_status()
        return time.perf_counter() - s

    throughput_access = measure_throughput(request_access, args.duration_throughput, args.concurrency)
    print(f"Requêtes complétées : {throughput_access.completed}, échecs : {throughput_access.failed}")
    print(f"Débit : {throughput_access.requests_per_second:.2f} req/s "
          f"(concurrence={args.concurrency}, durée={args.duration_throughput}s)")

    print("\n=== 4. Tailles ===")
    sizes = measure_sizes(args.idp_cert, args.idp_key, token)
    print(json.dumps(sizes, indent=2, ensure_ascii=False))

    return {
        "crypto_mode": "classical",
        "alg": "RSA-3072-PSS-SHA384",
        "temps_authentification": auth_summary,
        "latence_acces_bout_en_bout": access_summary,
        "debit_authenticate_req_s": round(throughput_auth.requests_per_second, 2),
        "debit_access_req_s": round(throughput_access.requests_per_second, 2),
        "tailles": sizes,
    }


def save_results(results: dict, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"bench_auth_{results['crypto_mode']}_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nRésultats détaillés : {json_path}")

    csv_path = os.path.join(output_dir, "bench_auth_summary.csv")
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp", "crypto_mode", "alg",
                "auth_mean_ms", "auth_p95_ms", "auth_p99_ms",
                "access_mean_ms", "access_p95_ms", "access_p99_ms",
                "debit_authenticate_req_s", "debit_access_req_s",
                "token_jwt_bytes", "certificat_idp_bytes",
            ])
        writer.writerow([
            timestamp, results["crypto_mode"], results["alg"],
            results["temps_authentification"]["mean"], results["temps_authentification"]["p95"], results["temps_authentification"]["p99"],
            results["latence_acces_bout_en_bout"]["mean"], results["latence_acces_bout_en_bout"]["p95"], results["latence_acces_bout_en_bout"]["p99"],
            results["debit_authenticate_req_s"], results["debit_access_req_s"],
            results["tailles"].get("token_jwt_bytes"), results["tailles"].get("certificat_idp_bytes"),
        ])
    print(f"Résumé cumulatif (CSV, pour comparaison future) : {csv_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark du flux d'authentification utilisateur -> service")
    parser.add_argument("--idp-url", default="https://idp.ztpqc.lab:8444")
    parser.add_argument("--pep-url", default="https://pep.ztpqc.lab:8443")
    parser.add_argument("--ca-cert", default="../pki/ca/certs/ca.cert.pem")
    parser.add_argument("--idp-cert", default="../pki/certs/idp.crt")
    parser.add_argument("--idp-key", default="../pki/certs/idp.key")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--n-latency", type=int, default=200, help="nombre de requêtes séquentielles pour les mesures de latence")
    parser.add_argument("--duration-throughput", type=float, default=10.0, help="durée (s) de chaque test de débit")
    parser.add_argument("--concurrency", type=int, default=10, help="nombre de threads concurrents pour le débit")
    parser.add_argument("--output-dir", default="results")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    results = run_benchmark(args)
    save_results(results, args.output_dir)