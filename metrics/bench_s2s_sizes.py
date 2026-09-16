"""
bench_s2s_sizes.py -- mesure des tailles cryptographiques SERVICE -> SERVICE.

Derniere metrique experimentale S2S : tailles en OCTETS des elements
cryptographiques reellement utilises dans le flux :

    Service A -> PEP -> PDP -> Service B (Ressource)

Ne mesure QUE des tailles. NE MODIFIE RIEN (architecture, PKI, services,
mecanismes) : script de LECTURE uniquement, identite S2S reelle
(Service A = batch-service, Service B = ressource, meme PKI que
bench_s2s_latency.py / bench_s2s_throughput.py).

Elements mesures :
  - certificate_service_a : certificat client de Service A presents en mTLS
    au PEP (batch-service.crt) ;
  - certificate_service_b : certificat serveur de Service B (ressource.crt),
    valide par le PEP lors du relais ;
  - ca_certificate : certificat de la CA commune (chaine de confiance) ;
  - signature_public_key : cle publique de Service A (verification du
    CertificateVerify) : DER SPKI (RSA-3072) ou octets bruts liboqs (CROSS),
    extraits du certificat reel ;
  - signature_private_key : cle privee de Service A (batch-service.key),
    utilisee pour signer le CertificateVerify : forme stockee PKCS#8
    (+ reference raw liboqs pour CROSS) ;
  - kem_public_key / kem_private_key : HQC-1 via liboqs (PQC, taille fixe,
    cles ephemeres par session) / not_applicable (classique : ECDHE
    ephemeres, aucune cle KEM persistante).

Formats signales explicitement (comparabilite) :
  - certificats : DER (forme transmise sur TLS) et PEM (disque) ;
  - cles : representation exacte (DER SubjectPublicKeyInfo, PKCS#8 DER,
    octets bruts liboqs) ; deux representations differentes ne sont jamais
    comparees sans l'indiquer.
  - la cle CROSS est fournie en raw liboqs (ce que consomme le mecanisme),
    avec la SPKI DER en reference pour la comparer a RSA.

Usage :
    venv/bin/python metrics/bench_s2s_sizes.py --mode classical
    venv/bin/python metrics/bench_s2s_sizes.py --mode pqc
"""

import argparse
import base64
import contextlib
import io
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parent.parent

# liboqs-python installe a l'import un StreamHandler(stdout) INFO
# ("liboqs-python faulthandler is disabled") : on isole ce message pour
# garder une sortie JSON propre, sans rien modifier a liboqs.
_oqs_import_stdout = io.StringIO()
with contextlib.redirect_stdout(_oqs_import_stdout):
    import oqs

DEFAULT_MODES = {"classical": "pki", "pqc": "pki-pqc"}
KEM_ALG = "HQC-1"
PQC_SIG_ALG = "cross-rsdp-128-balanced"
PQC_RAW_SEC_BYTES = 32   # taille fixe du secret CROSS (liboqs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure des tailles cryptographiques service -> service "
                    "(mTLS S2S), en octets"
    )
    parser.add_argument(
        "--mode", choices=sorted(DEFAULT_MODES), default="classical",
        help="phase a mesurer : classical (RSA-3072/ECDH) ou pqc "
             "(CROSS+HQC-1)"
    )
    parser.add_argument(
        "--pki-dir", default=None,
        help="repertoire PKI (defaut : 'pki/' pour classical, 'pki-pqc/' "
             "pour pqc)"
    )
    parser.add_argument(
        "--ca-cert", default=None,
        help="certificat CA (defaut : pki[-pqc]/ca/certs/ca.cert.pem)"
    )
    parser.add_argument(
        "--client-cert", default=None,
        help="certificat de Service A (defaut : "
             "pki[-pqc]/certs/batch-service.crt)"
    )
    parser.add_argument(
        "--client-key", default=None,
        help="cle de Service A (defaut : pki[-pqc]/certs/batch-service.key)"
    )
    parser.add_argument(
        "--service-b-cert", default=None,
        help="certificat de Service B (defaut : "
             "pki[-pqc]/certs/ressource.crt)"
    )
    return parser.parse_args()


def pki_dir_for(args: argparse.Namespace) -> Path:
    if args.pki_dir:
        return Path(args.pki_dir).resolve()
    return BASE_DIR / DEFAULT_MODES[args.mode]


def pem_der_size(pem_bytes: bytes) -> int:
    """Taille DER (octets) a partir d'un blob PEM, sans appeler openssl :
    decode le corps Base64 entre les armures BEGIN/END."""
    body = "".join(
        line for line in pem_bytes.decode("ascii").splitlines()
        if line and not line.startswith("-----")
    )
    return len(base64.b64decode(body))


def _pem_to_der(pem_bytes: bytes) -> bytes:
    body = "".join(
        line for line in pem_bytes.decode("ascii").splitlines()
        if line and not line.startswith("-----")
    )
    return base64.b64decode(body)


# ---------------------------------------------------------------------------
# Mini-parseur DER (lecture seule des structures ASN.1 reelles)
# ---------------------------------------------------------------------------

def _tlv(der: bytes, off: int):
    """Retourne (tag, start, body_start, body_end) du TLV commencant a off.
    body_start/body_end bornent les octets de CONTENU (hors tag et longueur)."""
    tag = der[off]
    start = off
    off += 1
    length = der[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(der[off:off + n], "big")
        off += n
    return tag, start, off, off + length


def _spki_from_cert_der(cert_der: bytes) -> bytes:
    """Extrait le TLV SubjectPublicKeyInfo (SPKI) du certificat DER.
    Certificat ::= SEQUENCE { tbsCertificate, sigAlg, sig } ; la SPKI est la
    premiere SEQUENCE de tbsCertificate dont le corps est un algorithme
    (SEQUENCE, tag 0x30) suivi d'une BIT STRING (0x03)."""
    _, _, cert_body, cert_end = _tlv(cert_der, 0)
    # 1er champ : tbsCertificate (SEQUENCE)
    _, _, tbs_body, tbs_end = _tlv(cert_der, cert_body)
    pos = tbs_body
    while pos < tbs_end:
        tag, start, body, end = _tlv(cert_der, pos)
        if tag == 0x30:
            # AlgorithmIdentifier : SEQUENCE { OID [params] }, puis la
            # BIT STRING du contenu cle. Le tag apres la FIN de l'algorithme.
            alg_tag, _, _, alg_end = _tlv(cert_der, body)
            next_tag, _, _, _ = _tlv(cert_der, alg_end)
            if alg_tag == 0x30 and next_tag == 0x03:
                return cert_der[start:end]
        pos = end
    raise ValueError("SPKI introuvable dans le certificat")


def _bit_string_raw(spki_der: bytes) -> bytes:
    """Contenu de la BIT STRING du SPKI : 1er octet = nb de bits non
    utilises (0 ici), le reste = octets bruts de la cle."""
    _, _, spki_body, spki_end = _tlv(spki_der, 0)
    pos = spki_body
    # saute l'algorithme (SEQUENCE) et lit la BIT STRING
    _, _, alg_body, alg_end = _tlv(spki_der, pos)
    tag, _, bs_body, bs_end = _tlv(spki_der, alg_end)
    assert tag == 0x03, "BIT STRING attendue dans la SPKI"
    unused = spki_der[bs_body]
    if unused != 0:
        raise ValueError(f"BIT STRING avec {unused} bits de padding inattendu")
    return spki_der[bs_body + 1:bs_end]


# ---------------------------------------------------------------------------
# Mesures
# ---------------------------------------------------------------------------

def measure_certificate(pem_path: Path, label: str) -> dict:
    pem = pem_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    sig_alg = cert.signature_algorithm_oid._name
    if sig_alg == "Unknown OID":
        sig_alg = f"CROSS/OQS (OID {cert.signature_algorithm_oid.dotted_string})"
    return {
        "label": label,
        "path": str(pem_path.relative_to(BASE_DIR)),
        "format": "DER (transmission TLS) / PEM (stockage disque)",
        "der_bytes": pem_der_size(pem),
        "pem_bytes": len(pem),
        "subject": cert.subject.rfc4514_string(),
        "signature_algorithm": sig_alg,
    }


def measure_signature_public_key(cert_path: Path, mode: str) -> dict:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if mode == "classical":
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "label": "Cle publique de Service A (verification CertificateVerify mTLS)",
            "format": "DER SubjectPublicKeyInfo",
            "algorithm": "RSA-3072",
            "size_bytes": len(spki),
            "source": f"extraite de {cert_path.relative_to(BASE_DIR)}",
        }
    # PQC (CROSS) : la SPKI reelle du certificat contient la BIT STRING
    # brute consommee par liboqs. On la decoupe sans regenere de cle.
    spki = _spki_from_cert_der(cert.public_bytes(serialization.Encoding.DER))
    raw = _bit_string_raw(spki)
    return {
        "label": "Cle publique de Service A (verification CertificateVerify mTLS)",
        "format": "raw liboqs",
        "algorithm": PQC_SIG_ALG,
        "size_bytes": len(raw),
        "spki_der_bytes": len(spki),
        "raw_liboqs_bytes": len(raw),
        "source": f"BIT STRING de la SPKI extraite de {cert_path.relative_to(BASE_DIR)}",
    }


def measure_signature_private_key(key_path: Path, mode: str) -> dict:
    pem = key_path.read_bytes()
    der_size = pem_der_size(pem)
    base = {
        "label": "Cle privee de Service A (authentification mTLS, CertificateVerify)",
        "path": str(key_path.relative_to(BASE_DIR)),
        "pem_bytes": len(pem),
        "pkcs8_der_bytes": der_size,
        "source": f"fichier stocke {key_path.relative_to(BASE_DIR)}",
    }
    if mode == "classical":
        return {
            **base,
            "format": "PKCS#8 DER",
            "algorithm": "RSA-3072",
            "size_bytes": der_size,
        }
    return {
        **base,
        "format": "PKCS#8 DER (stockage) + raw liboqs (reference)",
        "algorithm": PQC_SIG_ALG,
        "size_bytes": der_size,
        "raw_liboqs_secret_bytes": PQC_RAW_SEC_BYTES,
    }


def measure_hqc_kem() -> dict:
    kem = oqs.KeyEncapsulation(KEM_ALG)
    try:
        pub = kem.generate_keypair()
        return {
            "label": "KEM HQC-1 (ephemere par session TLS)",
            "format": "raw liboqs",
            "algorithm": KEM_ALG,
            "size_bytes": len(pub),
            "source": "oqs.KeyEncapsulation('HQC-1')",
        }
    finally:
        kem.free()


def measure_hqc_secret() -> dict:
    kem = oqs.KeyEncapsulation(KEM_ALG)
    try:
        kem.generate_keypair()
        secret = kem.export_secret_key()
        return {
            "label": "KEM HQC-1 (cle secrete, ephemere par session TLS)",
            "format": "raw liboqs",
            "algorithm": KEM_ALG,
            "size_bytes": len(secret),
            "source": "oqs.KeyEncapsulation('HQC-1').export_secret_key()",
        }
    finally:
        kem.free()


def not_applicable(reason: str) -> dict:
    return {"not_applicable": True, "reason": reason}


# ---------------------------------------------------------------------------
# Sortie
# ---------------------------------------------------------------------------

def summarize(result: dict) -> str:
    items = result["items"]
    titles = result["titles"]
    lines = [
        f"Metrique : {result['metric']} (mode {result['mode']}) -- unite : octets",
        f"Format certificats : {result['certificate_format']}",
        "",
    ]
    for key in ("service_a_certificate", "service_b_certificate",
                "ca_certificate"):
        c = items[key]
        lines.append(
            f"  {titles[key]} : {c['der_bytes']} B (DER) / {c['pem_bytes']} B "
            f"(PEM) [{c['signature_algorithm']}]"
        )
    lines.append("")
    for key in ("signature_public_key", "signature_private_key",
                "kem_public_key", "kem_private_key"):
        v = items.get(key)
        if not v:
            continue
        title = titles.get(key, key)
        if v.get("not_applicable"):
            lines.append(f"  {title} : non applicable -- {v['reason']}")
            continue
        extra = ""
        if "spki_der_bytes" in v:
            extra += f" | SPKI DER {v['spki_der_bytes']} B"
        if "pkcs8_der_bytes" in v:
            extra += (f" | PKCS#8 DER {v['pkcs8_der_bytes']} B "
                      f"(PEM {v['pem_bytes']} B)")
        if "raw_liboqs_secret_bytes" in v:
            extra += f" | raw liboqs {v['raw_liboqs_secret_bytes']} B"
        lines.append(
            f"  {title} : {v['size_bytes']} B ({v['format']}, "
            f"{v.get('algorithm', '')}){extra}"
        )
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict:
    pki = pki_dir_for(args)
    service_a_cert = Path(args.client_cert) if args.client_cert \
        else pki / "certs" / "batch-service.crt"
    service_a_key = Path(args.client_key) if args.client_key \
        else pki / "certs" / "batch-service.key"
    service_b_cert = Path(args.service_b_cert) if args.service_b_cert \
        else pki / "certs" / "ressource.crt"
    ca_cert = Path(args.ca_cert) if args.ca_cert \
        else pki / "ca" / "certs" / "ca.cert.pem"

    missing = [str(p.relative_to(BASE_DIR)) for p in
               (service_a_cert, service_a_key, service_b_cert, ca_cert)
               if not p.exists()]
    if missing:
        raise FileNotFoundError(
            f"PKI incomplete pour le mode {args.mode!r} : {missing}"
        )

    items = {
        "service_a_certificate": measure_certificate(
            service_a_cert,
            "Certificat client de Service A (batch-service) -- presente en "
            "mTLS au PEP"),
        "service_b_certificate": measure_certificate(
            service_b_cert,
            "Certificat serveur de Service B (ressource) -- valide par le PEP"),
        "ca_certificate": measure_certificate(
            ca_cert, "Certificat de la CA commune -- chaine de confiance"),
        "signature_public_key": measure_signature_public_key(
            service_a_cert, args.mode),
        "signature_private_key": measure_signature_private_key(
            service_a_key, args.mode),
    }

    if args.mode == "pqc":
        items["kem_public_key"] = measure_hqc_kem()
        items["kem_private_key"] = measure_hqc_secret()
    else:
        reason = (
            "TLS classique (RSA-3072/ECDH) utilise des ephemeres ECDHE "
            "negocies a chaque session : aucune cle KEM n'est generee ni "
            "stockee. La comparaison des tailles KEM ne concerne que le mode "
            "PQC (HQC-1)."
        )
        items["kem_public_key"] = not_applicable(reason)
        items["kem_private_key"] = not_applicable(reason)

    return {
        "metric": "tailles_cryptographiques_service_service",
        "unit": "bytes",
        "mode": args.mode,
        "certificate_format": "DER (transmission TLS) / PEM (stockage disque)",
        "titles": {
            "service_a_certificate": "1. Certificat Service A (batch-service)",
            "service_b_certificate": "2. Certificat Service B (ressource)",
            "ca_certificate": "3. Certificat CA",
            "signature_public_key": "4. Cle publique de signature/authentification",
            "signature_private_key": "5. Cle privee correspondante",
            "kem_public_key": "6. Cle publique KEM",
            "kem_private_key": "7. Cle privee KEM",
        },
        "comparability_notes": [
            "Les certificats sont compares dans leur forme DER (reseau) et "
            "PEM (disque).",
            "Cle publique de signature : DER SPKI (RSA-3072, 422 B) vs octets "
            "bruts liboqs (CROSS, 77 B) ; la SPKI DER (99 B) est fournie "
            "comme representation intermediaire pour CROSS.",
            "La cle privee est comparee dans sa forme stockee PKCS#8 (1793 B "
            "RSA / 136 B CROSS) ; le secret raw liboqs CROSS (32 B) est fourni "
            "en reference.",
            "HQC-1 (tailles fixes liboqs) et ECDHE classique sont des cles "
            "ephemeres par session TLS 1.3, non synonymes de certificat.",
            "Toutes les tailles concernent le scenario S2S reel : Service A = "
            "batch-service, Service B = ressource, CA commune.",
        ],
        "items": items,
    }


if __name__ == "__main__":
    args = parse_args()
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\n=== RESUME LISIBLE ===\n", file=sys.stderr)
    print(summarize(result), file=sys.stderr)