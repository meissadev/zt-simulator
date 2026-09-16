"""
bench_sizes.py -- mesure des tailles cryptographiques (clés et certificats).

4e métrique expérimentale du comparatif :
    classique : RSA-3072 / ECDH  (TLS + signature JWT)
    PQC       : CROSS (signature) + HQC-1 (KEM TLS)

Ne mesure QUE des tailles en OCTETS. Ne modifie aucun service, aucune
logique, aucun benchmark : ce script est un client de lecture qui
  1. lit les fichiers PKI réellement utilisés par le simulateur
     (chemins dérivés de PKI_DIR, même convention que idp/config.py) ;
  2. instancie les VRAIS backends cryptographiques du projet
     (idp/jwt_signer.py : RSASigner / PQCSigner) ainsi que liboqs
     (KeyEncapsulation HQC-1) pour mesurer les clés dans leur
     représentation réellement utilisée.

Formats mesurés (indiqués explicitement dans le JSON) :
  - certificats : PEM (fichiers lus par ssl.load_cert_chain /
    load_verify_locations) ET DER (forme transmise sur le réseau TLS) ;
  - clé publique de signature JWT : DER SubjectPublicKeyInfo (RSA) ou
    octets bruts liboqs (CROSS), telle que publiée au JWKS, plus sa
    forme Base64url réellement transmise ;
  - clé privée de signature JWT : PKCS#8 DER (RSA) ou octets bruts
    liboqs (CROSS), plus la clé privée TLS stockée (fichier .key) ;
  - KEM PQC : octets bruts liboqs (HQC-1), clés éphémères négociées
    en TLS 1.3 (Groups=hqc1).

Usage (phase classique) :
    venv/bin/python metrics/bench_sizes.py --mode classical

Usage (phase PQC) :
    venv/bin/python metrics/bench_sizes.py --mode pqc
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
IDP_DIR = BASE_DIR / "idp"
sys.path.insert(0, str(IDP_DIR))

import config  # idp/config.py -- configuration de l'IdP (réutilisée telle quelle)

# liboqs-python ajoute à l'import un StreamHandler(stdout) au niveau INFO
# ("liboqs-python faulthandler is disabled") : on isole ce message unique
# pour garder une sortie JSON propre, sans rien modifier à liboqs. Importé en
# premier pour que son import effectif (via idp/jwt_signer.py, qui fait
# `import oqs`) utilise le module déjà en cache.
_oqs_import_stdout = io.StringIO()
with contextlib.redirect_stdout(_oqs_import_stdout):
    import oqs

import jwt_signer  # idp/jwt_signer.py -- vrais signataires du simulateur

DEFAULT_MODES = {"classical": "pki", "pqc": "pki-pqc"}
KEM_ALG = "HQC-1"  # nom liboqs ; "hqc1" sous oqsprovider/OpenSSL


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mesure des tailles cryptographiques (clés et certificats), en octets"
    )
    parser.add_argument("--mode", choices=sorted(DEFAULT_MODES), default="classical",
                        help="phase à mesurer : classical (RSA-3072/ECDH) ou pqc (CROSS+HQC-1)")
    parser.add_argument("--pki-dir", default=None,
                        help="répertoire PKI (défaut : 'pki/' pour classical, "
                             "'pki-pqc/' pour pqc ; PKI_DIR est respecté s'il "
                             "est défini dans l'environnement)")
    parser.add_argument("--rsa-key-size", type=int, default=None,
                        help="taille RSA (défaut : RSA_KEY_SIZE de idp/config.py, 3072)")
    parser.add_argument("--pqc-sig-alg", default=None,
                        help="algorithme de signature PQC (défaut : PQC_SIG_ALG, "
                             "cross-rsdp-128-balanced)")
    return parser.parse_args()


def pki_dir_for(args: argparse.Namespace) -> Path:
    env_pki = Path(config.PKI_DIR).resolve()
    project_pki = BASE_DIR / "pki"
    if args.pki_dir:
        return Path(args.pki_dir).resolve()
    # Respecte PKI_DIR si l'environnement pointe explicitement une autre
    # arborescence PKI que le répertoire par défaut du dépôt.
    if env_pki != project_pki:
        return env_pki
    return BASE_DIR / DEFAULT_MODES[args.mode]


def pem_der_size(pem_bytes: bytes) -> int:
    """Taille DER (octets) à partir d'un fichier PEM, sans dépendre d'un
    fournisseur : décode le corps Base64 entre les en-têtes/armures."""
    body = "".join(
        line for line in pem_bytes.decode("ascii").splitlines()
        if line and not line.startswith("-----")
    )
    return len(base64.b64decode(body))


def measure_certificate(pem_path: Path, label: str) -> dict:
    pem = pem_path.read_bytes()
    der_len = pem_der_size(pem)
    cert = x509.load_pem_x509_certificate(pem)
    result = {
        "label": label,
        "path": str(pem_path.relative_to(BASE_DIR)),
        "format": "DER (transmission TLS) / PEM (stockage disque)",
        "size_bytes": der_len,  # forme réellement transmise au fil (réseau TLS)
        "size_bytes_pem": len(pem),  # forme réellement lue sur disque
        "subject": cert.subject.rfc4514_string(),
    }
    # L'algorithme du certificat est indiqué tel qu'annoncé par le certificat.
    # Pour CROSS, cryptography ne décode pas la clé (OID oqsprovider) : on
    # affiche alors l'OID brut.
    sig_alg = cert.signature_algorithm_oid._name
    if sig_alg == "Unknown OID":
        sig_alg = f"CROSS/OQS (OID {cert.signature_algorithm_oid.dotted_string})"
    result["signature_algorithm"] = sig_alg
    try:
        pub = cert.public_key()
        result["public_key_type"] = type(pub).__name__
    except Exception:
        result["public_key_type"] = "Clé CROSS/OQS (OID oqsprovider, non décodée par cryptography)"
    return result


def build_jwt_signer(mode: str, args: argparse.Namespace):
    """Instancie le VRAI signataire JWT de l'IdP (même code que app.py)."""
    config.CRYPTO_MODE = mode
    if args.rsa_key_size:
        config.RSA_KEY_SIZE = args.rsa_key_size
    if args.pqc_sig_alg:
        config.PQC_SIG_ALG = args.pqc_sig_alg
    # Même dispatch que idp/app.py build_signer().
    if config.CRYPTO_MODE == "classical":
        return jwt_signer.RSASigner(key_size=config.RSA_KEY_SIZE, kid=config.SIGNING_KID)
    return jwt_signer.PQCSigner(alg=config.PQC_SIG_ALG, kid=config.SIGNING_KID)


def measure_signature_public_key(signer, mode: str) -> dict:
    raw = signer.public_key_bytes()
    b64 = signer.public_key_b64url()
    if mode == "classical":
        return {
            "label": "Clé publique de signature JWT (JWKS)",
            "format": "DER SubjectPublicKeyInfo",
            "algorithm": signer.alg,
            "size_bytes": len(raw),
            "size_bytes_base64url": len(b64.encode("ascii")),
            "source": "idp/jwt_signer.py RSASigner.public_key_bytes()",
        }
    return {
        "label": "Clé publique de signature JWT (JWKS)",
        "format": "octets bruts liboqs",
        "algorithm": signer.alg,
        "size_bytes": len(raw),
        "size_bytes_base64url": len(b64.encode("ascii")),
        "source": "idp/jwt_signer.py PQCSigner.public_key_bytes()",
    }


def measure_signature_private_key(signer, mode: str, idp_key_path: Path) -> dict:
    if mode == "classical":
        priv_der = signer._private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        result = {
            "label": "Clé privée de signature JWT (en mémoire)",
            "format": "PKCS#8 DER",
            "algorithm": signer.alg,
            "size_bytes": len(priv_der),
            "source": "idp/jwt_signer.py RSASigner (paire générée au démarrage de l'IdP)",
        }
    else:
        secret = signer._signer.export_secret_key()
        result = {
            "label": "Clé privée de signature JWT (en mémoire)",
            "format": "octets bruts liboqs",
            "algorithm": signer.alg,
            "size_bytes": len(secret),
            "source": "idp/jwt_signer.py PQCSigner (paire générée au démarrage de l'IdP)",
        }
    # Clé privée TLS réellement stockée (mêmes parametres, autre usage) --
    # fournie pour information, pour ne pas confondre échelle et usage.
    if idp_key_path.exists():
        pem = idp_key_path.read_bytes()
        result["tls_private_key_stored"] = {
            "path": str(idp_key_path.relative_to(BASE_DIR)),
            "format": "PKCS#8 PEM",
            "size_bytes": len(pem),
            "size_bytes_der": pem_der_size(pem),
        }
    return result


def measure_hqc_kem() -> dict:
    kem = oqs.KeyEncapsulation(KEM_ALG)
    try:
        pub = kem.generate_keypair()
        return {
            "label": "KEM HQC-1 (éphémère par session TLS)",
            "format": "octets bruts liboqs",
            "algorithm": KEM_ALG,
            "size_bytes": len(pub),
            "source": "oqs.KeyEncapsulation('HQC-1') -- clé de session TLS 1.3 (Groups=hqc1)",
        }
    finally:
        kem.free()


def measure_hqc_secret() -> dict:
    kem = oqs.KeyEncapsulation(KEM_ALG)
    try:
        kem.generate_keypair()
        secret = kem.export_secret_key()
        return {
            "label": "KEM HQC-1 (clé secrète, éphémère par session TLS)",
            "format": "octets bruts liboqs",
            "algorithm": KEM_ALG,
            "size_bytes": len(secret),
            "source": "oqs.KeyEncapsulation('HQC-1').export_secret_key()",
        }
    finally:
        kem.free()


def not_applicable(reason: str) -> dict:
    return {"not_applicable": True, "reason": reason}


def summarize(result: dict) -> str:
    items = result["items"]
    lines = [
        f"Métrique : {result['metric']} (mode {result['mode']}) -- unité : octets",
        f"Format certificats : {result['certificate_format']}",
        "",
        "Certificats :",
    ]
    for key in ("ca_certificate", "idp_certificate"):
        c = items[key]
        lines.append(f"  {result['titles'].get(key, key)}")
        lines.append(
            f"    - {c['label']} : {c['size_bytes']} B (DER) / "
            f"{c['size_bytes_pem']} B (PEM) "
            f"[{c['signature_algorithm']}]"
        )
    lines.append("")
    lines.append("Clés et KEM :")
    for key in ("signature_public_key", "signature_private_key", "kem_public_key", "kem_private_key"):
        v = items.get(key)
        if not v:
            continue
        title = result["titles"].get(key, key)
        if v.get("not_applicable"):
            lines.append(f"  {title} : non applicable -- {v['reason']}")
        else:
            b64 = f", B64url : {v['size_bytes_base64url']} B" if "size_bytes_base64url" in v else ""
            lines.append(
                f"  {title}\n"
                f"    - {v['label']} : {v['size_bytes']} B "
                f"({v['format']}, {v.get('algorithm', '')}){b64}"
            )
            stored = v.get("tls_private_key_stored")
            if stored:
                lines.append(
                    f"      - clé TLS stockée ({stored['path']}) : "
                    f"{stored['size_bytes']} B (PEM) / "
                    f"{stored['size_bytes_der']} B (DER)"
                )
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict:
    pki = pki_dir_for(args)
    ca_pem = pki / "ca" / "certs" / "ca.cert.pem"
    idp_pem = pki / "certs" / "idp.crt"
    idp_key = pki / "certs" / "idp.key"

    missing = [str(p.relative_to(BASE_DIR)) for p in (ca_pem, idp_pem, idp_key) if not p.exists()]
    if missing:
        raise FileNotFoundError(f"PKI incomplète pour le mode {args.mode!r} (chemin {pki}) : {missing}")

    signer = build_jwt_signer(args.mode, args)
    sig_pub = measure_signature_public_key(signer, args.mode)
    sig_priv = measure_signature_private_key(signer, args.mode, idp_key)

    items = {
        "ca_certificate": measure_certificate(ca_pem, "Certificat de la CA (autorité racine)"),
        "idp_certificate": measure_certificate(idp_pem, "Certificat TLS de l'IdP"),
        "signature_public_key": sig_pub,
        "signature_private_key": sig_priv,
    }

    if args.mode == "pqc":
        items["kem_public_key"] = measure_hqc_kem()
        items["kem_private_key"] = measure_hqc_secret()
    else:
        reason = (
            "TLS classique (RSA-3072/ECDH) utilise des éphémères ECDHE négociés "
            "à chaque session : aucune clé KEM n'est générée ni stockée. La "
            "comparaison directe des tailles de clés KEM ne concerne que le mode "
            "PQC (HQC-1, clés elles aussi éphémères mais de taille fixe)."
        )
        items["kem_public_key"] = not_applicable(reason)
        items["kem_private_key"] = not_applicable(reason)

    result = {
        "metric": "tailles_cryptographiques",
        "unit": "bytes",
        "mode": args.mode,
        "certificate_format": "DER (transmission TLS) / PEM (stockage disque)",
        "titles": {
            "ca_certificate": "1. Certificat CA",
            "idp_certificate": "2. Certificat de l'IdP",
            "signature_public_key": "3. Clé publique de signature",
            "signature_private_key": "4. Clé privée de signature",
            "kem_public_key": "5. Clé publique KEM",
            "kem_private_key": "6. Clé privée KEM",
        },
        "comparability_notes": [
            "Les certificats sont comparables dans leur forme DER (réseau) et PEM (disque).",
            "La clé publique de signature diffère : DER SPKI (RSA-3072) vs octets bruts "
            "liboqs (CROSS) ; la taille Base64url (JWKS) est fournie comme représentation "
            "réellement transmise.",
            "HQC-1 (2241/2321 B) et le groupe classique ECDHE sont des clés éphémères par "
            "session TLS 1.3, non synonymes de taille de certificat ni de clé persistante.",
        ],
        "items": items,
    }
    return result


if __name__ == "__main__":
    args = parse_args()
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\n=== RÉSUMÉ LISIBLE ===\n", file=sys.stderr)
    print(summarize(result), file=sys.stderr)