"""
jwt_signer.py -- JWS avec structure JWT-compatible, backend cryptographique
interchangeable (RSA classique ou signature post-quantique).

Objectif méthodologique : garder EXACTEMENT la même structure de token, le
même flux de création/vérification et le même code applicatif (app.py) entre
la phase classique et la phase PQC -- seul le signataire (Signer) change.
Ça isole la variable étudiée (l'algorithme de signature) de tout artefact
d'implémentation, cohérent avec le principe déjà appliqué au niveau TLS
(même stack OpenSSL+oqs-provider pour toutes les mesures).

JWS uniquement (pas JWE) : la confidentialité est assurée par le canal TLS
sous-jacent, cf. justification déjà actée.
"""

import base64
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import oqs


# --- Encodage --------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """Encode en Base64url sans padding (conforme RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Décode du Base64url sans padding."""
    padding_needed = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding_needed)


# --- Signataires (interface commune : .alg, .kid, .sign(), .public_key_b64url()) ---

class RSASigner:
    """
    Backend classique -- RSA-3072, padding PSS, hachage SHA-384.
    Sert de baseline de comparaison face aux signatures post-quantiques.
    """

    def __init__(self, key_size: int = 3072, kid: str = "idp-key-1"):
        self.alg = f"RSA{key_size}-PSS-SHA384"
        self.kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self._public_key = self._private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA384(),
        )

    def public_key_bytes(self) -> bytes:
        """Clé publique encodée en DER (SubjectPublicKeyInfo)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_key_b64url(self) -> str:
        return b64url_encode(self.public_key_bytes())


class PQCSigner:
    """
    Backend post-quantique (ex. Dilithium3, Falcon512...) via liboqs-python.

    L'instance oqs.Signature conserve la clé privée en mémoire après
    generate_keypair() -- doit rester vivante toute la durée de vie du
    processus IdP.
    """

    def __init__(self, alg: str = "Dilithium3", kid: str = "idp-key-1"):
        self.alg = alg
        self.kid = kid
        self._signer = oqs.Signature(alg)
        self._public_key: bytes = self._signer.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    def public_key_bytes(self) -> bytes:
        return self._public_key

    def public_key_b64url(self) -> str:
        return b64url_encode(self.public_key_bytes())


# --- Vérification, dispatch par famille d'algorithme ------------------------

def _verify_rsa(message: bytes, signature: bytes, public_key_der: bytes) -> bool:
    public_key = serialization.load_der_public_key(public_key_der)
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA384(),
        )
        return True
    except InvalidSignature:
        return False


def _verify_pqc(alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature(alg) as verifier:
        return verifier.verify(message, signature, public_key)


def _verify_signature(alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Dispatch vers le bon backend selon le préfixe de l'identifiant alg."""
    if alg.startswith("RSA"):
        return _verify_rsa(message, signature, public_key)
    return _verify_pqc(alg, message, signature, public_key)


# --- Création / vérification de token (indépendant du backend) -------------

def create_jwt(claims: dict, signer) -> str:
    """
    Construit un JWS : header.payload.signature (Base64url), structure
    conforme à RFC 7515/7519. L'algorithme (RSA ou PQC) est hors registre
    IANA dans le cas PQC -- documenté et assumé.
    """
    header = {"alg": signer.alg, "typ": "JWT", "kid": signer.kid}

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature_b64 = b64url_encode(signer.sign(signing_input))

    return f"{header_b64}.{payload_b64}.{signature_b64}"


@dataclass
class DecodedToken:
    header: dict
    payload: dict


def decode_unverified(token: str) -> DecodedToken:
    """
    Décode header + payload SANS vérifier la signature. Utile pour
    extraire "iss" avant de choisir quelle clé publique récupérer.
    Ne jamais faire confiance à ces claims avant vérification.
    """
    try:
        header_b64, payload_b64, _sig_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("Format de token invalide (3 segments attendus)") from exc

    return DecodedToken(
        header=json.loads(b64url_decode(header_b64)),
        payload=json.loads(b64url_decode(payload_b64)),
    )


def verify_jwt(token: str, public_key: bytes, alg: str) -> dict:
    """
    Vérifie la signature et les claims temporelles (exp/nbf) d'un JWS.
    Retourne le payload si valide, lève ValueError sinon.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("Format de token invalide (3 segments attendus)") from exc

    header = json.loads(b64url_decode(header_b64))
    if header.get("alg") != alg:
        raise ValueError(f"Algorithme inattendu : {header.get('alg')} (attendu {alg})")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = b64url_decode(signature_b64)

    if not _verify_signature(alg, signing_input, signature, public_key):
        raise ValueError("Signature invalide")

    payload = json.loads(b64url_decode(payload_b64))

    now = int(time.time())
    if "exp" in payload and now >= payload["exp"]:
        raise ValueError("Token expiré")
    if "nbf" in payload and now < payload["nbf"]:
        raise ValueError("Token pas encore valide (nbf)")

    return payload