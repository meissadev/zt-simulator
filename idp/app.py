"""
IdP -- simulateur PQC-Zero Trust (phase classique par défaut, cf. CRYPTO_MODE).

Rôle (cf. architecture, chapitre 3) :
  1. Authentifie le sujet (vérification d'identifiants) -- étape distincte
     de l'émission du token, conforme à NIST SP 800-207.
  2. Émet un JWS (RSA-3072 en phase classique, PQC ensuite) porteur des
     claims nécessaires à l'autorisation par le PDP.
  3. Expose un endpoint JWKS-like pour que le PEP récupère la clé publique
     de vérification.

Ce fichier reste IDENTIQUE entre la phase classique et la phase PQC -- seul
jwt_signer.CRYPTO_MODE (via config.py) détermine le backend utilisé. C'est
volontaire : isoler l'algorithme comme unique variable du comparatif.

Authentification simplifiée par identifiants statiques (utilisateur/mot de
passe en mémoire) : suffisant pour un prototype de recherche centré sur la
migration PQC, pas sur la robustesse d'un mécanisme d'authentification
utilisateur -- à documenter comme simplification assumée en 4.8.
"""

import logging
import os
import ssl
import time

from flask import Flask, jsonify, request
from werkzeug.serving import run_simple

import config
import jwt_signer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [idp] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Base d'utilisateurs simulée (démonstration uniquement) ---------------
# À NE PAS utiliser tel quel hors contexte de prototype de recherche :
# mots de passe en clair, pas de hachage, pas de verrouillage de compte.
USERS = {
    "alice": {"password": "demo123", "role": "engineer", "device_id": "laptop-01"},
    "bob": {"password": "demo123", "role": "auditor", "device_id": "laptop-02"},
}


def build_signer():
    """Instancie le signataire selon CRYPTO_MODE (classique ou PQC)."""
    if config.CRYPTO_MODE == "classical":
        logger.info("Backend de signature : RSA-%s", config.RSA_KEY_SIZE)
        return jwt_signer.RSASigner(key_size=config.RSA_KEY_SIZE, kid=config.SIGNING_KID)
    elif config.CRYPTO_MODE == "pqc":
        logger.info("Backend de signature : %s (post-quantique)", config.PQC_SIG_ALG)
        return jwt_signer.PQCSigner(alg=config.PQC_SIG_ALG, kid=config.SIGNING_KID)
    else:
        raise ValueError(f"CRYPTO_MODE inconnu : {config.CRYPTO_MODE!r} (attendu 'classical' ou 'pqc')")


# --- Paire de clés de signature, générée une fois au démarrage -----------
signer = build_signer()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "idp", "crypto_mode": config.CRYPTO_MODE, "alg": signer.alg})


@app.route("/authenticate", methods=["POST"])
def authenticate():
    """
    Authentifie le sujet par identifiants et, si valide, émet un JWS.

    Requête attendue : {"username": "...", "password": "..."}
    Réponse : {"access_token": "...", "token_type": "JWS", "expires_in": N}
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")

    user = USERS.get(username)

    # --- Étape 1 : authentification (vérification d'identifiants) -------
    if user is None or user["password"] != password:
        logger.info("Échec d'authentification pour '%s'", username)
        return jsonify({"error": "invalid_credentials"}), 401

    logger.info("Authentification réussie pour '%s'", username)

    # --- Étape 2 : émission du JWS ---------------------------------------
    now = int(time.time())
    claims = {
        "iss": config.ISSUER,
        "sub": username,
        "iat": now,
        "nbf": now,
        "exp": now + config.TOKEN_TTL_SECONDS,
        "role": user["role"],
        "device_id": user["device_id"],
    }

    token = jwt_signer.create_jwt(claims, signer)

    return jsonify({
        "access_token": token,
        "token_type": "JWS",
        "expires_in": config.TOKEN_TTL_SECONDS,
    })


@app.route("/jwks", methods=["GET"])
def jwks():
    """
    Expose la clé publique de vérification.

    Structure inspirée de JWKS (RFC 7517) mais non conforme au registre
    IANA dès que CRYPTO_MODE=pqc (algorithme hors registre) -- documenté
    et assumé comme extension.
    """
    return jsonify({
        "keys": [
            {
                "kid": signer.kid,
                "alg": signer.alg,
                "use": "sig",
                "pub": signer.public_key_b64url(),
            }
        ]
    })


def build_ssl_context() -> ssl.SSLContext:
    """
    Contexte TLS du service IdP lui-même. Pas de mTLS exigé ici : les
    utilisateurs s'authentifient par identifiants, pas par certificat
    client -- seul le certificat serveur (émis par la CA du projet) est
    présenté.

    En phase PQC, cf. note déjà documentée dans ressource/app.py concernant
    OPENSSL_CONF, nécessaire pour que le module ssl négocie effectivement
    des algorithmes post-quantiques.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=config.IDP_TLS_CERT, keyfile=config.IDP_TLS_KEY)
    return context


if __name__ == "__main__":
    for path, label in [
        (config.IDP_TLS_CERT, "certificat TLS de l'IdP"),
        (config.IDP_TLS_KEY, "clé privée TLS de l'IdP"),
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{label} introuvable : {path}\n"
                f"Exécutez d'abord pki/scripts/issue_cert.sh idp"
            )

    ssl_context = build_ssl_context()

    logger.info(
        "Démarrage de l'IdP sur https://%s:%s (issuer=%s, mode=%s, alg=%s)",
        config.HOST, config.PORT, config.ISSUER, config.CRYPTO_MODE, signer.alg,
    )
    run_simple(config.HOST, config.PORT, app, ssl_context=ssl_context, threaded=True)