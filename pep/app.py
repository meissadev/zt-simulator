"""
PEP -- Policy Enforcement Point du simulateur Zero Trust.

Point de contrôle unique, à la frontière entre le Sujet et le reste de
l'architecture : intercepte toute requête, valide l'authentification
(mTLS pour un service, JWT pour un utilisateur), interroge le PDP pour la
décision d'autorisation, et ne relaie la requête vers la Ressource qu'en
cas de décision positive -- jamais l'inverse (fail-closed).

Trois étapes strictement séquentielles et jamais court-circuitées :
  1. authenticate_request()  -- validation cryptographique uniquement
  2. pdp_client.evaluate()   -- décision d'autorisation, déléguée au PDP
  3. relais mTLS vers la Ressource -- flux d'accès
"""

import logging
import os

import requests
from flask import Flask, Response, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

import config
import jwks_client
import jwt_signer
import mtls_handler
import pdp_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pep] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)


class PeerCertRequestHandler(WSGIRequestHandler):
    """Expose le certificat client (s'il existe) dans l'environnement WSGI."""

    def make_environ(self):
        environ = super().make_environ()
        peer_cert = self.connection.getpeercert()
        if peer_cert:
            subject = dict(x[0] for x in peer_cert.get("subject", []))
            environ["SSL_CLIENT_CN"] = subject.get("commonName")
        else:
            environ["SSL_CLIENT_CN"] = None
        return environ


class AuthenticationError(Exception):
    """Échec de l'étape 1 (authentification) -- distinct d'un refus d'autorisation."""


def authenticate_request() -> dict:
    """
    Étape 1 : authentification -- validation cryptographique uniquement.
    AUCUN appel au PDP ici : on ne fait que prouver une identité, pas
    encore statuer sur un droit d'accès (séparation des responsabilités,
    cf. NIST SP 800-207).

    Retourne un dict de claims/attributs si succès. Lève
    AuthenticationError sinon.
    """
    peer_cn = request.environ.get("SSL_CLIENT_CN")

    # --- Cas 1 : mTLS (service-to-service) ----------------------------------
    if peer_cn:
        logger.info("Authentification mTLS réussie (CN=%s)", peer_cn)
        return {"auth_method": "mtls", "service_id": peer_cn}

    # --- Cas 2 : JWT (utilisateur-service) ------------------------------------
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]

        try:
            decoded = jwt_signer.decode_unverified(token)
        except ValueError as exc:
            raise AuthenticationError(f"Token mal formé : {exc}") from exc

        issuer = decoded.payload.get("iss")
        kid = decoded.header.get("kid")
        alg = decoded.header.get("alg")

        # Algorithme fixé côté PEP (pas déduit aveuglément du header) --
        # évite une attaque par confusion d'algorithme.
        if alg != config.EXPECTED_JWT_ALG:
            raise AuthenticationError(f"Algorithme non autorisé : {alg!r}")

        # Vérification de l'issuer AVANT tout appel réseau (mitigation SSRF).
        if issuer not in config.TRUSTED_ISSUERS:
            raise AuthenticationError(f"Issuer non approuvé : {issuer!r}")

        try:
            public_key, jwks_alg = jwks_client.get_verification_key(issuer, kid)
        except (jwks_client.UntrustedIssuerError, jwks_client.JWKSFetchError) as exc:
            raise AuthenticationError(str(exc)) from exc

        if jwks_alg != alg:
            raise AuthenticationError("Incohérence d'algorithme entre le token et le JWKS")

        try:
            claims = jwt_signer.verify_jwt(token, public_key, alg)
        except ValueError as exc:
            raise AuthenticationError(str(exc)) from exc

        logger.info("Authentification JWT réussie (sub=%s)", claims.get("sub"))
        return {"auth_method": "jwt", **claims}

    # --- Aucun credential fourni ------------------------------------------------
    raise AuthenticationError("Aucune preuve d'authentification fournie (ni mTLS ni Bearer token)")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "pep"})


@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(subpath):
    # --- Étape 1 : authentification -------------------------------------------
    try:
        subject = authenticate_request()
    except AuthenticationError as exc:
        logger.warning("Authentification refusée : %s", exc)
        return jsonify({"error": "authentication_failed", "detail": str(exc)}), 401

    # --- Étape 2 : autorisation (délégation stricte au PDP) --------------------
    try:
        allowed = pdp_client.evaluate(subject, "/" + subpath, request.method)
    except pdp_client.PDPError as exc:
        logger.error("PDP injoignable, refus par défaut (fail-closed) : %s", exc)
        return jsonify({"error": "pdp_unreachable"}), 503

    if not allowed:
        logger.info("Accès refusé par le PDP (subject=%s, resource=/%s)", subject.get("sub", subject.get("service_id")), subpath)
        return jsonify({"error": "access_denied"}), 403

    # --- Étape 3 : flux d'accès, relayé en mTLS vers la Ressource --------------
    target_url = config.RESOURCE_BASE_URL.rstrip("/") + "/" + subpath
    forwarded_headers = {k: v for k, v in request.headers if k.lower() not in ("host", "content-length")}

    try:
        upstream = requests.request(
            method=request.method,
            url=target_url,
            headers=forwarded_headers,
            data=request.get_data(),
            cert=mtls_handler.resource_client_cert(),
            verify=config.CA_CERT,
            timeout=config.RESOURCE_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        logger.error("Échec de relais mTLS vers la Ressource : %s", exc)
        return jsonify({"error": "resource_unreachable"}), 502

    return Response(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "application/json"),
    )


if __name__ == "__main__":
    for path, label in [
        (config.PEP_TLS_CERT, "certificat TLS du PEP"),
        (config.PEP_TLS_KEY, "clé privée TLS du PEP"),
        (config.CA_CERT, "certificat de la CA"),
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{label} introuvable : {path}\nExécutez d'abord pki/scripts/issue_cert.sh pep"
            )

    ssl_context = mtls_handler.build_server_ssl_context()

    logger.info("Démarrage du PEP sur https://%s:%s", config.HOST, config.PORT)
    run_simple(
        config.HOST,
        config.PORT,
        app,
        ssl_context=ssl_context,
        request_handler=PeerCertRequestHandler,
        threaded=True,
    )