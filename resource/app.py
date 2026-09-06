"""
Ressource -- microservice protégé du simulateur PQC-Zero Trust.

Ce service ne réévalue jamais d'autorisation : il fait confiance à la
décision déjà rendue par le PDP et relayée par le PEP (séparation des
responsabilités selon NIST SP 800-207). Il exige néanmoins un certificat
client valide (mTLS post-quantique) émis par la CA du projet, en défense
en profondeur -- seul le PEP doit posséder un tel certificat.
"""

import os
import ssl
import logging

from flask import Flask, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ressource] %(message)s")
logger = logging.getLogger(__name__)

# --- Configuration (surchargeable via variables d'environnement) ---------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.environ.get("PKI_DIR", os.path.join(BASE_DIR, "..", "pki"))

CERT_FILE = os.environ.get("RESOURCE_CERT", os.path.join(PKI_DIR, "certs", "resource.crt"))
KEY_FILE = os.environ.get("RESOURCE_KEY", os.path.join(PKI_DIR, "certs", "resource.key"))
CA_FILE = os.environ.get("CA_CERT", os.path.join(PKI_DIR, "ca", "certs", "ca.cert.pem"))

HOST = os.environ.get("RESOURCE_HOST", "0.0.0.0")
PORT = int(os.environ.get("RESOURCE_PORT", "8446"))

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Endpoint non protégé (utile pour un check de liveness/orchestrateur)."""
    return jsonify({"status": "ok", "service": "ressource"})


@app.route("/api/data", methods=["GET"])
def get_data():
    """
    Endpoint simulant une ressource applicative protégée.

    N'est atteint que si le PEP a déjà validé mTLS et/ou JWT et obtenu
    une décision Allow du PDP -- ce service ne fait qu'exécuter, pas
    décider (cf. NIST SP 800-207, séparation PEP/PDP).
    """
    peer_cn = request.environ.get("SSL_CLIENT_CN", "inconnu")
    logger.info("Accès à /api/data -- certificat client CN=%s", peer_cn)
    return jsonify({
        "resource": "donnees-sensibles",
        "message": "Accès autorisé via PQC-Zero Trust",
        "served_by": "ressource",
        "client_cn": peer_cn,
    })


class PeerCertRequestHandler(WSGIRequestHandler):
    """
    Handler WSGI étendu pour exposer le CN du certificat client mTLS dans
    l'environnement WSGI (clé SSL_CLIENT_CN), à des fins d'audit/logging
    -- défense en profondeur, pas une décision d'autorisation.

    ATTENTION -- "SSL_CLIENT_CN" (ci-dessous, dans request.environ) n'a
    aucun rapport avec os.environ (variables d'environnement système, cf.
    config.py) : c'est une clé ajoutée par CE CODE dans le dictionnaire
    WSGI propre à chaque requête, pas une variable d'environnement, ni un
    standard WSGI/CGI officiel (le nom imite juste la convention Apache
    mod_ssl pour rester lisible).
    """

    def make_environ(self):
        environ = super().make_environ()
        peer_cert = self.connection.getpeercert()
        if peer_cert:
            subject = dict(x[0] for x in peer_cert.get("subject", []))
            environ["SSL_CLIENT_CN"] = subject.get("commonName", "inconnu")
        return environ


def build_ssl_context() -> ssl.SSLContext:
    """
    Construit un contexte TLS exigeant un certificat client (mTLS),
    validé contre la CA post-quantique du projet.

    Note d'implémentation importante : pour que la négociation TLS utilise
    effectivement un groupe d'échange de clé KEM post-quantique et une
    signature CROSS, OpenSSL doit charger oqs-provider par défaut --
    typiquement via la variable d'environnement OPENSSL_CONF pointant vers
    un fichier de configuration qui active le provider (cf. openssl_pqc.cnf
    fourni à côté de ce script). Le module ssl standard de Python n'offre
    pas d'API pour charger un provider programmatiquement ; il dépend donc
    de la configuration OpenSSL globale du système. À vérifier concrètement
    sur l'instance EC2 (ex. avec `openssl s_client` en parallèle).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.load_verify_locations(cafile=CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


if __name__ == "__main__":
    for path, label in [
        (CERT_FILE, "certificat de la ressource"),
        (KEY_FILE, "clé privée de la ressource"),
        (CA_FILE, "certificat de la CA"),
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{label} introuvable : {path}\n"
                f"Exécutez d'abord pki/scripts/issue_cert.sh ressource"
            )

    ssl_context = build_ssl_context()

    logger.info("Démarrage du service Ressource sur https://%s:%s (mTLS requis)", HOST, PORT)
    run_simple(
        HOST,
        PORT,
        app,
        ssl_context=ssl_context,
        request_handler=PeerCertRequestHandler,
        threaded=True,
    )