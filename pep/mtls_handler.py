"""
mtls_handler.py -- contextes TLS pour le PEP.

Deux directions distinctes :
  - Entrant (serveur) : le PEP accepte les connexions du Sujet. Certificat
    client OPTIONNEL -- présent pour un flux mTLS service-to-service,
    absent pour un utilisateur humain authentifié par JWT.
  - Sortant (client) : le PEP présente SON PROPRE certificat en mTLS quand
    il relaie la requête vers la Ressource (flux d'accès).
"""

import ssl

import config


def build_server_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=config.PEP_TLS_CERT, keyfile=config.PEP_TLS_KEY)
    context.load_verify_locations(cafile=config.CA_CERT)
    context.verify_mode = ssl.CERT_OPTIONAL
    return context


def resource_client_cert() -> tuple:
    """Cert/clé que le PEP présente lui-même en mTLS vers la Ressource."""
    return (config.PEP_TLS_CERT, config.PEP_TLS_KEY)