"""
pdp_client.py -- interrogation du PDP (OPA) pour la décision d'autorisation.

Le PEP ne réévalue jamais de politique lui-même : il transmet le contexte
(identité authentifiée + requête) et applique la décision retournée,
conformément à la séparation PEP/PDP de NIST SP 800-207.
"""

import logging

import requests

import config

logger = logging.getLogger(__name__)

# Session réutilisée globale pour les appels au PDP
_pdp_session = requests.Session()

# Configure TCP_NODELAY pour éviter les délais de Nagle
_pdp_session.mount('http://', requests.adapters.HTTPAdapter())
_pdp_session.mount('https://', requests.adapters.HTTPAdapter())


class PDPError(Exception):
    pass


def evaluate(subject: dict, resource_path: str, method: str) -> bool:
    """
    Interroge OPA et retourne True (Allow) ou False (Deny).

    Toute erreur réseau/timeout lève PDPError -- à traiter comme un refus
    par défaut côté appelant (fail-closed : "never trust, always verify"
    implique qu'une absence de décision positive explicite équivaut à
    un refus, jamais à un accès implicite).
    """
    payload = {
        "input": {
            "subject": subject,
            "resource": resource_path,
            "method": method,
        }
    }
    try:
        response = _pdp_session.post(config.OPA_URL, json=payload, timeout=config.OPA_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise PDPError(f"Échec d'appel au PDP : {exc}") from exc

    result = response.json().get("result")
    return bool(result)