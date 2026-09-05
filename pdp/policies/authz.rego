# authz.rego
#
# Politique d'autorisation du PDP (Policy Engine, via OPA).
#
# Le PEP transmet un document "input" de la forme :
#   {
#     "subject": { ... claims JWT, ou {"auth_method": "mtls", "service_id": ...} },
#     "resource": "/api/data",
#     "method": "GET"
#   }
#
# Ce module ne fait AUCUNE vérification cryptographique -- l'authentification
# (signature JWT, chaîne mTLS) est déjà validée par le PEP avant cet appel
# (séparation des responsabilités, NIST SP 800-207). Les rôles ("engineer",
# "auditor") correspondent à ceux définis dans idp/app.py (USERS).

package authz

import rego.v1

default allow := false

# --- Service-to-service (mTLS) ---------------------------------------------
# Un service authentifié par certificat (déjà validé par le PEP) peut lire
# les ressources applicatives. Accès en écriture volontairement exclu par
# défaut ici -- à étendre avec une liste explicite de services de confiance
# si un scénario d'écriture service-to-service est nécessaire.
allow if {
	input.subject.auth_method == "mtls"
	input.method == "GET"
}

# --- Utilisateur "engineer" (JWT) -------------------------------------------
# Accès complet (lecture/écriture) aux ressources applicatives.
allow if {
	input.subject.auth_method == "jwt"
	input.subject.role == "engineer"
	startswith(input.resource, "/api/")
}

# --- Utilisateur "auditor" (JWT) --------------------------------------------
# Accès en lecture seule -- illustre une politique d'autorisation
# différenciée par rôle, au-delà de la simple authentification.
allow if {
	input.subject.auth_method == "jwt"
	input.subject.role == "auditor"
	input.method == "GET"
	startswith(input.resource, "/api/")
}
