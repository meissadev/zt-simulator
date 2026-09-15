# Simulateur PQC-Zero Trust

Architecture Zero Trust (NIST SP 800-207) avec cryptographie post-quantique
a base de codes correcteurs d'erreurs : **HQC** pour le KEM TLS,
**CROSS** (rsdp-128-balanced) pour les signatures (certificats + JWT),
comparee a une baseline classique **RSA-3072**.

## Architecture

```
                        Plan de controle
                  +--------------------------+
                  |  PDP (OPA, port 8181)    |
                  |  Rego : authz.rego       |
                  +-----+--------------------+
                        |
        Sujet     PEP (port 8443)      Ressource (port 8446)
        ----->  [mTLS opt. + JWT]  --mTLS-->  [mTLS requis]
                        |
                  IdP (port 8444)
                  [auth + JWS]
```

- **PEP** : point de controle unique (fail-closed), authentification
  (mTLS ou JWT Bearer), delegation au PDP, relais mTLS vers la Ressource.
- **IdP** : authentifie l'utilisateur, emet un JWS (RSA ou CROSS selon
  `CRYPTO_MODE`), expose `/jwks`.
- **PDP** : OPA avec `default allow := false`, PA/PE fusionnes
  (limitation documentee).
- **Ressource** : microservice protege, exige mTLS, ne reevalue jamais
  d'autorisation.

## Prerequis

- Ubuntu 24.04 avec OpenSSL 3.x + oqs-provider installe
- liboqs-python dans le venv
- OPA 1.x (binaire `./opa` a la racine)
- bind9 avec zone `ztpqc.lab` (enregistrements : idp, pep, ressource,
  ca -> 192.168.60.133)

## Installation rapide

```bash
cd ~/zt-simulator
source venv/bin/activate
pip install -r requirements.txt
```

## Verification des algorithmes disponibles

```bash
bash pki/scripts/00_check_algorithms.sh
```

Doit confirmer :
- OpenSSL KEM : `hqc1` / Signature : `CROSSrsdp128balanced`
- liboqs-python KEM : `HQC-1` / Signature : `cross-rsdp-128-balanced`

## Generation de la PKI

### PKI classique (RSA-3072)

```bash
# CA
bash pki/scripts/generate_ca.sh rsa:3072 pki

# Certificats feuille
bash pki/scripts/issue_cert.sh idp rsa:3072 pki
bash pki/scripts/issue_cert.sh pep rsa:3072 pki
bash pki/scripts/issue_cert.sh ressource rsa:3072 pki
bash pki/scripts/issue_cert.sh batch-service rsa:3072 pki
```

### PKI post-quantique (CROSS)

```bash
# CA
bash pki/scripts/generate_ca.sh CROSSrsdp128balanced pki-pqc

# Certificats feuille
bash pki/scripts/issue_cert.sh idp CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh pep CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh ressource CROSSrsdp128balanced pki-pqc
bash pki/scripts/issue_cert.sh batch-service CROSSrsdp128balanced pki-pqc
```

## Lancement des services

### Phase classique (RSA-3072)

Lancer dans cet ordre, chacun dans un terminal separe :

```bash
# 1. PDP (OPA)
./opa run --server \
    --config-file pdp/opa_config.yaml \
    pdp/policies/ \
    --addr :8181

# 2. Ressource
cd ressource
PKI_DIR=../pki python app.py

# 3. IdP
cd idp
CRYPTO_MODE=classical PKI_DIR=../pki python app.py

# 4. PEP
cd pep
CRYPTO_MODE=classical PKI_DIR=../pki \
    EXPECTED_JWT_ALG=RSA3072-PSS-SHA384 \
    python app.py
```

### Phase PQC (CROSS + HQC)

```bash
# 1. PDP (OPA) -- meme commande, pas de crypto ici
./opa run --server \
    --config-file pdp/opa_config.yaml \
    pdp/policies/ \
    --addr :8181

# 2. Ressource (avec OPENSSL_CONF pour forcer HQC en TLS)
cd ressource
OPENSSL_CONF=$(pwd)/openssl_pqc.cnf PKI_DIR=../pki-pqc python app.py

# 3. IdP
cd idp
CRYPTO_MODE=pqc PQC_SIG_ALG=cross-rsdp-128-balanced \
    PKI_DIR=../pki-pqc \
    OPENSSL_CONF=$(pwd)/../ressource/openssl_pqc.cnf \
    python app.py

# 4. PEP
cd pep
PKI_DIR=../pki-pqc \
    EXPECTED_JWT_ALG=cross-rsdp-128-balanced \
    OPENSSL_CONF=$(pwd)/../ressource/openssl_pqc.cnf \
    python app.py
```

**Important** : `OPENSSL_CONF` doit etre defini AVANT le lancement de
chaque service Python pour que le module `ssl` negocie HQC en TLS 1.3.
Le fichier `openssl_pqc.cnf` fixe `Groups = hqc1` (sans repli classique,
pour des mesures strictement PQC).

## Tests manuels rapides

```bash
# Authentification (JWT)
curl -sk https://idp.ztpqc.lab:8444/health
curl -sk -X POST https://idp.ztpqc.lab:8444/authenticate \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"demo123"}' \
    --cacert pki/ca/certs/ca.cert.pem

# Acces via PEP (Bearer token)
TOKEN=$(curl -sk -X POST https://idp.ztpqc.lab:8444/authenticate \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"demo123"}' \
    --cacert pki/ca/certs/ca.cert.pem | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -sk https://pep.ztpqc.lab:8443/api/data \
    -H "Authorization: Bearer $TOKEN" \
    --cacert pki/ca/certs/ca.cert.pem

# Acces via PEP (mTLS service-to-service)
curl -sk https://pep.ztpqc.lab:8443/api/data \
    --cert pki/certs/batch-service.crt \
    --key pki/certs/batch-service.key \
    --cacert pki/ca/certs/ca.cert.pem

# Tests Rego
./opa test pdp/policies/ -v
```

## Ports

| Service    | Port | Protocole        |
|------------|------|------------------|
| PEP        | 8443 | HTTPS (mTLS opt) |
| IdP        | 8444 | HTTPS            |
| Ressource  | 8446 | HTTPS (mTLS req) |
| PDP (OPA)  | 8181 | HTTP             |

## Limitations documentees

- **Werkzeug** : serveur de developpement, pas de production.
- **PA/PE fusionnes** : pas de composant PA separe (architecture simplifiee).
- **JWS hors registre IANA** : l'algorithme CROSS n'a pas d'identifiant IANA
  (extension assumee, documentee dans le memoire).
- **Utilisateurs statiques** : identifiants en memoire (prototype de recherche).

## Arborescence

```
zt-simulator/
  venv/
  pki/                        # PKI classique (RSA-3072)
    scripts/
      00_check_algorithms.sh
      generate_ca.sh
      issue_cert.sh
    ca/
    certs/
  pki-pqc/                    # PKI post-quantique (CROSS)
    ca/
    certs/
  idp/
    app.py, config.py, jwt_signer.py, requirements.txt
  pep/
    app.py, config.py, jwks_client.py, pdp_client.py,
    mtls_handler.py, jwt_signer.py, requirements.txt
  pdp/
    policies/authz.rego, authz_test.rego
    opa_config.yaml
  ressource/
    app.py, openssl_pqc.cnf, requirements.txt
  README.md
```
