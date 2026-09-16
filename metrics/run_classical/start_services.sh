#!/usr/bin/env bash
set -e
ROOT=/home/meissa/zt-simulator
VENV=$ROOT/venv/bin/python
LOG_DIR=$ROOT/metrics/run_classical/logs

for port in 8443 8444 8446; do
    pid=$(ss -tlnp 2>/dev/null | grep ":$port " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
done
sleep 1

# Phase classique : AUCUN OPENSSL_CONF (défaut système = Groups = x25519:P-256)
# 1. Ressource
(cd "$ROOT/ressource" && setsid env PKI_DIR=../pki $VENV app.py </dev/null >"$LOG_DIR/ressource.log" 2>&1) &

# 2. IdP
(cd "$ROOT/idp" && setsid env CRYPTO_MODE=classical PKI_DIR=../pki $VENV app.py </dev/null >"$LOG_DIR/idp.log" 2>&1) &

# 3. PEP
(cd "$ROOT/pep" && setsid env CRYPTO_MODE=classical PKI_DIR=../pki \
    EXPECTED_JWT_ALG=RSA3072-PSS-SHA384 $VENV app.py </dev/null >"$LOG_DIR/pep.log" 2>&1) &

sleep 4
echo "Services classiques lancés."
for port in 8443 8444 8446; do
    ss -tlnp 2>/dev/null | grep ":$port " && echo "  :$port OK" || echo "  :$port FAILED"
done