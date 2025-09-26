#!/usr/bin/env bash
# NovaShield Installation Module: Security Setup
# This module handles key generation, TLS setup, and security configuration

generate_keys(){
  if [ ! -f "${NS_KEYS}/private.pem" ] || [ ! -f "${NS_KEYS}/public.pem" ]; then
    ns_log "Generating RSA keypair"
    openssl genpkey -algorithm RSA -out "${NS_KEYS}/private.pem" -pkcs8 2>/dev/null
    openssl rsa -pubout -in "${NS_KEYS}/private.pem" -out "${NS_KEYS}/public.pem" 2>/dev/null
  fi
  
  if [ ! -f "${NS_KEYS}/aes.key" ]; then
    ns_log "Generating AES key file: keys/aes.key"
    openssl rand -hex 32 > "${NS_KEYS}/aes.key" 2>/dev/null
  fi
}

generate_self_signed_tls(){
  local cert="${NS_KEYS}/tls.crt"
  local key="${NS_KEYS}/tls.key"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    ns_log "Generating self-signed TLS certificate"
    openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" \
      -days 3650 -nodes -subj "/CN=localhost" 2>/dev/null || true
  fi
}

ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)
  if [ "$have_user" = "yes" ]; then return 0; fi
  
  # Handle non-interactive mode and automated startup scenarios
  if [ "${NS_NON_INTERACTIVE:-}" = "1" ] || [ ! -t 0 ] || [ "${NOVASHIELD_AUTO_START:-}" = "1" ]; then
    ns_warn "Non-interactive mode or automated startup: Skipping user creation. You can add users later with --add-user"
    ns_warn "Note: Authentication is enabled but no users exist. Web access will be blocked until users are added."
    return 0
  fi
  
  echo
  ns_warn "No web users found but auth_enabled is true. Creating the first user."
  add_user
  echo
  read -r -p "Enable 2FA for this user now? [y/N]: " yn
  case "$yn" in [Yy]*) enable_2fa ;; esac
}

# Export functions
export -f generate_keys generate_self_signed_tls ensure_auth_bootstrap 2>/dev/null || true