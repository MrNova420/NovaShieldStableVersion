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
  if [ "$have_user" = "yes" ]; then 
    # Show existing user count for security awareness
    local user_count
    user_count=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print(len(ud))
PY
)
    ns_log "🔐 Security Status: $user_count user(s) configured for dashboard access"
    return 0
  fi
  
  # Enhanced automated setup with fallback to manual creation
  if [ "${NS_NON_INTERACTIVE:-}" = "1" ] || [ ! -t 0 ] || [ "${NOVASHIELD_AUTO_START:-}" = "1" ]; then
    ns_warn "🔒 SECURITY NOTICE: Authentication enabled but no users exist"
    ns_warn "💡 Dashboard access is BLOCKED until users are created"
    ns_warn "📋 Run './novashield.sh --add-user' to create your first admin user"
    ns_warn "📊 Or set NS_AUTO_USER=1 environment variable for automated demo user creation"
    
    # Check for automated demo user creation
    if [ "${NS_AUTO_USER:-}" = "1" ]; then
      ns_log "🤖 Creating automated demo user (admin/NovaShield123)"
      ns_warn "⚠️  SECURITY: Change default credentials immediately after installation!"
      create_demo_user
    fi
    return 0
  fi
  
  # Interactive user creation with enhanced security prompts
  echo
  ns_warn "🔐 SECURITY REQUIREMENT: Dashboard authentication is enabled"
  ns_warn "📋 No authorized users found - creating your first admin account"
  echo
  ns_log "This is a one-time security setup to protect your NovaShield dashboard."
  ns_log "Your dashboard will be inaccessible until this user is created."
  echo
  
  # Show current security status
  ns_log "🛡️  Current Security Status:"
  ns_log "   • Authentication: ENABLED"
  ns_log "   • 2FA: Available (optional)"
  ns_log "   • Dashboard Access: BLOCKED (no users)"
  ns_log "   • User Count: 0"
  echo
  
  if add_user; then
    echo
    read -r -p "Enable 2FA for enhanced security? [Y/n]: " yn
    case "$yn" in 
      [Nn]*) ns_log "2FA skipped - you can enable it later with --enable-2fa" ;;
      *) enable_2fa ;;
    esac
    
    # Show final security status
    echo
    ns_ok "✅ Security setup complete!"
    ns_log "🔓 Dashboard access is now enabled for authorized users"
    ns_log "🌐 Access your dashboard at: https://localhost:8765"
  else
    ns_err "❌ Failed to create user - dashboard access remains blocked"
    ns_err "💡 Run './novashield.sh --add-user' manually after installation"
  fi
}

# Function to create automated demo user for non-interactive setups
create_demo_user() {
  local user="admin"
  local pass="NovaShield123"
  local salt
  
  # Get auth salt
  salt=$(awk -F': ' '/auth_salt:/ {print $2}' "$NS_CONF" 2>/dev/null | tr -d ' "' | head -1)
  
  if [ -z "$salt" ] || [ "$salt" = "change-this-salt" ] || [ ${#salt} -lt 16 ]; then
    ns_err "SECURITY ERROR: Authentication salt not properly configured!"
    return 1
  fi
  
  # Create demo user account
  local sha; sha=$(printf '%s' "${salt}:${pass}" | sha256sum | awk '{print $1}')
  if [ ! -f "$NS_SESS_DB" ]; then echo '{}' >"$NS_SESS_DB"; fi
  
  if python3 - "$NS_SESS_DB" "$user" "$sha" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{})
ud[u]=s
j['_userdb']=ud
open(p,'w').write(json.dumps(j))
print('Demo user created')
PY
  then
    ns_warn "🤖 Demo user created: admin/NovaShield123"
    ns_warn "⚠️  SECURITY: Change these credentials immediately!"
    return 0
  else
    ns_err "Failed to create demo user"
    return 1
  fi
}

# Export functions
export -f generate_keys generate_self_signed_tls ensure_auth_bootstrap 2>/dev/null || true