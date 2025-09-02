#!/usr/bin/env bash
# ==============================================================================
# NovaShield Terminal 3.1.0 — JARVIS Edition — All-in-One Installer & Runtime
# ==============================================================================
# Author  : niteas aka MrNova420
# Project : NovaShield (a.k.a. Nova)
# License : MIT
# Platform: Termux (Android) + Linux (Debian/Ubuntu/Arch/Fedora) auto-detect
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

NS_VERSION="3.1.0"

NS_HOME="${HOME}/.novashield"
NS_BIN="${NS_HOME}/bin"
NS_LOGS="${NS_HOME}/logs"
NS_WWW="${NS_HOME}/www"
NS_MODULES="${NS_HOME}/modules"
NS_PROJECTS="${NS_HOME}/projects"
NS_VERSIONS="${NS_HOME}/versions"
NS_KEYS="${NS_HOME}/keys"
NS_CTRL="${NS_HOME}/control"
NS_TMP="${NS_HOME}/.tmp"
NS_PID="${NS_HOME}/.pids"
NS_CONF="${NS_HOME}/config.yaml"
NS_SESSION="${NS_HOME}/session.log"
NS_VERSION_FILE="${NS_HOME}/version.txt"
NS_SELF_PATH_FILE="${NS_BIN}/self_path"
NS_LAUNCHER_BACKUPS="${NS_BIN}/backups"
NS_ALERTS="${NS_LOGS}/alerts.log"
NS_AUDIT="${NS_LOGS}/audit.log"
NS_CHATLOG="${NS_LOGS}/chat.log"
NS_SCHED_STATE="${NS_CTRL}/scheduler.state"
NS_SESS_DB="${NS_CTRL}/sessions.json"
NS_RL_DB="${NS_CTRL}/ratelimit.json"
NS_BANS_DB="${NS_CTRL}/bans.json"
NS_JARVIS_MEM="${NS_CTRL}/jarvis_memory.json"

NS_DEFAULT_PORT=8765
NS_DEFAULT_HOST="127.0.0.1"

NS_SELF="${BASH_SOURCE[0]}"
if command -v realpath >/dev/null 2>&1; then
  NS_SELF="$(realpath "${NS_SELF}")" || true
elif command -v readlink >/dev/null 2>&1; then
  NS_SELF="$(readlink -f "${NS_SELF}" 2>/dev/null || echo "${NS_SELF}")"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ns_now() { date '+%Y-%m-%d %H:%M:%S'; }
ns_log() { mkdir -p "${NS_HOME}" 2>/dev/null; echo -e "$(ns_now) [INFO ] $*" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_warn(){ mkdir -p "${NS_HOME}" 2>/dev/null; echo -e "${YELLOW}$(ns_now) [WARN ] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_err() { mkdir -p "${NS_HOME}" 2>/dev/null; echo -e "${RED}$(ns_now) [ERROR] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_ok()  { echo -e "${GREEN}✓ $*${NC}"; }

audit(){ 
  mkdir -p "$(dirname "$NS_AUDIT")" 2>/dev/null
  echo "$(ns_now) $*" | tee -a "$NS_AUDIT" >/dev/null
  # Also log security-relevant events to security.log
  case "$*" in
    *LOGIN*|*AUTH*|*SECURITY*|*BREACH*|*ATTACK*|*SUSPICIOUS*)
      mkdir -p "$(dirname "$NS_LOGS/security.log")" 2>/dev/null
      echo "$(ns_now) [SECURITY] $*" | tee -a "$NS_LOGS/security.log" >/dev/null
      ;;
  esac
}

alert(){
  local level="$1"; shift
  local msg="$*"
  local line="$(ns_now) [$level] $msg"
  mkdir -p "$(dirname "$NS_ALERTS")" 2>/dev/null
  echo "$line" | tee -a "$NS_ALERTS" >&2
  
  # Enhanced alert categorization
  case "$level" in
    CRIT|ERROR)
      # Critical security events
      echo "$(ns_now) [THREAT] $level: $msg" | tee -a "$NS_LOGS/security.log" >/dev/null 2>&1
      ;;
    WARN)
      # Warning-level security events
      echo "$(ns_now) [SECURITY] $level: $msg" | tee -a "$NS_LOGS/security.log" >/dev/null 2>&1
      ;;
  esac
  
  notify_dispatch "$level" "$msg" || true
}

# Improved error handling and cleanup
cleanup_on_exit(){
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    ns_err "Script exiting with code $exit_code"
  fi
}

handle_error(){
  local line_no=$1
  local error_code=$2
  ns_err "Error on line $line_no (code: $error_code) in function: ${FUNCNAME[2]:-main}"
  alert "ERROR" "Script error at line $line_no"
}

handle_signal(){
  local signal=$1
  ns_warn "Received signal $signal, cleaning up..."
  alert "WARN" "Script interrupted by signal $signal"
  stop_monitors 2>/dev/null || true
  stop_web 2>/dev/null || true
  exit 130
}

# Set up comprehensive error handling
trap 'handle_error $LINENO $?' ERR
trap 'cleanup_on_exit' EXIT 
trap 'handle_signal SIGINT' INT
trap 'handle_signal SIGTERM' TERM

die(){ ns_err "$*"; alert "CRIT" "$*"; exit 1; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

# Load optional configuration file for opt-in features
load_config_file(){
  local config_file="${NS_HOME}/novashield.conf"
  
  # If config file doesn't exist, create it from the example
  if [ ! -f "$config_file" ] && [ -f "$(dirname "$0")/novashield.conf.example" ]; then
    ns_log "Creating initial config file from example"
    cp "$(dirname "$0")/novashield.conf.example" "$config_file" 2>/dev/null || true
  fi
  
  if [ -f "$config_file" ]; then
    ns_log "Loading configuration from $config_file"
    # Source the config file to load environment variables
    set +u  # Temporarily allow unset variables
    source "$config_file" 2>/dev/null || ns_warn "Failed to load config file: $config_file"
    set -u  # Re-enable unset variable checking
  else
    ns_log "No config file found at $config_file - using defaults"
  fi
}

# Check if optional features are enabled (default: disabled for stable behavior)
is_auto_restart_enabled(){ [ "${NOVASHIELD_AUTO_RESTART:-0}" = "1" ]; }
is_security_hardening_enabled(){ [ "${NOVASHIELD_SECURITY_HARDENING:-0}" = "1" ]; }
is_strict_sessions_enabled(){ [ "${NOVASHIELD_STRICT_SESSIONS:-0}" = "1" ]; }
is_external_checks_enabled(){ [ "${NOVASHIELD_EXTERNAL_CHECKS:-1}" = "1" ]; }
is_web_auto_start_enabled(){ [ "${NOVASHIELD_WEB_AUTO_START:-1}" = "1" ]; }
is_auth_strict_enabled(){ [ "${NOVASHIELD_AUTH_STRICT:-1}" = "1" ]; }

# Improved file writing with proper directory creation and permissions
write_file(){ 
  local path="$1" mode="$2"; shift 2
  local dir; dir=$(dirname "$path")
  
  # Ensure directory exists
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir" || { ns_err "Failed to create directory: $dir"; return 1; }
  fi
  
  # Create file and set permissions
  if ! cat > "$path"; then
    ns_err "Failed to write file: $path"
    return 1
  fi
  
  # Set permissions if file was created successfully
  chmod "$mode" "$path" 2>/dev/null || ns_warn "Failed to set permissions $mode on $path"
}

append_file(){ local path="$1"; shift; cat >>"$path"; }
slurp(){ [ -f "$1" ] && cat "$1" || true; }
is_int(){ [[ "$1" =~ ^[0-9]+$ ]]; }
ensure_int(){ local v="$1" d="$2"; is_int "$v" && echo "$v" || echo "$d"; }

# Safer YAML value extraction for nested keys (handles both single-line and multi-line formats)
# Usage: yaml_get "section" "key" "default_value" 
yaml_get(){
  local section="$1" key="$2" default="$3"
  
  # Return default if config file doesn't exist
  if [ ! -f "$NS_CONF" ]; then
    echo "$default"
    return 0
  fi
  
  # Try single-line format first: section: { key: value, ... }
  local result
  result=$(awk -v sect="$section" -v k="$key" -v def="$default" '
    # Match lines with section: { ... key: value ... }
    $0 ~ sect ":.*\\{.*" k ":" {
      # Extract quoted values
      if (match($0, k ":[ \t]*\"([^\"]+)\"", arr)) {
        print arr[1];
        found = 1;
        exit;
      }
      # Extract unquoted values
      else if (match($0, k ":[ \t]*([^,}]+)", arr)) {
        gsub(/^[ \t]+/, "", arr[1]);
        gsub(/[ \t]+$/, "", arr[1]);
        print arr[1];
        found = 1;
        exit;
      }
    }
    END { if (!found) print def }
  ' "$NS_CONF" 2>/dev/null)
  
  # If single-line parsing found a result different from default, use it
  if [ "$result" != "$default" ]; then
    echo "$result"
    return 0
  fi
  
  # Fall back to multi-line format parsing
  awk -v sect="$section" -v k="$key" -v def="$default" '
    /^[a-zA-Z][a-zA-Z0-9_]*:/ { 
      gsub(/:$/, "", $1); 
      in_section = ($1 == sect) ? 1 : 0; 
      next 
    }
    in_section && /^[ \t]*[a-zA-Z][a-zA-Z0-9_]*:/ {
      gsub(/^[ \t]*/, ""); 
      split($0, parts, ":");
      gsub(/^[ \t]*/, "", parts[1]);
      if (parts[1] == k && length(parts) > 1) {
        value = "";
        for (i = 2; i <= length(parts); i++) {
          if (i > 2) value = value ":";
          value = value parts[i];
        }
        gsub(/^[ \t]*/, "", value);
        gsub(/[ \t]*$/, "", value);
        gsub(/^["'"'"']/, "", value);
        gsub(/["'"'"']$/, "", value);
        print value;
        found = 1;
        exit;
      }
    }
    END { if (!found) print def }
  ' "$NS_CONF" 2>/dev/null || echo "$default"
}

# Extract YAML array values from a section
# Usage: yaml_get_array "section" "key"
yaml_get_array(){
  local section="$1" key="$2"
  awk -v sect="$section" -v k="$key" '
    /^[a-zA-Z][a-zA-Z0-9_]*:/ { 
      gsub(/:$/, "", $1); 
      in_section = ($1 == sect) ? 1 : 0; 
      next 
    }
    in_section && /^[ \t]*[a-zA-Z][a-zA-Z0-9_]*:/ {
      gsub(/^[ \t]*/, ""); 
      if ($1 == k ":") {
        # Handle array on same line: key: [item1, item2, item3]
        if ($0 ~ /\[.*\]/) {
          gsub(/.*\[/, ""); gsub(/\].*/, "");
          gsub(/[ \t]*"[ \t]*/, ""); gsub(/[ \t]*'"'"'[ \t]*/, "");
          gsub(/,/, "\n");
          print;
          exit;
        }
        # Handle array on following lines: - item
        in_array = 1;
        next;
      }
    }
    in_array && /^[ \t]*-/ {
      gsub(/^[ \t]*-[ \t]*/, "");
      gsub(/[ \t]*$/, "");
      gsub(/^["'"'"']/, ""); gsub(/["'"'"']$/, "");
      if (length($0) > 0) print;
    }
    in_array && !/^[ \t]*-/ && /^[ \t]*[a-zA-Z]/ { in_array = 0 }
  ' "$NS_CONF" 2>/dev/null
}

# Safely validate and read a PID file
# Returns the PID if valid and belongs to our process tree, 0 otherwise
safe_read_pid(){
  local pidfile="$1"
  [ -f "$pidfile" ] || { echo "0"; return; }
  local pid; pid=$(cat "$pidfile" 2>/dev/null | head -n1 | tr -d ' \t\n\r')
  
  # Validate PID is a number
  if ! [[ "$pid" =~ ^[0-9]+$ ]] || [ "$pid" -eq 0 ]; then
    echo "0"; return
  fi
  
  # Check if process exists and is not our own shell
  if ! kill -0 "$pid" 2>/dev/null || [ "$pid" -eq "$$" ]; then
    echo "0"; return
  fi
  
  # Additional safety: check if it's a valid process type
  local cmdline; cmdline=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
  # Allow bash/sh (monitors) and python3 (web server)
  if [[ "$cmdline" =~ ^(bash|sh|python3)$ ]]; then
    echo "$pid"
  else
    echo "0"
  fi
}

# Safely write PID file with validation
safe_write_pid(){
  local pidfile="$1" pid="$2"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 0 ]; then
    echo "$pid" > "$pidfile"
  fi
}

IS_TERMUX=0
if uname -a | grep -iq termux || { [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q "/com.termux/"; }; then
  IS_TERMUX=1
fi

PKG_INSTALL(){
  if [ "$IS_TERMUX" -eq 1 ]; then
    pkg install -y "$@" 2>/dev/null
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -q -y 2>/dev/null && sudo apt-get install -q -y "$@" 2>/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "$@" 2>/dev/null
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm "$@" 2>/dev/null
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y "$@" 2>/dev/null
  else
    ns_warn "Unknown package manager. Install dependencies manually: $*"
    return 1
  fi
}

ensure_dirs(){
  mkdir -p "$NS_BIN" "$NS_LOGS" "$NS_WWW" "$NS_MODULES" "$NS_PROJECTS" \
           "$NS_VERSIONS" "$NS_KEYS" "$NS_CTRL" "$NS_TMP" "$NS_PID" \
           "$NS_LAUNCHER_BACKUPS" "${NS_HOME}/backups" "${NS_HOME}/site"
  : >"$NS_ALERTS" || true
  : >"$NS_CHATLOG" || true
  : >"$NS_AUDIT" || true
  [ -f "$NS_SESS_DB" ] || echo '{}' >"$NS_SESS_DB"
  [ -f "$NS_RL_DB" ] || echo '{}' >"$NS_RL_DB"
  [ -f "$NS_BANS_DB" ] || echo '{}' >"$NS_BANS_DB"
  [ -f "$NS_JARVIS_MEM" ] || echo '{"conversations":[]}' >"$NS_JARVIS_MEM"
  echo "$NS_VERSION" >"$NS_VERSION_FILE"
  echo "$NS_SELF" >"$NS_SELF_PATH_FILE"
}

write_default_config(){
  if [ -f "$NS_CONF" ]; then return 0; fi
  ns_log "Writing default config to $NS_CONF"
  write_file "$NS_CONF" 600 <<'YAML'
version: "3.1.0"
http:
  host: 127.0.0.1
  port: 8765
  allow_lan: false

security:
  auth_enabled: true
  require_2fa: false
  users: []        # add via CLI: ./novashield.sh --add-user
  auth_salt: "change-this-salt"
  rate_limit_per_min: 60
  lockout_threshold: 10
  ip_allowlist: [] # e.g. ["127.0.0.1"]
  ip_denylist: []  # e.g. ["0.0.0.0/0"]
  csrf_required: true
  tls_enabled: false
  tls_cert: "keys/tls.crt"
  tls_key: "keys/tls.key"
  session_ttl_minutes: 120  # Session timeout in minutes (default: 2 hours)
  force_login_on_reload: false  # Force login on every page reload

terminal:
  enabled: true
  shell: ""             # auto-detect
  idle_timeout_sec: 900 # 15 minutes
  cols: 120
  rows: 32
  allow_write: true
  command_allowlist: []

monitors:
  cpu:         { enabled: true,  interval_sec: 3, warn_load: 2.00, crit_load: 4.00 }
  memory:      { enabled: true,  interval_sec: 3, warn_pct: 85,  crit_pct: 93 }
  disk:        { enabled: true,  interval_sec: 10, warn_pct: 85, crit_pct: 95, mount: "/" }
  network:     { enabled: true,  interval_sec: 5, iface: "", ping_host: "1.1.1.1", loss_warn: 20, external_checks: true, public_ip_services: ["icanhazip.com", "ifconfig.me", "api.ipify.org"] }
  integrity:   { enabled: true,  interval_sec: 60, watch_paths: ["/system/bin","/system/xbin","/usr/bin"] }
  process:     { enabled: true,  interval_sec: 10, suspicious: ["nc","nmap","hydra","netcat","telnet"] }
  userlogins:  { enabled: true,  interval_sec: 30 }
  services:    { enabled: false, interval_sec: 20, targets: ["cron","ssh","sshd"] }
  logs:        { enabled: true,  interval_sec: 15, files: ["/var/log/auth.log","/var/log/syslog"], patterns:["error","failed","denied","segfault"] }
  scheduler:   { enabled: true,  interval_sec: 30 }

logging:
  keep_days: 14
  alerts_enabled: true
  alert_sink: ["notify"]
  notify_levels: ["CRIT","WARN","ERROR"]

backup:
  enabled: true
  max_keep: 10
  encrypt: true
  paths: ["projects", "modules", "config.yaml"]

keys:
  rsa_bits: 4096
  aes_key_file: "keys/aes.key"

notifications:
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    username: "user@example.com"
    password: "change-me"
    to: ["you@example.com"]
    use_tls: true
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
  discord:
    enabled: false
    webhook_url: ""

updates:
  enabled: false
  source: ""

sync:
  enabled: false
  method: "rclone"
  remote: ""

scheduler:
  tasks:
    - name: "daily-backup"
      action: "backup"
      time: "02:30"
    - name: "version-snapshot-weekly"
      action: "version"
      time: "03:00"

webgen:
  enabled: true
  site_name: "NovaShield Site"
  theme: "jarvis-dark"


jarvis:
  personality: "helpful"  # helpful, snarky, professional
  memory_size: 10         # remember last N conversations
  voice_enabled: false    # future text-to-speech capability
YAML
}

install_dependencies(){
  ns_log "Checking dependencies..."
  local need=(python3 awk sed grep tar gzip df du ps top uname head tail cut tr sha256sum curl ping find xargs)
  local missing=()
  
  # Enhanced Termux setup as requested
  if [ "$IS_TERMUX" -eq 1 ]; then
    ns_log "Termux detected - performing enhanced mobile setup..."
    
    # Essential Termux packages for better experience
    ns_log "Installing enhanced Termux packages..."
    PKG_INSTALL termux-tools || true
    PKG_INSTALL termux-api || true
    PKG_INSTALL procps || true  # Better ps, top, etc.
    PKG_INSTALL htop || true    # Enhanced system monitor
    PKG_INSTALL nano || true    # Text editor
    PKG_INSTALL vim || true     # Advanced editor
    PKG_INSTALL git || true     # Version control
    PKG_INSTALL man || true     # Manual pages
    PKG_INSTALL which || true   # Which command
    PKG_INSTALL openssh || true # SSH capabilities
    
    # Update packages to latest versions
    ns_log "Updating Termux packages..."
    pkg update -y 2>/dev/null || true
    pkg upgrade -y 2>/dev/null || true
    
    # Setup storage access
    ns_log "Setting up Termux storage access..."
    if [ ! -d "$HOME/storage" ]; then
      termux-setup-storage 2>/dev/null || ns_warn "Storage setup may require manual confirmation"
    fi
    
    # Enhanced terminal capabilities
    ns_log "Setting up enhanced terminal..."
    echo "export TERM=xterm-256color" >> "$HOME/.bashrc" 2>/dev/null || true
    echo "export COLORTERM=truecolor" >> "$HOME/.bashrc" 2>/dev/null || true
  fi
  
  # Check which dependencies are missing
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      missing+=("$c")
    fi
  done
  
  # Install missing dependencies
  if [ ${#missing[@]} -gt 0 ]; then
    ns_warn "Missing dependencies: ${missing[*]}"
    for c in "${missing[@]}"; do
      ns_log "Installing $c..."
      if ! PKG_INSTALL "$c"; then
        ns_warn "Failed to install $c - functionality may be limited"
      fi
    done
    
    # Recheck after installation
    local still_missing=()
    for c in "${missing[@]}"; do
      if ! command -v "$c" >/dev/null 2>&1; then
        still_missing+=("$c")
      fi
    done
    
    if [ ${#still_missing[@]} -gt 0 ]; then
      ns_warn "Some dependencies could not be installed: ${still_missing[*]}"
      ns_warn "You may need to install them manually for full functionality"
    fi
  fi
  
  # Handle OpenSSL separately due to different package names
  if ! command -v openssl >/dev/null 2>&1; then
    if [ "$IS_TERMUX" -eq 1 ]; then
      ns_warn "Installing openssl-tool (Termux)"
      PKG_INSTALL openssl-tool || ns_warn "OpenSSL installation failed - crypto features disabled"
    else
      PKG_INSTALL openssl || ns_warn "OpenSSL installation failed - crypto features disabled"
    fi
  fi
  
  # Termux-specific services (optional)
  if [ "$IS_TERMUX" -eq 1 ]; then
    if ! command -v sv-enable >/dev/null 2>&1; then
      ns_log "Installing termux-services (optional for auto-start)"
      PKG_INSTALL termux-services || ns_warn "termux-services install failed (non-critical)"
    fi
    
    # Install additional useful tools for Termux users
    ns_log "Installing additional security and system tools..."
    PKG_INSTALL nmap || ns_warn "nmap install failed"
    PKG_INSTALL netcat-openbsd || PKG_INSTALL netcat || true
    PKG_INSTALL wget || true
    PKG_INSTALL zip || true
    PKG_INSTALL unzip || true
    PKG_INSTALL tree || true
    PKG_INSTALL lsof || true
    
    ns_ok "Enhanced Termux setup completed"
  fi
  
  # Verify critical dependencies are available
  local critical=(python3 awk grep)
  for c in "${critical[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      die "Critical dependency '$c' is missing and could not be installed"
    fi
  done
  
  ns_ok "Dependencies check completed"
}

generate_keys(){
  if [ ! -f "${NS_KEYS}/private.pem" ] || [ ! -f "${NS_KEYS}/public.pem" ]; then
    ns_log "Generating RSA keypair"
    local bits; bits=$(yaml_get "security" "rsa_bits" "4096")
    (cd "$NS_KEYS" && openssl genrsa -out private.pem "${bits}" && openssl rsa -in private.pem -pubout -out public.pem)
    chmod 600 "${NS_KEYS}/private.pem"
  fi
  local aesf
  aesf=$(yaml_get "security" "aes_key_file" "keys/aes.key")
  [ -z "$aesf" ] && aesf="keys/aes.key"
  if [ ! -f "${NS_HOME}/${aesf}" ]; then
    ns_log "Generating AES key file: ${aesf}"
    head -c 64 /dev/urandom >"${NS_HOME}/${aesf}"
    chmod 600 "${NS_HOME}/${aesf}"
  fi
}

generate_self_signed_tls(){
  local enabled; enabled=$(yaml_get "security" "tls_enabled" "true")
  [ "$enabled" = "true" ] || return 0
  local crt key
  crt=$(yaml_get "security" "tls_cert" "keys/server.crt")
  key=$(yaml_get "security" "tls_key" "keys/server.key")
  [ -z "$crt" ] && crt="keys/tls.crt"
  [ -z "$key" ] && key="keys/tls.key"
  [ -f "${NS_HOME}/${crt}" ] && [ -f "${NS_HOME}/${key}" ] && return 0
  ns_log "Generating self-signed TLS cert"
  (cd "$NS_HOME/keys" && \
    openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 825 \
      -subj "/CN=localhost/O=NovaShield/OU=SelfSigned") || ns_warn "TLS cert generation failed"
}

aes_key_path(){ yaml_get "security" "aes_key_file" "keys/aes.key"; }
enc_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -aes-256-cbc -salt -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
dec_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
enc_dir(){ local dir="$1"; local out="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; tar -C "$dir" -czf "$tmp" . || tar -czf "$tmp" "$dir"; enc_file "$tmp" "$out"; rm -f "$tmp"; }
dec_dir(){ local in="$1"; local outdir="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; dec_file "$in" "$tmp"; mkdir -p "$outdir"; tar -C "$outdir" -xzf "$tmp"; rm -f "$tmp"; }

write_notify_py(){
  write_file "${NS_BIN}/notify.py" 700 <<'PY'
#!/usr/bin/env python3
import os, sys, json, smtplib, ssl, urllib.request, urllib.parse
from email.mime.text import MIMEText

NS_HOME = os.path.expanduser('~/.novashield')
CONF = os.path.join(NS_HOME, 'config.yaml')

def yaml_get(path, default=None):
  try:
    with open(CONF,'r',encoding='utf-8') as f:
      tree = {}
      stack = [(-1, tree)]
      for line in f:
        if not line.strip() or line.strip().startswith('#'): continue
        indent = len(line)-len(line.lstrip())
        while stack and indent <= stack[-1][0]: stack.pop()
        parent = stack[-1][1] if stack else tree
        s=line.strip()
        if ':' in s:
          k,v = s.split(':',1)
          k=k.strip(); v=v.strip()
          if v=='':
            parent[k]={}
            stack.append((indent,parent[k]))
          else:
            parent[k]=v.strip().strip('"')
        elif s.startswith('- '):
          k=s[2:].strip().strip('"')
          parent.setdefault('_list',[]).append(k)
    cur=tree
    for p in path.split('.'):
      if isinstance(cur,dict) and p in cur: cur=cur[p]
      else: return default
    return cur
  except Exception:
    return default

def send_email(subject, body):
  if not str(yaml_get('notifications.email.enabled','false')).lower()=='true': return
  host = yaml_get('notifications.email.smtp_host','')
  port = int(yaml_get('notifications.email.smtp_port','587'))
  user = yaml_get('notifications.email.username','')
  pwd  = yaml_get('notifications.email.password','')
  to   = yaml_get('notifications.email.to','').strip('[]').replace('"','').split(',')
  use_tls = str(yaml_get('notifications.email.use_tls','true')).lower()=='true'
  tos = [t.strip() for t in to if t.strip()]
  if not (host and user and pwd and tos): return
  msg = MIMEText(body, 'plain', 'utf-8')
  msg['Subject'] = subject
  msg['From'] = user
  msg['To'] = ','.join(tos)
  try:
    if use_tls:
      context = ssl.create_default_context()
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=context)
        server.login(user, pwd)
        server.sendmail(user, tos, msg.as_string())
    else:
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.login(user, pwd)
        server.sendmail(user, tos, msg.as_string())
  except Exception:
    pass

def send_telegram(body):
  if not str(yaml_get('notifications.telegram.enabled','false')).lower()=='true': return
  token = yaml_get('notifications.telegram.bot_token','')
  chat  = yaml_get('notifications.telegram.chat_id','')
  if not (token and chat): return
  data = urllib.parse.urlencode({'chat_id':chat,'text':body}).encode('utf-8')
  try: urllib.request.urlopen(urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=data), timeout=5)
  except Exception: pass

def send_discord(body):
  if not str(yaml_get('notifications.discord.enabled','false')).lower()=='true': return
  hook = yaml_get('notifications.discord.webhook_url','')
  if not hook: return
  payload = json.dumps({'content': body}).encode('utf-8')
  req = urllib.request.Request(hook, data=payload, headers={'Content-Type':'application/json'})
  try: urllib.request.urlopen(req, timeout=5)
  except Exception: pass

if __name__ == '__main__':
  level = (sys.argv[1] if len(sys.argv)>1 else 'INFO').upper()
  subject = sys.argv[2] if len(sys.argv)>2 else 'NovaShield Notification'
  body = sys.argv[3] if len(sys.argv)>3 else ''
  allow = (yaml_get('logging.notify_levels','["CRIT","WARN","ERROR"]') or '').upper()
  if level in allow:
    send_email(subject, body)
    send_telegram(f'{subject}\n{body}')
    send_discord(f'{subject}\n{body}')
PY
}

notify_dispatch(){
  local level="$1" msg="$2"
  local enabled; enabled=$(yaml_get "notifications" "alerts_enabled" "false")
  local sinks; sinks=$(yaml_get_array "notifications" "alert_sink")
  [ "$enabled" = "true" ] || return 0
  for s in $sinks; do
    case "$s" in
      notify) python3 "${NS_BIN}/notify.py" "$1" "NovaShield [$1]" "$2" >/dev/null 2>&1 || true ;;
      *) : ;;
    esac
  done
}

backup_snapshot(){
  # Robust backup with concurrency lock, YAML-driven includes, optional AES-256 encryption, and rotation
  local stamp; stamp="$(date '+%Y%m%d-%H%M%S')"
  local dest_dir="${NS_HOME}/backups"
  local lock="${NS_CTRL}/backup.lock"
  local tmp_tar="${NS_TMP}/backup-${stamp}.tar.gz"
  local final enc_enabled sha bytes
  local -a rels=()

  mkdir -p "${NS_TMP}" "${dest_dir}"

  if [ -f "$lock" ]; then
    local oldpid; oldpid="$(cat "$lock" 2>/dev/null || true)"
    if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
      ns_warn "Another backup is already running (PID $oldpid). Aborting."
      return 1
    fi
    rm -f "$lock" 2>/dev/null || true
  fi
  echo "$$" > "$lock"
  trap 'rm -f "'"$lock"'" 2>/dev/null || true' EXIT

  ns_log "Creating backup snapshot: ${stamp}"

  enc_enabled="$(
    awk '
      BEGIN{blk=0}
      /^[[:space:]]*backup:[[:space:]]*$/ {blk=1;next}
      blk==1 && /^[^[:space:]]/ {blk=0}
      blk==1 && $1 ~ /encrypt:/ {
        sub(/^[^:]*:[[:space:]]*/, "", $0)
        sub(/[[:space:]]*#.*/, "", $0)
        gsub(/[[:space:]]/,"",$0)
        print tolower($0)
        exit
      }
    ' "$NS_CONF" 2>/dev/null
  )"
  [ -z "$enc_enabled" ] && enc_enabled="true"

  local paths; paths="$(
    awk '
      BEGIN{blk=0;plist=0}
      /^[[:space:]]*backup:[[:space:]]*$/ {blk=1;next}
      blk==1 && /^[^[:space:]]/ {blk=0}
      blk==1 && /paths:[[:space:]]*\[/ {
        line=$0
        sub(/.*\[/,"",line); sub(/\].*/,"",line)
        gsub(/"/,"",line); gsub(/[[:space:]]/,"",line)
        n=split(line,a,","); for(i=1;i<=n;i++) if(a[i]!="") print a[i]
      }
      blk==1 && /paths:[[:space:]]*$/ {plist=1;next}
      blk==1 && plist==1 {
        if($0 ~ /^\s*-\s*/){
          t=$0; sub(/^\s*-\s*/,"",t); sub(/[[:space:]]*#.*/, "", t); gsub(/"/,"",t); sub(/[[:space:]]+$/,"",t);
          if(t!="") print t
        } else if($0 !~ /^\s*#/ && $0 ~ /[^[:space:]]/){
          plist=0
        }
      }
    ' "$NS_CONF" 2>/dev/null
  )"

  if [ -n "$paths" ]; then
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      local full rel
      case "$p" in
        /*) full="$p" ;;
        *)  full="${NS_HOME}/$p" ;;
      esac
      if [ ! -e "$full" ]; then
        ns_warn "Backup path missing: $p (full: $full) — skipping"
        continue
      fi
      case "$full" in
        "${NS_HOME}/"*) rel="${full#${NS_HOME}/}";;
        *) ns_warn "Backup path outside NS_HOME not included: $full"; continue;;
      esac
      case "$rel" in
        backups|backups/*|.tmp|.tmp/*|.pids|.pids/*) ns_warn "Skipping internal path: $rel"; continue;;
      esac
      rels+=("$rel")
    done <<EOF
$paths
EOF
  fi

  if [ "${#rels[@]}" -eq 0 ]; then
    rels=()
    [ -d "$NS_PROJECTS" ] && rels+=("projects")
    [ -d "$NS_MODULES" ]  && rels+=("modules")
    [ -f "$NS_CONF" ]     && rels+=("config.yaml")
    [ "${#rels[@]}" -eq 0 ] && rels=("projects" "modules" "config.yaml")
  fi

  if ! tar -C "$NS_HOME" -czf "$tmp_tar" \
       --warning=no-file-changed \
       --exclude="./backups/*" --exclude="./.tmp/*" --exclude="./.pids/*" \
       "${rels[@]}" 2>/dev/null; then
    ns_warn "Primary tar failed; attempting minimal fallback set."
    tar -C "$NS_HOME" -czf "$tmp_tar" \
       --warning=no-file-changed \
       --exclude="./backups/*" --exclude="./.tmp/*" --exclude="./.pids/*" \
       projects modules config.yaml 2>/dev/null || true
  fi

  if [ "$enc_enabled" = "true" ]; then
    final="${dest_dir}/backup-${stamp}.tar.gz.enc"
    if ! enc_file "$tmp_tar" "$final"; then
      rm -f "$tmp_tar" 2>/dev/null || true
      rm -f "$lock" 2>/dev/null || true
      trap - EXIT
      die "Encryption failed; backup aborted."
    fi
    rm -f "$tmp_tar" 2>/dev/null || true
  else
    final="${dest_dir}/backup-${stamp}.tar.gz"
    mv -f "$tmp_tar" "$final"
  fi

  if [ -f "$final" ]; then
    sha="$(sha256sum "$final" 2>/dev/null | awk '{print $1}')"
    bytes="$(stat -c%s "$final" 2>/dev/null || wc -c <"$final" 2>/dev/null || echo 0)"
    ns_ok "Backup created: $final (size: ${bytes} bytes, sha256: ${sha})"
    audit "BACKUP CREATED path=${final} bytes=${bytes} sha256=${sha} enc=${enc_enabled}"
  else
    rm -f "$lock" 2>/dev/null || true
    trap - EXIT
    die "Backup file not found after creation."
  fi

  rotate_backups
  rm -f "$lock" 2>/dev/null || true
  trap - EXIT
}

rotate_backups(){
  local max_keep
  max_keep="$(
    awk '
      BEGIN{blk=0}
      /^[[:space:]]*backup:[[:space:]]*$/ {blk=1;next}
      blk==1 && /^[^[:space:]]/ {blk=0}
      blk==1 && $1 ~ /max_keep:/ {
        sub(/^[^:]*:[[:space:]]*/, "", $0)
        sub(/[[:space:]]*#.*/, "", $0)
        gsub(/[[:space:]]/,"",$0)
        print $0
        exit
      }
    ' "$NS_CONF" 2>/dev/null
  )"
  [[ "$max_keep" =~ ^[0-9]+$ ]] || max_keep=10

  local bdir="${NS_HOME}/backups"
  [ -d "$bdir" ] || return 0

  local to_delete
  to_delete="$(ls -1t "$bdir"/backup-*.tar.gz* 2>/dev/null | tail -n +"$((max_keep+1))" || true)"
  if [ -n "$to_delete" ]; then
    echo "$to_delete" | while IFS= read -r f; do
      [ -n "$f" ] || continue
      ns_warn "Removing old backup: $(basename "$f")"
      rm -f -- "$f" || true
    done
  fi
}

version_snapshot(){
  local stamp="$(date '+%Y%m%d-%H%M%S')"
  local vdir="${NS_VERSIONS}/${stamp}"; mkdir -p "$vdir"
  ns_log "Creating version snapshot: $vdir"
  cp -a "$NS_MODULES" "$vdir/modules" 2>/dev/null || true
  cp -a "$NS_PROJECTS" "$vdir/projects" 2>/dev/null || true
  cp -a "$NS_CONF" "$vdir/config.yaml" 2>/dev/null || true
  cp -a "$NS_HOME/launcher.log" "$vdir/launcher.log" 2>/dev/null || true
  cp -a "$NS_ALERTS" "$vdir/alerts.log" 2>/dev/null || true
  audit "VERSION SNAPSHOT ${vdir}"
}

monitor_enabled(){ local name="$1"; [ -f "${NS_CTRL}/${name}.disabled" ] && return 1 || return 0; }
write_json(){ 
  local path="$1"; shift; 
  local content="$*"
  if ! printf '%s' "$content" >"$path" 2>/dev/null; then
    alert WARN "Failed to write JSON to $path"
    return 1
  fi
  # Validate JSON is not truncated by checking if it can be parsed
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import json; json.loads('''$content''')" 2>/dev/null; then
      alert WARN "Invalid JSON written to $path: $content"
      return 1
    fi
  fi
  return 0
}

ns_internal_ip(){
  local iface="$1" ip=""
  if [ "$IS_TERMUX" -eq 1 ] && command -v getprop >/dev/null 2>&1; then
    ip=$(getprop dhcp.wlan0.ipaddress 2>/dev/null || true)
    [ -z "$ip" ] && ip=$(getprop dhcp.eth0.ipaddress 2>/dev/null || true)
    if [ -z "$ip" ]; then
      ip=$(getprop 2>/dev/null | awk -F'[][]' '/dhcp\..*\.ipaddress]/{print $3}' | head -n1)
    fi
  fi
  if [ -z "$ip" ] && command -v ifconfig >/dev/null 2>&1; then
    ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1)
    [ -z "$ip" ] && ip=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -n1)
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
    ip=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    [ -z "$ip" ] && ip=$(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -n1)
  fi
  echo "$ip"
}

# ------------------------------- MONITORS ------------------------------------
_monitor_cpu(){
  set +e; set +o pipefail
  local interval warn crit
  interval=$(ensure_int "$(yaml_get "cpu" "interval_sec" "3")" 3)
  warn=$(yaml_get "cpu" "warn_load" "2.00")
  crit=$(yaml_get "cpu" "crit_load" "4.00")
  [ -z "$warn" ] && warn=2.00; [ -z "$crit" ] && crit=4.00
  while true; do
    monitor_enabled cpu || { sleep "$interval"; continue; }
    local load1; load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    local lvl; lvl=$(awk -v l="$load1" -v w="$warn" -v c="$crit" 'BEGIN{ if(l>=c){print "CRIT"} else if(l>=w){print "WARN"} else {print "OK"} }')
    write_json "${NS_LOGS}/cpu.json" "{\"ts\":\"$(ns_now)\",\"load1\":${load1},\"warn\":${warn},\"crit\":${crit},\"level\":\"${lvl}\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "CPU load high: $load1" || { [ "$lvl" = "WARN" ] && alert WARN "CPU load elevated: $load1"; }
    sleep "$interval"
  done
}

_monitor_mem(){
  set +e; set +o pipefail
  local interval warn crit
  interval=$(ensure_int "$(yaml_get "memory" "interval_sec" "3")" 3)
  warn=$(ensure_int "$(yaml_get "memory" "warn_pct" "85")" 85)
  crit=$(ensure_int "$(yaml_get "memory" "crit_pct" "95")" 95)
  while true; do
    monitor_enabled memory || { sleep "$interval"; continue; }
    local mem_total mem_avail mem_used pct
    if grep -q MemAvailable /proc/meminfo 2>/dev/null; then
      mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
      mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
      mem_used=$((mem_total-mem_avail)); pct=$((mem_used*100/mem_total))
    else
      read -r _ mem_total _ < <(free -k | awk '/Mem:/ {print $2, $3, $4}')
      mem_used=$(free -k | awk '/Mem:/ {print $3}'); pct=$((mem_used*100/mem_total))
    fi
    local lvl="OK"; [ "$pct" -ge "$crit" ] && lvl="CRIT" || { [ "$pct" -ge "$warn" ] && lvl="WARN"; }
    write_json "${NS_LOGS}/memory.json" "{\"ts\":\"$(ns_now)\",\"used_pct\":${pct},\"warn\":${warn},\"crit\":${crit},\"level\":\"${lvl}\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "Memory high: ${pct}%" || { [ "$lvl" = "WARN" ] && alert WARN "Memory elevated: ${pct}%"; }
    sleep "$interval"
  done
}

_monitor_disk(){
  set +e; set +o pipefail
  local interval warn crit mount
  interval=$(ensure_int "$(yaml_get "disk" "interval_sec" "10")" 10)
  warn=$(ensure_int "$(yaml_get "disk" "warn_pct" "85")" 85)
  crit=$(ensure_int "$(yaml_get "disk" "crit_pct" "95")" 95)
  mount=$(yaml_get "disk" "mount" "/")
  [ -z "$mount" ] && mount="/"
  if [ "$IS_TERMUX" -eq 1 ] && [ "$mount" = "/" ]; then
    mount="$NS_HOME"
  fi
  while true; do
    monitor_enabled disk || { sleep "$interval"; continue; }
    local use; use=$(df -P "$mount" | awk 'END {gsub("%","",$5); print $5+0}')
    local lvl="OK"; [ "$use" -ge "$crit" ] && lvl="CRIT" || { [ "$use" -ge "$warn" ] && lvl="WARN"; }
    write_json "${NS_LOGS}/disk.json" "{\"ts\":\"$(ns_now)\",\"use_pct\":${use},\"warn\":${warn},\"crit\":${crit},\"mount\":\"${mount}\",\"level\":\"${lvl}\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "Disk $mount high: ${use}%" || { [ "$lvl" = "WARN" ] && alert WARN "Disk $mount elevated: ${use}%"; }
    sleep "$interval"
  done
}

_monitor_net(){
  set +e; set +o pipefail
  local interval iface pingh warnloss external_checks
  interval=$(ensure_int "$(yaml_get "network" "interval_sec" "5")" 5)
  iface=$(yaml_get "network" "iface" "")
  pingh=$(yaml_get "network" "ping_host" "1.1.1.1")
  warnloss=$(ensure_int "$(yaml_get "network" "loss_warn" "20")" 20)
  external_checks=$(yaml_get "network" "external_checks" "true")
  
  # Get list of public IP services from config
  local pubip_services
  if [ "$external_checks" = "true" ]; then
    pubip_services=$(yaml_get "network" "public_ip_services" "")
    if [ -z "$pubip_services" ]; then
      # Fallback to default services if not configured
      pubip_services="icanhazip.com ifconfig.me api.ipify.org"
    else
      # Parse YAML array format [service1, service2, service3] -> service1 service2 service3
      pubip_services=$(echo "$pubip_services" | sed 's/\[//g; s/\]//g; s/,/ /g; s/"//g; s/'\''//g')
    fi
  fi
  
  while true; do
    monitor_enabled network || { sleep "$interval"; continue; }
    local ip pubip loss=0 avg=0
    ip="$(ns_internal_ip "$iface")"
    
    # Only do external ping if external checks are enabled
    if [ "$external_checks" = "true" ] && command -v ping >/dev/null 2>&1; then
      local out; out=$(timeout 10 ping -c 3 -w 3 "$pingh" 2>/dev/null || true)
      if [ $? -eq 124 ]; then
        # Timeout occurred, consider this as 100% loss
        loss=100
        avg=0
        ns_warn "Network ping to $pingh timed out (likely blocked by firewall)"
      else
        loss=$(echo "$out" | awk -F',' '/packet loss/ {gsub("%","",$3); gsub(" ","",$3); print $3+0}' 2>/dev/null || echo 0)
        avg=$(echo "$out" | awk -F'/' '/rtt/ {print $5}' 2>/dev/null || echo 0)
      fi
    else
      # External checks disabled or ping not available
      loss=0
      avg=0
      if [ "$external_checks" != "true" ]; then
        ns_log "Network monitoring: External ping checks disabled"
      fi
    fi
    
    # Only get public IP if external checks are enabled
    pubip=""
    if [ "$external_checks" = "true" ] && [ -n "$pubip_services" ]; then
      for service in $pubip_services; do
        if command -v curl >/dev/null 2>&1; then 
          pubip=$(timeout 5 curl -s --max-time 3 --connect-timeout 3 "$service" 2>/dev/null || true)
          if [ $? -eq 124 ]; then
            ns_warn "Public IP check to $service timed out (likely blocked by firewall)"
          fi
        fi
        [ -n "$pubip" ] && break
      done
      if [ -z "$pubip" ]; then
        ns_warn "All public IP services failed/blocked, setting to 'unavailable'"
        pubip="unavailable"
      fi
    else
      if [ "$external_checks" != "true" ]; then
        pubip="disabled"
        ns_log "Network monitoring: External public IP checks disabled"
      else
        pubip="no_services"
      fi
    fi
    
    local lvl="OK"
    if [ "$external_checks" = "true" ] && [ "${loss:-0}" -ge "${warnloss:-999}" ]; then
      lvl="WARN"
    fi
    
    write_json "${NS_LOGS}/network.json" "{\"ts\":\"$(ns_now)\",\"ip\":\"${ip:-}\",\"public_ip\":\"${pubip:-}\",\"loss_pct\":${loss:-0},\"rtt_avg_ms\":${avg:-0},\"level\":\"${lvl}\",\"external_checks\":\"${external_checks}\"}"
    
    if [ "$lvl" = "WARN" ] && [ "$external_checks" = "true" ]; then
      alert WARN "Network loss ${loss}% to ${pingh}"
    fi
    
    sleep "$interval"
  done
}

_monitor_integrity(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/integrity:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 60)
  local list; list=$(awk -F'- ' '/watch_paths:/{flag=1;next}/]/{flag=0}flag{print $2}' "$NS_CONF" 2>/dev/null || true)
  
  # Initialize integrity state file
  local state_file="${NS_CTRL}/integrity.state"
  mkdir -p "$(dirname "$state_file")"
  
  while true; do
    monitor_enabled integrity || { sleep "$interval"; continue; }
    
    local total_files=0
    local total_changes=0
    local recent_changes=[]
    
    for p in $list; do
      p=$(echo "$p" | tr -d '"' | tr -d ' ')
      [ -d "$p" ] || continue
      local sumfile="${NS_LOGS}/integrity.$(echo "$p" | tr '/' '_').sha"
      local file_count=0
      local changes=0
      
      # Count files and check for changes
      if [ -f "$sumfile" ]; then
        while IFS= read -r line; do
          local have file; have=$(echo "$line" | awk '{print $1}'); file=$(echo "$line" | awk '{print $2}')
          file_count=$((file_count + 1))
          if [ -f "$file" ]; then
            local now; now=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            if [ "$now" != "$have" ]; then
              changes=$((changes + 1))
              # Log the specific change
              echo "$(ns_now) [INTEGRITY] File modified: $file" >> "$NS_LOGS/security.log" 2>/dev/null
              audit "INTEGRITY CHANGE file=$file path=$p"
            fi
          fi
        done <"$sumfile"
        if [ "$changes" -gt 0 ]; then
          alert WARN "Integrity changes in $p: $changes files"
          total_changes=$((total_changes + changes))
        fi
      fi
      
      # Update checksums
      find "$p" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null | head -n 200 | xargs -r sha256sum >"$sumfile" 2>/dev/null || true
      
      # Count current files
      local current_count; current_count=$(find "$p" -maxdepth 1 -type f 2>/dev/null | wc -l)
      total_files=$((total_files + current_count))
    done
    
    # Update integrity state
    cat > "$state_file" 2>/dev/null <<EOF
{
  "timestamp": "$(ns_now)",
  "files": $total_files,
  "changes_detected": $total_changes,
  "recent_changes": [],
  "monitored_paths": ["$(echo "$list" | tr ' ' ',' | tr -d '"')"],
  "last_scan": "$(ns_now)"
}
EOF
    
    write_json "${NS_LOGS}/integrity.json" "{\"ts\":\"$(ns_now)\", \"files\": $total_files, \"changes\": $total_changes}"
    sleep "$interval"
  done
}

_monitor_process(){
  set +e; set +o pipefail
  local interval suspicious
  interval=$(ensure_int "$(yaml_get "process" "interval_sec" "10")" 10)
  suspicious=$(yaml_get_array "process" "suspicious")
  while true; do
    monitor_enabled process || { sleep "$interval"; continue; }
    local procs; procs=$(ps aux 2>/dev/null || ps -ef 2>/dev/null || true)
    for s in $suspicious; do
      [ -z "$s" ] && continue
      if echo "$procs" | grep -Eiq "[[:space:]]${s}[[:space:]]|${s}$|/${s}"; then
        alert WARN "Suspicious process detected: $s"
      fi
    done
    write_json "${NS_LOGS}/process.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_userlogins(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/userlogins:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 30)
  local prev_hash=""
  while true; do
    monitor_enabled userlogins || { sleep "$interval"; continue; }
    local users; users=$(who 2>/dev/null || true)
    local cur_hash; cur_hash=$(printf '%s' "$users" | sha256sum | awk '{print $1}')
    if [ -n "$prev_hash" ] && [ "$cur_hash" != "$prev_hash" ]; then
      alert INFO "User sessions changed: $(echo "$users" | tr '\n' '; ')"
    fi
    prev_hash="$cur_hash"
    local users_json; users_json=$(printf '%s' "$users" | python3 -c '
import sys, json
print(json.dumps(sys.stdin.read()))
')
    write_json "${NS_LOGS}/user.json" "{\"ts\":\"$(ns_now)\",\"who\":${users_json:-\"\"}}"
    sleep "$interval"
  done
}

_monitor_services(){
  set +e; set +o pipefail
  local interval targets
  interval=$(ensure_int "$(yaml_get "services" "interval_sec" "20")" 20)
  targets=$(yaml_get_array "services" "targets")
  while true; do
    monitor_enabled services || { sleep "$interval"; continue; }
    for svc in $targets; do
      [ -z "$svc" ] && continue
      if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$svc" 2>/dev/null || alert CRIT "Service $svc is not active!"
      else
        pgrep -f "$svc" >/dev/null 2>&1 || alert WARN "Service process not found: $svc"
      fi
    done
    write_json "${NS_LOGS}/service.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_logs(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/logs:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 15)
  local files patterns; files=$(awk -F'[][]' '/logs:/,/\}/ { if($0 ~ /files:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' ' ')
  patterns=$(awk -F'[][]' '/logs:/,/\}/ { if($0 ~ /patterns:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '|')
  [ -z "$patterns" ] && patterns="error|failed|denied|segfault"
  local state="${NS_CTRL}/logwatch.state"; touch "$state" || true
  while true; do
    monitor_enabled logs || { sleep "$interval"; continue; }
    for f in $files; do
      [ -f "$f" ] || continue
      local size from
      size=$(stat -c%s "$f" 2>/dev/null || wc -c <"$f" 2>/dev/null || echo 0)
      from=$(awk -v F="$f" '$1==F{print $2}' "$state" 2>/dev/null | tail -n1)
      [ -z "$from" ] && from=0
      if [ "$size" -gt "$from" ]; then
        tail -c +"$((from+1))" "$f" 2>/dev/null | grep -Eai "$patterns" | while IFS= read -r line; do
          alert WARN "Log anomaly in $(basename "$f"): $line"
        done
      fi
      if grep -q "^$f " "$state" 2>/dev/null; then
        sed -i "s|^$f .*|$f $size|" "$state" 2>/dev/null || true
      else
        echo "$f $size" >>"$state"
      fi
    done
    write_json "${NS_LOGS}/logwatch.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_supervisor(){
  set +e; set +o pipefail
  local interval=10
  while true; do
    # Only perform auto-restart if explicitly enabled (opt-in for stable behavior)
    if is_auto_restart_enabled; then
      for p in cpu memory disk network integrity process userlogins services logs; do
        if [ -f "${NS_PID}/${p}.pid" ]; then
          local pid; pid=$(safe_read_pid "${NS_PID}/${p}.pid")
          if [ "$pid" -eq 0 ] || ! kill -0 "$pid" 2>/dev/null; then
            alert ERROR "Monitor $p crashed. Restarting."
            case "$p" in
              cpu) _monitor_cpu & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              memory) _monitor_mem & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              disk) _monitor_disk & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              network) _monitor_net & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              integrity) _monitor_integrity & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              process) _monitor_process & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              userlogins) _monitor_userlogins & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              services) _monitor_services & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
              logs) _monitor_logs & safe_write_pid "${NS_PID}/${p}.pid" $! ;;
            esac
          fi
        fi
      done
      if [ -f "${NS_PID}/web.pid" ]; then
        local wpid; wpid=$(safe_read_pid "${NS_PID}/web.pid")
        if [ "$wpid" -eq 0 ] || ! kill -0 "$wpid" 2>/dev/null; then
          alert ERROR "Web server crashed. Restarting."
          start_web || true
        fi
      fi
    else
      # In stable mode, just log crashed services without restarting
      for p in cpu memory disk network integrity process userlogins services logs; do
        if [ -f "${NS_PID}/${p}.pid" ]; then
          local pid; pid=$(safe_read_pid "${NS_PID}/${p}.pid")
          if [ "$pid" -eq 0 ] || ! kill -0 "$pid" 2>/dev/null; then
            alert WARN "Monitor $p crashed. Auto-restart disabled - manual restart required."
          fi
        fi
      done
      if [ -f "${NS_PID}/web.pid" ]; then
        local wpid; wpid=$(safe_read_pid "${NS_PID}/web.pid")
        if [ "$wpid" -eq 0 ] || ! kill -0 "$wpid" 2>/dev/null; then
          alert WARN "Web server crashed. Auto-restart disabled - manual restart required."
        fi
      fi
    fi
    sleep "$interval"
  done
}

_monitor_scheduler(){
  set +e; set +o pipefail
  local interval; interval=$(ensure_int "$(yaml_get "scheduler" "interval_sec" "30")" 30)
  : >"$NS_SCHED_STATE" || true
  while true; do
    monitor_enabled scheduler || { sleep "$interval"; continue; }
    local now_hm; now_hm=$(date +%H:%M)
    local ran_today_key="$(date +%Y-%m-%d)"
    awk '/scheduler:/,/tasks:/{print}' "$NS_CONF" >/dev/null 2>&1 || { sleep "$interval"; continue; }
    local names; names=$(awk '/tasks:/,0{if($1=="-"){print $0}}' "$NS_CONF" 2>/dev/null || true)
    local IFS=$'\n'
    for line in $names; do
      local name action time every
      name=$(echo "$line" | awk -v RS=',' -F'name:' '{print $2}' | head -n1 | tr -d '"' | tr -d ' ' || true)
      action=$(echo "$line" | awk -v RS=',' -F'action:' '{print $2}' | head -n1 | tr -d '"' | tr -d ' ' || true)
      time=$(echo "$line" | awk -v RS=',' -F'time:' '{print $2}' | head -n1 | tr -d '"' | tr -d ' ' || true)
      every=$(echo "$line" | awk -v RS=',' -F'every_n_min:' '{print $2}' | head -n1 | tr -d '"' | tr -d ' ' || true)
      [ -z "$name" ] && continue
      if [ -n "$time" ] && [ "$time" = "$now_hm" ]; then
        if ! grep -q "^$ran_today_key $name$" "$NS_SCHED_STATE" 2>/dev/null; then
          ns_log "Scheduler running '$name' ($action at $time)"; scheduler_run_action "$action"
          echo "$ran_today_key $name" >>"$NS_SCHED_STATE"
        fi
      fi
      if [ -n "$every" ]; then
        local mod=$(( $(date +%s) / 60 % every ))
        if [ "$mod" -eq 0 ]; then
          ns_log "Scheduler running '$name' (every ${every}m: $action)"; scheduler_run_action "$action"
        fi
      fi
    done
    sleep "$interval"
  done
}

scheduler_run_action(){
  local act="$1"
  case "$act" in
    backup) backup_snapshot;;
    version) version_snapshot;;
    restart_monitors) restart_monitors;;
    *) if [ -x "${NS_MODULES}/${act}.sh" ]; then "${NS_MODULES}/${act}.sh" || alert ERROR "Module ${act} failed"; else ns_warn "Unknown scheduler action: $act"; fi ;;
  esac
}

_spawn_monitor(){ local name="$1"; shift; "$@" & safe_write_pid "${NS_PID}/${name}.pid" $!; }

start_monitors(){
  ns_log "Starting monitors..."
  stop_monitors || true
  _spawn_monitor cpu _monitor_cpu
  _spawn_monitor memory _monitor_mem
  _spawn_monitor disk _monitor_disk
  _spawn_monitor network _monitor_net
  _spawn_monitor integrity _monitor_integrity
  _spawn_monitor process _monitor_process
  _spawn_monitor userlogins _monitor_userlogins
  _spawn_monitor services _monitor_services
  _spawn_monitor logs _monitor_logs
  _spawn_monitor scheduler _monitor_scheduler
  
  # Only start supervisor if auto-restart is enabled (opt-in feature)
  if is_auto_restart_enabled; then
    _spawn_monitor supervisor _supervisor
    ns_log "Auto-restart supervisor enabled"
  else
    ns_log "Auto-restart disabled - services will not auto-restart if they crash"
  fi
  
  ns_ok "Monitors started"
}

stop_monitors(){
  local any=0
  for p in cpu memory disk network integrity process userlogins services logs scheduler supervisor; do
    if [ -f "${NS_PID}/${p}.pid" ]; then
      local pid; pid=$(safe_read_pid "${NS_PID}/${p}.pid")
      if [ "$pid" -gt 0 ]; then
        kill "$pid" 2>/dev/null || true
      fi
      rm -f "${NS_PID}/${p}.pid"
      any=1
    fi
  done
  [ "$any" -eq 1 ] && ns_ok "Monitors stopped" || true
}

# ------------------------------ PY WEB SERVER --------------------------------
# Hardened server with: robust nested YAML, CSRF, optional 2FA, rate-limit/lockout/IP lists,
# WebSocket terminal, FS ops, site builder, TLS, /logout and /api/whoami.
write_server_py(){
  write_file "${NS_WWW}/server.py" 700 <<'PY'
#!/usr/bin/env python3
import struct, hmac, ssl, datetime, random, re, signal, subprocess, termios, json, os, sys, time, hashlib, http.cookies, socket, base64, threading, select, pty, tty, fcntl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
NS_KEYS = os.path.join(NS_HOME, 'keys')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')
INDEX = os.path.join(NS_WWW, 'index.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
JARVIS_MEM = os.path.join(NS_CTRL,'jarvis_memory.json')
AUDIT = os.path.join(NS_LOGS, 'audit.log')
SITE_DIR = os.path.join(NS_HOME, 'site')
RL_DB = os.path.join(NS_CTRL,'ratelimit.json')
BANS_DB = os.path.join(NS_CTRL,'bans.json')

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'  # WebSocket

# Environment variable checks
AUTH_STRICT = os.environ.get('NOVASHIELD_AUTH_STRICT', '1') == '1'

def py_alert(level, msg):
    """Helper to log security alerts to alerts.log in the same format as bash alert()"""
    try:
        alerts_path = os.path.join(NS_LOGS, 'alerts.log')
        Path(os.path.dirname(alerts_path)).mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(alerts_path, 'a', encoding='utf-8') as f:
            f.write(f"{timestamp} [{level}] {msg}\n")
    except Exception:
        pass

def read_text(path, default=''):
    try: return open(path,'r',encoding='utf-8').read()
    except Exception: return default

def write_text(path, data):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(data)

def read_json(path, default=None):
    try: return json.loads(read_text(path,''))
    except Exception: return default

def write_json(path, obj):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(json.dumps(obj))

# -------- Robust YAML (minimal) -> nested dict (no external deps) -------------
def yaml_tree():
    try:
        root = {}
        stack = [(-1, root)]
        with open(CONFIG,'r',encoding='utf-8') as f:
            for raw in f:
                s = raw.split('#',1)[0].rstrip('\n')
                if not s.strip():
                    continue
                indent = len(s) - len(s.lstrip())
                while stack and indent <= stack[-1][0]:
                    stack.pop()
                parent = stack[-1][1] if stack else root
                ss = s.strip()
                if ss.startswith('- '):
                    val = ss[2:].strip().strip('"').strip("'")
                    if isinstance(parent, list):
                        parent.append(val)
                    else:
                        parent.setdefault('_list', []).append(val)
                    continue
                if ':' in ss:
                    k, v = ss.split(':',1)
                    k = k.strip()
                    v = v.strip()
                    if v == '':
                        node = {}
                        if isinstance(parent, dict):
                            parent[k] = node
                        elif isinstance(parent, list):
                            parent.append({k: node})
                            node = parent[-1][k]
                        stack.append((indent, node))
                    else:
                        vv = v.strip().strip('"').strip("'")
                        parent[k] = vv
        def normalize(obj):
            if isinstance(obj, dict):
                for k in list(obj.keys()):
                    obj[k] = normalize(obj[k])
                if '_list' in obj and len(obj)==1:
                    return obj['_list']
                return obj
            if isinstance(obj, list):
                return [normalize(x) for x in obj]
            return obj
        return normalize(root)
    except Exception:
        return {}

CFG = None
def cfg_reload():
    global CFG
    CFG = yaml_tree()

def cfg_get(path, default=None):
    if CFG is None:
        cfg_reload()
    cur = CFG
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur

def _coerce_bool(v, default=False):
    if isinstance(v, bool): return v
    if isinstance(v, str):
        vl=v.strip().lower()
        if vl in ('true','yes','1','on'): return True
        if vl in ('false','no','0','off'): return False
    return default

def _coerce_int(v, default=0):
    try: return int(v)
    except Exception: return default

# ------------------------------- Security helpers -----------------------------
def auth_enabled(): return _coerce_bool(cfg_get('security.auth_enabled', True), True)
def csrf_required(): return _coerce_bool(cfg_get('security.csrf_required', True), True)
def require_2fa(): return _coerce_bool(cfg_get('security.require_2fa', False), False)
def rate_limit_per_min(): return _coerce_int(cfg_get('security.rate_limit_per_min', 60), 60)
def lockout_threshold(): return _coerce_int(cfg_get('security.lockout_threshold', 10), 10)

def ip_lists():
    allow = cfg_get('security.ip_allowlist', []) or []
    deny  = cfg_get('security.ip_denylist', []) or []
    if isinstance(allow, str): allow = [x.strip() for x in allow.strip('[]').replace('"','').split(',') if x.strip()]
    if isinstance(deny, str):  deny  = [x.strip() for x in deny.strip('[]').replace('"','').split(',') if x.strip()]
    return allow, deny

def audit(msg):
    try:
        with open(AUDIT,'a',encoding='utf-8') as f: f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+'\n')
    except Exception: pass

def users_db():
    return read_json(SESSIONS, {}) or {}

def set_users_db(j):
    write_json(SESSIONS, j)

def users_list():
    db = users_db()
    return db.get('_userdb', {})

def user_2fa_secret(user):
    return (users_db().get('_2fa', {}) or {}).get(user)

def set_user(username, pass_sha):
    db = users_db()
    ud = db.get('_userdb', {})
    ud[username]=pass_sha
    db['_userdb']=ud
    set_users_db(db)

def set_2fa(username, secret_b32):
    db = users_db()
    tow = db.get('_2fa', {})
    tow[username]=secret_b32
    db['_2fa']=tow
    set_users_db(db)

def check_login(username, password):
    salt = cfg_get('security.auth_salt','change-this-salt')
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    return users_list().get(username,'')==sha

def totp_now(secret_b32, t=None):
    if not secret_b32: return None
    try:
        pad = '=' * ((8 - (len(secret_b32) % 8)) % 8)
        key = base64.b32decode((secret_b32.upper() + pad).encode())
    except Exception:
        return None
    if t is None: t = int(time.time())
    steps = int(t/30)
    msg = steps.to_bytes(8,'big')
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 0x0f
    code = (int.from_bytes(h[o:o+4],'big') & 0x7fffffff) % 1000000
    return f'{code:06d}'

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}:{os.urandom(8)}'.encode()).hexdigest()
    csrf  = hashlib.sha256(f'csrf:{token}:{os.urandom(8)}'.encode()).hexdigest()
    db = users_db()
    # Add session TTL support
    session_ttl_minutes = _coerce_int(cfg_get('security.session_ttl_minutes', 120), 120)
    expires = int(time.time()) + (session_ttl_minutes * 60)
    db[token]={'user':username,'ts':int(time.time()),'csrf':csrf,'expires':expires}
    set_users_db(db)
    return token, csrf

def get_session(handler):
    if not auth_enabled(): return {'user':'public','csrf':'public'}
    if 'Cookie' not in handler.headers: return None
    C = http.cookies.SimpleCookie()
    C.load(handler.headers['Cookie'])
    if 'NSSESS' not in C: return None
    token = C['NSSESS'].value
    db = users_db()
    session = db.get(token)
    if not session:
        return None
    # Check session expiry
    current_time = int(time.time())
    session_expires = session.get('expires', 0)
    if session_expires > 0 and current_time > session_expires:
        # Session expired, remove it
        del db[token]
        set_users_db(db)
        return None
    return session

def require_auth(handler):
    client_ip = handler.client_address[0]
    user_agent = handler.headers.get('User-Agent', 'Unknown')
    path = getattr(handler, 'path', 'unknown')
    
    allow, deny = ip_lists()
    if deny and (client_ip in deny or ('0.0.0.0/0' in deny)):
        # Log forbidden access attempts
        security_log_path = os.path.join(NS_LOGS, 'security.log')
        try:
            Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
            with open(security_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [FORBIDDEN] IP={client_ip} Path={path} Reason=denied_list UserAgent='{user_agent[:100]}'\n")
        except Exception: pass
        py_alert('WARN', f'403 FORBIDDEN access from denied IP {client_ip} to {path}')
        handler._set_headers(403); handler.wfile.write(b'{"error":"forbidden"}'); return False
        
    if allow and client_ip not in allow:
        # Log unauthorized access attempts
        security_log_path = os.path.join(NS_LOGS, 'security.log')
        try:
            Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
            with open(security_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [FORBIDDEN] IP={client_ip} Path={path} Reason=not_in_allow_list UserAgent='{user_agent[:100]}'\n")
        except Exception: pass
        py_alert('WARN', f'403 FORBIDDEN access from non-allowed IP {client_ip} to {path}')
        handler._set_headers(403); handler.wfile.write(b'{"error":"forbidden"}'); return False
        
    if not auth_enabled(): return True
    sess = get_session(handler)
    if not sess:
        # Log unauthorized access attempts
        security_log_path = os.path.join(NS_LOGS, 'security.log')
        try:
            Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
            with open(security_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [UNAUTHORIZED] IP={client_ip} Path={path} Reason=no_session UserAgent='{user_agent[:100]}'\n")
        except Exception: pass
        py_alert('INFO', f'401 UNAUTHORIZED access from {client_ip} to {path} (no session)')
        handler._set_headers(401); handler.wfile.write(b'{"error":"unauthorized"}'); return False
        
    if csrf_required() and handler.command=='POST':
        client_csrf = handler.headers.get('X-CSRF','')
        if client_csrf != sess.get('csrf',''):
            # Log CSRF token failures
            security_log_path = os.path.join(NS_LOGS, 'security.log')
            try:
                Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
                with open(security_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [CSRF_FAIL] IP={client_ip} Path={path} UserAgent='{user_agent[:100]}'\n")
            except Exception: pass
            py_alert('WARN', f'CSRF failure from {client_ip} to {path}')
            handler._set_headers(403); handler.wfile.write(b'{"error":"csrf"}'); return False
    return True

def rate_limit_ok(handler, key='default'):
    ip = handler.client_address[0]
    now = int(time.time())
    rl = read_json(RL_DB,{}) or {}
    per = rate_limit_per_min()
    win = now // 60
    ent = rl.get(ip, {'win':win,'cnt':0,'lock':0})
    if ent.get('lock',0) and ent['lock']>now:
        return False
    if ent.get('win')!=win:
        ent={'win':win,'cnt':0,'lock':0}
    ent['cnt']=ent.get('cnt',0)+1
    if ent['cnt']>per:
        ent['lock']=now+min(900, int((ent['cnt']-per)*2))
    rl[ip]=ent
    write_json(RL_DB, rl)
    return ent['cnt']<=per

def login_fail(handler):
    ip=handler.client_address[0]
    user_agent = handler.headers.get('User-Agent', 'Unknown')
    rl = read_json(BANS_DB,{}) or {}
    now=int(time.time())
    ent = rl.get(ip, {'fails':0,'lock':0})
    ent['fails']=ent.get('fails',0)+1
    if ent['fails']>=lockout_threshold():
        ent['lock']=now+900
    rl[ip]=ent
    write_json(BANS_DB, rl)
    
    # Enhanced session logging with detailed connection info
    session_log_entry = f"FAILED_LOGIN ip={ip} fails={ent['fails']} locked={'yes' if ent.get('lock', 0) > now else 'no'} user_agent='{user_agent[:100]}'"
    session_log_path = os.path.join(NS_HOME, 'session.log')
    try:
        with open(session_log_path, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {session_log_entry}\n")
    except Exception: pass
    
    # Enhanced security logging for failed attempts
    security_log_path = os.path.join(NS_LOGS, 'security.log')
    try:
        Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
        with open(security_log_path, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [AUTH_FAIL] IP={ip} Fails={ent['fails']} UserAgent='{user_agent[:100]}'\n")
    except Exception: pass

def login_ok(handler):
    ip=handler.client_address[0]
    user_agent = handler.headers.get('User-Agent', 'Unknown')
    rl = read_json(BANS_DB,{}) or {}
    if ip in rl: rl.pop(ip,None); write_json(BANS_DB, rl)
    
    # Enhanced session logging with connection details
    session_log_entry = f"SUCCESSFUL_LOGIN ip={ip} cleared_ban=yes user_agent='{user_agent[:100]}'"
    session_log_path = os.path.join(NS_HOME, 'session.log')
    try:
        with open(session_log_path, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {session_log_entry}\n")
    except Exception: pass
    
    # Enhanced security logging for successful logins
    security_log_path = os.path.join(NS_LOGS, 'security.log')
    try:
        Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
        with open(security_log_path, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [AUTH_SUCCESS] IP={ip} UserAgent='{user_agent[:100]}'\n")
    except Exception: pass

def banned(handler):
    ip=handler.client_address[0]
    rl = read_json(BANS_DB,{}) or {}
    now=int(time.time())
    ent=rl.get(ip)
    return bool(ent and ent.get('lock',0)>now)

def last_lines(path, n=100):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END); size=f.tell(); block=1024; data=b''
            while size>0 and n>0:
                step=min(block,size); size-=step; f.seek(size); buf=f.read(step); data=buf+data; n-=buf.count(b'\n')
            return data.decode('utf-8','ignore').splitlines()[-n:]
    except Exception:
        return []

# Old ai_reply function removed - using enhanced version below

# ------------------------------- WebSocket PTY -------------------------------

def ws_recv(sock):
    hdr = sock.recv(2)
    if not hdr: return None, None
    opcode = hdr[0] & 0x0f
    masked = hdr[1] & 0x80
    length = hdr[1] & 0x7f
    if length==126:
        ext = sock.recv(2); length = int.from_bytes(ext,'big')
    elif length==127:
        ext = sock.recv(8); length = int.from_bytes(ext,'big')
    mask = sock.recv(4) if masked else b'\x00\x00\x00\x00'
    data = b''
    while len(data)<length:
        chunk = sock.recv(length-len(data))
        if not chunk: break
        data += chunk
    if masked:
        data = bytes(b ^ mask[i%4] for i,b in enumerate(data))
    return opcode, data

def ws_send(sock, data, opcode=1):
    if isinstance(data,str): data = data.encode()
    length = len(data)
    hdr = bytearray()
    hdr.append(0x80 | (opcode & 0x0f))
    if length<126:
        hdr.append(length)
    elif length<65536:
        hdr.append(126); hdr += length.to_bytes(2,'big')
    else:
        hdr.append(127); hdr += length.to_bytes(8,'big')
    sock.send(bytes(hdr)+data)

def spawn_pty(shell=None, cols=120, rows=32):
    pid, fd = pty.fork()
    if pid==0:
    # Child
        try:
            if shell is None or not shell:
                shell = os.environ.get('SHELL','')
            if not shell:
                # Improved shell resolution with Termux bash preference
                for cand in ('/data/data/com.termux/files/usr/bin/bash','/bin/bash','/bin/zsh','/system/bin/sh','/bin/sh'):
                    if os.path.exists(cand): shell=cand; break
            os.execv(shell, [shell, '-l'])
        except Exception as e:
            os.write(1, f'Failed to start shell: {e}\n'.encode())
            os._exit(1)
    # Parent
    # Ensure proper window size is set
    winsz = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(fd, tty.TIOCSWINSZ, winsz)
    except Exception:
        pass
    return pid, fd

def mirror_terminal(handler):
    if not require_auth(handler): return
    if not ws_handshake(handler): return
    sess = get_session(handler)
    user = sess.get('user','?') if sess else '?'
    client = handler.connection
    cols = _coerce_int(cfg_get('terminal.cols', 120), 120)
    rows = _coerce_int(cfg_get('terminal.rows', 32), 32)
    shell = cfg_get('terminal.shell', '') or None
    idle_timeout = _coerce_int(cfg_get('terminal.idle_timeout_sec', 900), 900)
    allow_write = _coerce_bool(cfg_get('terminal.allow_write', 'true'), True)
    
    # Create a real PTY
    pid, fd = spawn_pty(shell, cols, rows)
    audit(f'TERM START user={user} pid={pid} ip={handler.client_address[0]}')
    last_activity = time.time()
    
    # Set terminal to raw mode
    old_attr = None
    try:
        old_attr = termios.tcgetattr(fd)
        tty.setraw(fd, termios.TCSANOW)
    except:
        pass
    
    # Reader thread to send terminal output to websocket
    def reader():
        try:
            while True:
                r, _, _ = select.select([fd], [], [], 0.1)
                if fd in r:
                    try:
                        data = os.read(fd, 8192)
                        if not data: break
                        ws_send(client, data, opcode=2)
                    except OSError:
                        break
        finally:
            try: os.close(fd)
            except: pass
            try: os.kill(pid, signal.SIGTERM)
            except: pass
    
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    
    # Process websocket input
    try:
        while True:
            if time.time() - last_activity > idle_timeout:
                ws_send(client, '\r\n[Session idle timeout]\r\n')
                break
                
            opcode, data = ws_recv(client)
            if opcode is None: break
            last_activity = time.time()
            
            if opcode == 8:  # Close frame
                break
                
            if opcode in (1, 2) and allow_write:  # Text/binary frame
                try:
                    # Try to parse as JSON for resize frames
                    if opcode == 1:  # Text frame
                        try:
                            frame_text = data.decode('utf-8')
                            frame_data = json.loads(frame_text)
                            if frame_data.get('type') == 'resize' and 'cols' in frame_data and 'rows' in frame_data:
                                # Handle terminal resize
                                cols = int(frame_data['cols'])
                                rows = int(frame_data['rows'])
                                winsz = struct.pack("HHHH", rows, cols, 0, 0)
                                fcntl.ioctl(fd, tty.TIOCSWINSZ, winsz)
                                continue  # Don't write JSON to PTY
                        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                            # Not JSON, treat as regular terminal input
                            pass
                    
                    # Regular terminal input - write to PTY
                    os.write(fd, data)
                except Exception:
                    break
    except Exception:
        pass
    finally:
        try: ws_send(client, '\r\n[Session ended]\r\n')
        except: pass
        try: os.kill(pid, signal.SIGTERM)
        except: pass
        audit(f'TERM END user={user} pid={pid} ip={handler.client_address[0]}')

# Add these functions before the Handler class:
def load_jarvis_memory():
    """Load Jarvis conversation memory."""
    memory = read_json(JARVIS_MEM, None)
    if not memory:
        memory = {"conversations": []}
        write_json(JARVIS_MEM, memory)
    return memory

def save_jarvis_memory(memory):
    """Save Jarvis conversation memory."""
    write_json(JARVIS_MEM, memory)

def sanitize_username(username):
    """Sanitize username for safe filename usage."""
    import re
    # Keep only alphanumeric, underscore, hyphen, and dots
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', str(username))
    # Limit length and ensure it's not empty
    safe_name = safe_name[:50] if safe_name else 'anonymous'
    return safe_name

def user_memory_path(username):
    """Get the path to a user's encrypted memory file."""
    safe_username = sanitize_username(username)
    return os.path.join(NS_CTRL, f'memory_{safe_username}.enc')

def load_user_memory(username):
    """Load per-user encrypted memory, fallback to plaintext if encryption fails."""
    safe_username = sanitize_username(username)
    enc_path = user_memory_path(username)
    json_path = os.path.join(NS_CTRL, f'memory_{safe_username}.json')
    
    # Default empty memory structure
    default_memory = {
        "conversations": [],
        "preferences": {"theme": "jarvis-dark", "last_active_tab": "ai"},
        "last_seen": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Try to load encrypted file first
    if os.path.exists(enc_path):
        try:
            # Use openssl to decrypt
            aes_key_path = os.path.join(NS_KEYS, 'aes.key')
            if os.path.exists(aes_key_path):
                # Read the key
                with open(aes_key_path, 'rb') as f:
                    aes_key = f.read().strip()
                
                # Decrypt using openssl
                cmd = ['openssl', 'aes-256-cbc', '-d', '-salt', '-pbkdf2', '-in', enc_path, '-pass', f'file:{aes_key_path}']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    return json.loads(result.stdout)
        except Exception as e:
            # Log error but continue with fallback
            py_alert('WARN', f'Failed to decrypt user memory for {username}: {str(e)}')
    
    # Fallback to plaintext JSON file
    if os.path.exists(json_path):
        try:
            return read_json(json_path, default_memory)
        except Exception:
            pass
    
    # Return default memory if no file exists
    return default_memory

def save_user_memory(username, data):
    """Save per-user encrypted memory, fallback to plaintext if encryption fails."""
    safe_username = sanitize_username(username)
    enc_path = user_memory_path(username)
    json_path = os.path.join(NS_CTRL, f'memory_{safe_username}.json')
    
    # Ensure data has required structure
    if not isinstance(data, dict):
        data = {"conversations": [], "preferences": {}, "last_seen": time.strftime('%Y-%m-%d %H:%M:%S')}
    
    # Ensure directory exists
    Path(NS_CTRL).mkdir(parents=True, exist_ok=True)
    
    # Try to encrypt and save
    aes_key_path = os.path.join(NS_KEYS, 'aes.key')
    if os.path.exists(aes_key_path):
        try:
            # Convert data to JSON
            json_data = json.dumps(data)
            
            # Encrypt using openssl
            cmd = ['openssl', 'aes-256-cbc', '-salt', '-pbkdf2', '-out', enc_path, '-pass', f'file:{aes_key_path}']
            result = subprocess.run(cmd, input=json_data, text=True, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                # Successfully encrypted, remove any old plaintext file
                if os.path.exists(json_path):
                    try:
                        os.remove(json_path)
                    except Exception:
                        pass
                return
        except Exception as e:
            py_alert('WARN', f'Failed to encrypt user memory for {username}: {str(e)}')
    
    # Fallback to plaintext JSON
    try:
        write_json(json_path, data)
    except Exception as e:
        py_alert('ERROR', f'Failed to save user memory for {username}: {str(e)}')

def get_jarvis_personality():
    """Get the configured Jarvis personality type."""
    personality = cfg_get('jarvis.personality', 'helpful').lower()
    if personality not in ('helpful', 'snarky', 'professional'):
        personality = 'helpful'
    return personality

def ai_reply(prompt, username, user_ip):
    """Generate a more Jarvis-like reply with per-user memory and expanded intents."""
    if not prompt or not prompt.strip():
        return "How can I assist you today?"
    
    prompt_low = prompt.lower()
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Load per-user memory using new encrypted system
    user_memory = load_user_memory(username)
    user_memory["last_seen"] = now
    
    # Status data collection
    status = {
        'cpu': read_json(os.path.join(NS_LOGS,'cpu.json'),{}),
        'mem': read_json(os.path.join(NS_LOGS,'memory.json'),{}),
        'disk': read_json(os.path.join(NS_LOGS,'disk.json'),{}),
        'net': read_json(os.path.join(NS_LOGS,'network.json'),{}),
    }
    
    # Get personality traits
    personality = get_jarvis_personality()
    
    # Add this conversation to user memory
    memory_size = _coerce_int(cfg_get('jarvis.memory_size', 10), 10)
    user_memory["conversations"].append({
        "timestamp": now,
        "prompt": prompt,
        "context": {
            "cpu_load": status['cpu'].get('load1','?'),
            "mem_used": status['mem'].get('used_pct','?'),
            "disk_used": status['disk'].get('use_pct','?')
        }
    })
    
    # Keep memory at configured size
    if len(user_memory["conversations"]) > memory_size:
        user_memory["conversations"] = user_memory["conversations"][-memory_size:]
    
    save_user_memory(username, user_memory)
    
    # Expanded intents processing
    # Status intent
    if any(term in prompt_low for term in ['status', 'health', 'system', 'how are you']):
        cpu_load = status['cpu'].get('load1', '?')
        mem_pct = status['mem'].get('used_pct', '?')
        disk_pct = status['disk'].get('use_pct', '?')
        
        if personality == 'snarky':
            return f"Systems are running, {username}. CPU: {cpu_load}, Memory: {mem_pct}%, Disk: {disk_pct}%. Anything else you need to micromanage?"
        elif personality == 'professional':
            return f"System status report: CPU load {cpu_load}, Memory usage {mem_pct}%, Disk usage {disk_pct}%. All systems operational."
        else:
            return f"All systems running smoothly, {username}. CPU load: {cpu_load}, Memory: {mem_pct}%, Disk: {disk_pct}%."
    
    # Backup intent
    elif any(term in prompt_low for term in ['backup', 'create backup']):
        return f"I'll initiate a backup for you, {username}. This will create an encrypted snapshot of your critical files and configurations."
    
    # Version/snapshot intent
    elif any(term in prompt_low for term in ['version', 'snapshot']):
        version = read_text(os.path.join(NS_HOME,'version.txt'),'3.1.0')
        return f"Current NovaShield version is {version}. I can create a version snapshot if you'd like."
    
    # Restart monitors intent
    elif any(term in prompt_low for term in ['restart monitor', 'restart service']):
        return f"Restarting monitoring services, {username}. This will briefly pause data collection while services reload."
    
    # IP info intent
    elif any(term in prompt_low for term in ['ip', 'network info', 'my ip']):
        local_ip = status['net'].get('ip', 'unknown')
        public_ip = status['net'].get('public_ip', 'unknown')
        return f"Your local IP is {local_ip}, public IP is {public_ip}. Network status: {status['net'].get('level', 'OK')}."
    
    # Show alerts intent
    elif any(term in prompt_low for term in ['alerts', 'show alerts', 'warnings']):
        return f"Checking alerts for you, {username}. Switch to the Alerts tab to see recent system notifications and warnings."
    
    # Show logs intent  
    elif any(term in prompt_low for term in ['logs', 'show logs', 'security logs']):
        return f"Security logs are available in the Security tab, {username}. I monitor all authentication attempts, audit events, and system access."
    
    # Terminal intent
    elif any(term in prompt_low for term in ['terminal', 'command line', 'shell']):
        return f"Opening terminal access, {username}. Switch to the Terminal tab for full command-line interface with real-time I/O."
    
    # List files intent
    elif any(term in prompt_low for term in ['files', 'list files', 'file manager']):
        return f"File manager is available in the Files tab, {username}. You can browse, view, and manage your system files there."
    
    # Web generation intent
    elif any(term in prompt_low for term in ['webgen', 'create page', 'web builder']):
        return f"Web Builder is ready, {username}. You can create custom HTML pages in the Web Builder tab - perfect for documentation or reports."
    
    # Whoami intent
    elif any(term in prompt_low for term in ['who am i', 'whoami', 'my info']):
        last_seen = user_memory.get('last_seen', 'first time')
        convo_count = len(user_memory.get('conversations', []))
        return f"You are {username}, last active: {last_seen}. We've had {convo_count} conversations. Your preferred theme: {user_memory['preferences'].get('theme', 'default')}."
    
    # Help intent
    elif any(term in prompt_low for term in ['help', 'what can you do', 'commands']):
        tools_count = len(scan_system_tools())
        return f"I can help with: system status, backups, version info, restart monitors, show IP info, alerts, logs, terminal access, file management, web generation, and {tools_count} system tools. I also remember our conversations and learn from them, {username}! Try asking about 'tools', 'security scan', or 'system info'."
    
    # Tools intent
    elif any(term in prompt_low for term in ['tools', 'scan tools', 'available tools', 'what tools']):
        tools = scan_system_tools()
        available = [name for name, info in tools.items() if info['available']]
        missing = [name for name, info in tools.items() if not info['available']]
        return f"I found {len(available)} available tools: {', '.join(available[:10])}{'...' if len(available) > 10 else ''}. Missing: {len(missing)} tools. I can install missing tools or run any available tool for you!"
    
    # Security scan intent
    elif any(term in prompt_low for term in ['security scan', 'security check', 'vulnerability scan', 'scan security']):
        try:
            scan_result = perform_basic_security_scan()
            summary_lines = scan_result.split('\n')[:10]  # First 10 lines for summary
            return f"Security scan completed! Here's a summary:\n\n" + '\n'.join(summary_lines) + f"\n\n{username}, I've found some security information. Check the Tools tab for the full report!"
        except Exception as e:
            return f"Sorry {username}, I encountered an error running the security scan: {str(e)}. You can try the security scan tool manually in the Tools tab."
    
    # System info intent
    elif any(term in prompt_low for term in ['system info', 'system report', 'hardware info', 'system details']):
        try:
            info_result = generate_system_info_report()
            summary_lines = info_result.split('\n')[:15]  # First 15 lines for summary
            return f"System information gathered! Here's a summary:\n\n" + '\n'.join(summary_lines) + f"\n\n{username}, I've compiled a comprehensive system report. Check the Tools tab for the complete details!"
        except Exception as e:
            return f"Sorry {username}, I couldn't generate the system report: {str(e)}. You can try the system-info tool in the Tools tab."
    
    # Log analysis intent
    elif any(term in prompt_low for term in ['analyze logs', 'log analysis', 'check logs', 'log report']):
        try:
            log_result = analyze_system_logs()
            summary_lines = [l for l in log_result.split('\n')[:20] if l.strip()]
            return f"Log analysis complete! Summary:\n\n" + '\n'.join(summary_lines) + f"\n\n{username}, I've analyzed your system logs. Check the Tools tab for detailed analysis!"
        except Exception as e:
            return f"Sorry {username}, I couldn't analyze the logs: {str(e)}. You can try the log-analyzer tool manually."
    
    # Install tools intent
    elif any(term in prompt_low for term in ['install tools', 'install missing', 'setup tools', 'get tools']):
        return f"I can install missing security and system tools for you, {username}! This includes nmap, htop, curl, wget, and many others. Use the 'Install Missing Tools' button in the Tools tab, or I can guide you through the process."
    
    # Performance intent
    elif any(term in prompt_low for term in ['performance', 'slow', 'speed', 'optimization', 'optimize']):
        try:
            # Quick performance check
            result = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')[1:6]  # Top 5 processes
            processes = []
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append(f"{parts[10]} ({parts[2]}% CPU)")
            
            return f"Performance check complete, {username}! Top CPU processes: " + ', '.join(processes) + ". I can run detailed system monitoring tools like htop, iotop, or vmstat for deeper analysis in the Tools tab."
        except Exception:
            return f"I can help optimize your system performance, {username}. Try running htop, vmstat, or iostat from the Tools tab to identify bottlenecks."
    
    # Network diagnostics intent
    elif any(term in prompt_low for term in ['network', 'connectivity', 'internet', 'ping', 'connection']):
        try:
            # Quick network test
            result = subprocess.run(['ping', '-c', '2', '8.8.8.8'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return f"Network connectivity is good, {username}! I can run more detailed network diagnostics like netstat, ss, nmap, or traceroute from the Tools tab for comprehensive analysis."
            else:
                return f"Network connectivity issues detected, {username}. I recommend running network diagnostic tools like ping, traceroute, or netstat from the Tools tab to troubleshoot."
        except Exception:
            return f"I can help diagnose network issues, {username}. Use the network tools in the Tools tab: ping, netstat, ss, nmap, or traceroute."
    
    # Learning and memory intent
    elif any(term in prompt_low for term in ['remember', 'memory', 'forget', 'learn']):
        convo_count = len(user_memory.get('conversations', []))
        return f"I remember our {convo_count} conversations, {username}. I learn from your preferences, command usage, and interaction patterns. You can view or clear my memory in the AI panel. I'm constantly improving based on our interactions!"
    
    # Advanced features intent
    elif any(term in prompt_low for term in ['advanced', 'expert', 'technical', 'professional']):
        return f"Advanced mode activated, {username}! I can execute system tools, analyze logs, perform security scans, generate reports, and provide technical insights. Try commands like 'run nmap localhost', 'analyze performance', or 'security audit' for detailed technical operations."
    
    # Tool execution intent - NEW CAPABILITY
    elif any(term in prompt_low for term in ['run ', 'execute ', 'launch ', 'start ']) and any(tool in prompt_low for tool in ['nmap', 'netstat', 'htop', 'ps', 'df', 'ping', 'curl', 'dig', 'ss']):
        # Extract tool name
        tool_match = None
        for tool in ['nmap', 'netstat', 'htop', 'ps', 'df', 'ping', 'curl', 'dig', 'ss']:
            if tool in prompt_low:
                tool_match = tool
                break
        
        if tool_match:
            try:
                # Execute the tool
                output = execute_tool(tool_match)
                return f"Executed {tool_match} for you, {username}:\n\n{output[:500]}{'...' if len(output) > 500 else ''}\n\nCheck the Tools tab for the complete output and to run more tools."
            except Exception as e:
                return f"I tried to run {tool_match} but encountered an error, {username}: {str(e)}. You can manually execute tools in the Tools tab."
        
    # Security scan intent - ENHANCED
    elif any(term in prompt_low for term in ['security scan', 'scan security', 'check security', 'security audit']):
        try:
            output = execute_tool('security-scan')
            return f"Security scan completed, {username}! Here's a summary:\n\n{output[:400]}{'...' if len(output) > 400 else ''}\n\nFull results are in the Tools tab. I can also run specific tools like nmap or netstat if needed."
        except Exception:
            return f"I'll perform a security scan, {username}. Switch to the Tools tab and run the Security Scan tool for comprehensive analysis."
    
    # System information intent - ENHANCED
    elif any(term in prompt_low for term in ['system info', 'system report', 'full status', 'detailed status']):
        try:
            output = execute_tool('system-info')
            return f"System report generated, {username}:\n\n{output[:400]}{'...' if len(output) > 400 else ''}\n\nComplete report available in the Tools tab."
        except Exception:
            return f"Generating detailed system report, {username}. Check the Tools tab for comprehensive system information and diagnostics."
    
    # Fallback responses based on personality
    if personality == 'snarky':
        return f"I'm not sure what you want, {username}. Try asking about status, backups, or saying 'help' for available commands."
    elif personality == 'professional':
        return f"I don't recognize that request, {username}. Please try asking about system status, backups, or type 'help' for available commands."
    else:
        return f"I'm here to help, {username}! Try asking about system status, creating backups, or say 'help' to see what I can do."

# Old ai_reply function removed - using enhanced version above

# ------------------------------- Tools Management Functions -------------------------------
def scan_system_tools():
    """Scan system for available tools and return their status."""
    tools = {
        # Security tools
        'nmap': {'description': 'Network Mapper - Port scanning and network discovery', 'category': 'security'},
        'netstat': {'description': 'Display network connections and listening ports', 'category': 'network'},
        'ss': {'description': 'Modern replacement for netstat - socket statistics', 'category': 'network'},
        'iptables': {'description': 'Configure Linux firewall rules', 'category': 'security'},
        
        # Network tools
        'ping': {'description': 'Test network connectivity to hosts', 'category': 'network'},
        'curl': {'description': 'Transfer data to/from servers - HTTP client', 'category': 'network'},
        'wget': {'description': 'Download files from web servers', 'category': 'network'},
        'dig': {'description': 'DNS lookup utility for domain name resolution', 'category': 'network'},
        'traceroute': {'description': 'Trace packet route to destination', 'category': 'network'},
        
        # System tools
        'htop': {'description': 'Interactive process viewer and system monitor', 'category': 'system'},
        'lsof': {'description': 'List open files and network connections', 'category': 'system'},
        'df': {'description': 'Display filesystem disk space usage', 'category': 'system'},
        'ps': {'description': 'Display running processes', 'category': 'system'},
        'top': {'description': 'Display system processes and resource usage', 'category': 'system'},
        'iotop': {'description': 'Display I/O usage by processes', 'category': 'system'},
        'iostat': {'description': 'I/O statistics monitoring', 'category': 'monitoring'},
        
        # Monitoring tools
        'vmstat': {'description': 'Virtual memory statistics', 'category': 'monitoring'},
        'sar': {'description': 'System activity reporter', 'category': 'monitoring'},
        'dstat': {'description': 'Versatile resource statistics', 'category': 'monitoring'},
        
        # Forensics tools
        'strings': {'description': 'Extract text strings from binary files', 'category': 'forensics'},
        'file': {'description': 'Determine file type', 'category': 'forensics'},
        'xxd': {'description': 'Hex dump utility', 'category': 'forensics'},
        'md5sum': {'description': 'Calculate MD5 checksums', 'category': 'forensics'},
        'sha256sum': {'description': 'Calculate SHA256 checksums', 'category': 'forensics'},
    }
    
    # Check availability of each tool
    for tool_name, tool_info in tools.items():
        try:
            result = subprocess.run(['which', tool_name], capture_output=True, timeout=5)
            tool_info['available'] = result.returncode == 0
            if tool_info['available']:
                tool_info['path'] = result.stdout.decode().strip()
            else:
                tool_info['path'] = None
        except Exception:
            tool_info['available'] = False
            tool_info['path'] = None
    
    return tools

def install_missing_tools():
    """Install commonly used security and system tools."""
    output = []
    
    # Detect package manager
    package_managers = [
        ('apt-get', ['apt-get', 'update', '&&', 'apt-get', 'install', '-y']),
        ('yum', ['yum', 'install', '-y']),
        ('dnf', ['dnf', 'install', '-y']),
        ('pacman', ['pacman', '-S', '--noconfirm']),
        ('pkg', ['pkg', 'install', '-y']),  # Termux
    ]
    
    pkg_manager = None
    install_cmd = None
    
    for manager, cmd in package_managers:
        try:
            result = subprocess.run(['which', manager], capture_output=True, timeout=5)
            if result.returncode == 0:
                pkg_manager = manager
                install_cmd = cmd
                break
        except Exception:
            continue
    
    if not pkg_manager:
        return "No supported package manager found (apt, yum, dnf, pacman, pkg)"
    
    output.append(f"Using package manager: {pkg_manager}")
    
    # Essential tools to install
    essential_tools = [
        'nmap', 'netstat-nat', 'curl', 'wget', 'dig', 'htop', 'lsof', 
        'iotop', 'dstat', 'traceroute', 'tcpdump', 'strings', 'file'
    ]
    
    # Adjust package names for different managers
    if pkg_manager == 'apt-get':
        tool_packages = {
            'netstat-nat': 'net-tools',
            'dig': 'dnsutils',
            'traceroute': 'traceroute',
            'tcpdump': 'tcpdump',
            'strings': 'binutils',
            'iotop': 'iotop',
            'dstat': 'dstat'
        }
    elif pkg_manager in ['yum', 'dnf']:
        tool_packages = {
            'netstat-nat': 'net-tools',
            'dig': 'bind-utils',
            'iotop': 'iotop',
            'dstat': 'dstat'
        }
    elif pkg_manager == 'pkg':  # Termux
        tool_packages = {
            'netstat-nat': 'net-tools',
            'dig': 'dnsutils',
            'iotop': 'iotop',
            'tcpdump': 'libpcap'
        }
    else:
        tool_packages = {}
    
    installed_count = 0
    for tool in essential_tools:
        package_name = tool_packages.get(tool, tool)
        try:
            # Check if already installed
            check_result = subprocess.run(['which', tool], capture_output=True, timeout=5)
            if check_result.returncode == 0:
                output.append(f"✓ {tool} already installed")
                continue
            
            # Install the package
            cmd = install_cmd + [package_name]
            if pkg_manager == 'apt-get':
                # For apt, run update first then install
                update_result = subprocess.run(['apt-get', 'update'], capture_output=True, timeout=30)
                cmd = ['apt-get', 'install', '-y', package_name]
            
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            
            if result.returncode == 0:
                output.append(f"✓ Installed {tool}")
                installed_count += 1
            else:
                output.append(f"✗ Failed to install {tool}: {result.stderr.decode()[:100]}")
                
        except subprocess.TimeoutExpired:
            output.append(f"✗ Timeout installing {tool}")
        except Exception as e:
            output.append(f"✗ Error installing {tool}: {str(e)}")
    
    output.append(f"\nInstallation summary: {installed_count} tools installed")
    return "\n".join(output)

def execute_custom_command(command):
    """Execute a custom command with safety checks."""
    if not command or not command.strip():
        return "Error: Empty command"
    
    # Basic safety check for dangerous commands
    dangerous_patterns = ['rm -rf', 'mkfs', 'dd if=', 'format', 'fdisk', 'shutdown', 'halt', 'init 0', 'init 6']
    for pattern in dangerous_patterns:
        if pattern in command.lower():
            return f"Error: Potentially dangerous command blocked: {pattern}"
    
    try:
        # Execute with timeout and capture output
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=NS_HOME
        )
        
        output = f"Command: {command}\n"
        output += f"Exit code: {result.returncode}\n\n"
        
        if result.stdout:
            output += "STDOUT:\n" + result.stdout + "\n"
        
        if result.stderr:
            output += "STDERR:\n" + result.stderr + "\n"
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after 30 seconds: {command}"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def execute_tool(tool_name):
    """Execute a system tool and return its output."""
    
    # Built-in custom tools
    if tool_name == 'system-info':
        return generate_system_info_report()
    elif tool_name == 'security-scan':
        return perform_basic_security_scan()
    elif tool_name == 'log-analyzer':
        return analyze_system_logs()
    
    # Predefined tool commands
    tool_commands = {
        'nmap': ['nmap', '-sT', '-O', 'localhost'],
        'netstat': ['netstat', '-tuln'],
        'ss': ['ss', '-tuln'],
        'iptables': ['iptables', '-L', '-n'],
        'ping': ['ping', '-c', '4', '8.8.8.8'],
        'curl': ['curl', '-I', 'http://httpbin.org/ip'],
        'wget': ['wget', '--spider', 'http://httpbin.org/ip'],
        'dig': ['dig', 'google.com'],
        'traceroute': ['traceroute', 'google.com'],
        'htop': ['htop', '--version'],  # Safe non-interactive version
        'lsof': ['lsof', '-i'],
        'df': ['df', '-h'],
        'ps': ['ps', 'aux'],
        'top': ['top', '-b', '-n', '1'],
        'iotop': ['iotop', '--version'],
        'iostat': ['iostat'],
        'vmstat': ['vmstat'],
        'sar': ['sar', '-u', '1', '1'],
        'dstat': ['dstat', '--version'],
        'strings': ['strings', '/bin/ls'],
        'file': ['file', '/bin/ls'],
        'xxd': ['xxd', '/etc/passwd'],
        'md5sum': ['md5sum', '/etc/passwd'],
        'sha256sum': ['sha256sum', '/etc/passwd'],
    }
    
    if tool_name not in tool_commands:
        return f"Unknown tool: {tool_name}"
    
    try:
        cmd = tool_commands[tool_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        output = f"Command: {' '.join(cmd)}\n"
        output += f"Exit code: {result.returncode}\n\n"
        
        if result.stdout:
            output += "STDOUT:\n" + result.stdout + "\n"
        
        if result.stderr:
            output += "STDERR:\n" + result.stderr + "\n"
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Tool execution timed out: {tool_name}"
    except FileNotFoundError:
        return f"Tool not found: {tool_name}. Try installing it first."
    except Exception as e:
        return f"Error executing {tool_name}: {str(e)}"

def generate_system_info_report():
    """Generate a comprehensive system information report."""
    import platform
    
    output = []
    output.append("=== SYSTEM INFORMATION REPORT ===")
    output.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("")
    
    # Basic system info
    output.append("--- Basic System Info ---")
    try:
        output.append(f"Hostname: {platform.node()}")
        output.append(f"System: {platform.system()}")
        output.append(f"Release: {platform.release()}")
        output.append(f"Version: {platform.version()}")
        output.append(f"Machine: {platform.machine()}")
        output.append(f"Processor: {platform.processor()}")
        output.append(f"Python: {platform.python_version()}")
    except Exception as e:
        output.append(f"Error getting basic info: {e}")
    
    output.append("")
    
    # Memory info
    output.append("--- Memory Usage ---")
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith(('MemTotal:', 'MemFree:', 'MemAvailable:', 'Buffers:', 'Cached:')):
                    output.append(line.strip())
    except Exception as e:
        output.append(f"Error reading memory info: {e}")
    
    output.append("")
    
    # Disk usage
    output.append("--- Disk Usage ---")
    try:
        result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
        output.append(result.stdout)
    except Exception as e:
        output.append(f"Error getting disk usage: {e}")
    
    # Network interfaces
    output.append("--- Network Interfaces ---")
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=10)
        output.append(result.stdout)
    except Exception:
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            output.append(result.stdout)
        except Exception as e:
            output.append(f"Error getting network info: {e}")
    
    # Running processes
    output.append("--- Top Processes ---")
    try:
        result = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True, timeout=10)
        lines = result.stdout.split('\n')
        output.extend(lines[:11])  # Header + top 10 processes
    except Exception as e:
        output.append(f"Error getting process info: {e}")
    
    return "\n".join(output)

def perform_basic_security_scan():
    """Perform a basic security vulnerability scan."""
    output = []
    output.append("=== BASIC SECURITY SCAN ===")
    output.append(f"Scan started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("")
    
    # Check for common security issues
    security_checks = [
        ("Checking for world-writable files", "find /tmp -type f -perm -002 2>/dev/null | head -10"),
        ("Checking listening ports", "netstat -tuln 2>/dev/null || ss -tuln"),
        ("Checking for SUID files", "find /usr/bin -type f -perm -4000 2>/dev/null | head -10"),
        ("Checking failed login attempts", "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -5"),
        ("Checking system users", "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"),
        ("Checking sudo access", "groups $(whoami)"),
    ]
    
    for description, command in security_checks:
        output.append(f"--- {description} ---")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
            if result.stdout.strip():
                output.append(result.stdout.strip())
            else:
                output.append("No issues found")
        except Exception as e:
            output.append(f"Error: {e}")
        output.append("")
    
    # Check file permissions
    output.append("--- Critical File Permissions ---")
    critical_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/ssh/sshd_config']
    for file_path in critical_files:
        try:
            result = subprocess.run(['ls', '-la', file_path], capture_output=True, text=True, timeout=5)
            output.append(result.stdout.strip())
        except Exception:
            output.append(f"{file_path}: Not accessible")
    
    output.append("")
    output.append(f"Scan completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return "\n".join(output)

def analyze_system_logs():
    """Analyze system logs for anomalies and patterns."""
    output = []
    output.append("=== SYSTEM LOG ANALYSIS ===")
    output.append(f"Analysis started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("")
    
    # Analyze different log files
    log_files = [
        ("/var/log/auth.log", "Authentication Events"),
        ("/var/log/syslog", "System Messages"),
        ("/var/log/messages", "General Messages"),
        ("/var/log/secure", "Security Events"),
        (NS_ALERTS, "NovaShield Alerts"),
        (NS_AUDIT, "NovaShield Audit"),
    ]
    
    for log_path, description in log_files:
        if os.path.exists(log_path):
            output.append(f"--- {description} ({log_path}) ---")
            try:
                # Get recent entries
                result = subprocess.run(['tail', '-20', log_path], capture_output=True, text=True, timeout=10)
                lines = result.stdout.strip().split('\n')
                
                # Count different types of events
                error_count = len([l for l in lines if 'error' in l.lower() or 'fail' in l.lower()])
                warning_count = len([l for l in lines if 'warn' in l.lower()])
                
                output.append(f"Recent entries: {len(lines)}")
                output.append(f"Errors/Failures: {error_count}")
                output.append(f"Warnings: {warning_count}")
                
                if error_count > 0:
                    output.append("Recent errors:")
                    for line in lines:
                        if 'error' in line.lower() or 'fail' in line.lower():
                            output.append(f"  {line}")
                
            except Exception as e:
                output.append(f"Error analyzing {log_path}: {e}")
            output.append("")
        else:
            output.append(f"--- {description} ---")
            output.append(f"Log file not found: {log_path}")
            output.append("")
    
    # System resource alerts
    output.append("--- Resource Usage Alerts ---")
    try:
        # Check disk usage
        result = subprocess.run(['df', '/'], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                usage_pct = int(parts[4].replace('%', ''))
                if usage_pct > 90:
                    output.append(f"⚠️  High disk usage: {usage_pct}%")
                elif usage_pct > 80:
                    output.append(f"⚠️  Moderate disk usage: {usage_pct}%")
                else:
                    output.append(f"✓ Normal disk usage: {usage_pct}%")
    except Exception:
        output.append("Could not check disk usage")
    
    output.append("")
    output.append(f"Analysis completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return "\n".join(output)

def execute_custom_command(command):
    """Execute a custom command safely and return its output."""
    output = []
    output.append(f"=== EXECUTING CUSTOM COMMAND ===")
    output.append(f"Command: {command}")
    output.append(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("")
    
    # Basic command validation and security checks
    dangerous_patterns = [
        'rm -rf /', 'rm -rf ~', 'rm -rf *', 
        'dd if=', 'mkfs', 'format',
        '> /dev/', '> /etc/', '> /boot/',
        'init 0', 'init 6', 'shutdown', 'halt', 'reboot',
        'iptables -F', 'iptables -X',
        'chmod 777 /', 'chown root /'
    ]
    
    command_lower = command.lower()
    is_dangerous = any(pattern in command_lower for pattern in dangerous_patterns)
    
    if is_dangerous:
        output.append("⚠️  WARNING: Command blocked for security reasons")
        output.append("Potentially dangerous commands are not allowed via web interface")
        output.append("Use the terminal tab for administrative commands")
        return "\n".join(output)
    
    # Limit command length
    if len(command) > 200:
        output.append("❌ ERROR: Command too long (max 200 characters)")
        return "\n".join(output)
    
    try:
        # Execute command with timeout and limits
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            cwd=os.path.expanduser('~')  # Run in user's home directory
        )
        
        output.append("--- STDOUT ---")
        if result.stdout.strip():
            # Limit output size to prevent browser issues
            stdout = result.stdout.strip()
            if len(stdout) > 5000:
                stdout = stdout[:5000] + "\n... (output truncated - use terminal for full output)"
            output.append(stdout)
        else:
            output.append("(no output)")
        
        if result.stderr.strip():
            output.append("")
            output.append("--- STDERR ---")
            stderr = result.stderr.strip()
            if len(stderr) > 1000:
                stderr = stderr[:1000] + "\n... (error output truncated)"
            output.append(stderr)
        
        output.append("")
        output.append(f"Exit code: {result.returncode}")
        
        if result.returncode == 0:
            output.append("✅ Command completed successfully")
        else:
            output.append("❌ Command failed with non-zero exit code")
            
    except subprocess.TimeoutExpired:
        output.append("⏱️  ERROR: Command timed out after 30 seconds")
        output.append("Use the terminal tab for long-running commands")
    except Exception as e:
        output.append(f"❌ ERROR: {str(e)}")
    
    output.append("")
    output.append(f"Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(output)

# ------------------------------- WebSocket PTY -------------------------------
def ws_handshake(handler):
    key = handler.headers.get('Sec-WebSocket-Key')
    if not key: return False
    accept = base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
    headers = {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Accept': accept,
        'Sec-WebSocket-Protocol': 'chat'
    }
    handler._set_headers(101, 'application/octet-stream', headers)
    return True

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self';")
        if extra_headers:
            for k,v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        # Enhanced connection logging - log all incoming connections
        ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        path = self.path
        
        # Log all connections to security.log
        security_log_path = os.path.join(NS_LOGS, 'security.log')
        try:
            Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
            with open(security_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [CONNECTION] IP={ip} Path={path} UserAgent='{user_agent[:100]}'\n")
        except Exception: pass
        
        parsed = urlparse(self.path)

        if parsed.path == '/ws/term':
            if not require_auth(self): return
            mirror_terminal(self); return

        if parsed.path == '/':
            # Log dashboard access for security monitoring
            client_ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')[:100]
            sess = get_session(self)
            if sess:
                user = sess.get('user', 'unknown')
                py_alert('INFO', f'DASHBOARD_ACCESS user={user} ip={client_ip} user_agent={user_agent}')
                audit(f'DASHBOARD_ACCESS user={user} ip={client_ip}')
            else:
                py_alert('INFO', f'UNAUTHORIZED_ACCESS ip={client_ip} user_agent={user_agent}')
                audit(f'UNAUTHORIZED_ACCESS ip={client_ip}')
            
            # Enhanced session handling with force_login_on_reload support
            force_login_on_reload = _coerce_bool(cfg_get('security.force_login_on_reload', False), False)
            
            # If AUTH_STRICT is enabled and no valid session OR force_login_on_reload is enabled
            if AUTH_STRICT and (not sess or force_login_on_reload):
                self._set_headers(200, 'text/html; charset=utf-8', {'Set-Cookie': 'NSSESS=deleted; Path=/; HttpOnly; Max-Age=0; SameSite=Strict'})
            else:
                self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8')); return

        if parsed.path == '/logout':
            # Log logout event
            client_ip = self.client_address[0]
            sess = get_session(self)
            user = sess.get('user', 'unknown') if sess else 'unknown'
            py_alert('INFO', f'LOGOUT user={user} ip={client_ip}')
            audit(f'LOGOUT user={user} ip={client_ip}')
            self._set_headers(302, 'text/plain', {'Set-Cookie': 'NSSESS=deleted; Path=/; HttpOnly; Max-Age=0; SameSite=Strict', 'Location':'/'})
            self.wfile.write(b'bye'); return

        if parsed.path.startswith('/static/'):
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(NS_WWW): self._set_headers(404); self.wfile.write(b'{}'); return
            if os.path.exists(p) and os.path.isfile(p):
                ctype='text/plain'
                if p.endswith('.js'): ctype='application/javascript'
                if p.endswith('.css'): ctype='text/css'
                if p.endswith('.html'): ctype='text/html; charset=utf-8'
                self._set_headers(200, ctype); self.wfile.write(read_text(p).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return

        if parsed.path == '/api/status':
            if not require_auth(self): return
            sess = get_session(self) or {}
            
            # Helper function to check monitor enabled state using NS_CTRL flags
            def monitor_enabled(name):
                return not os.path.exists(os.path.join(NS_CTRL, f'{name}.disabled'))
            
            data = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'cpu':   read_json(os.path.join(NS_LOGS, 'cpu.json'), {}),
                'memory':read_json(os.path.join(NS_LOGS, 'memory.json'), {}),
                'disk':  read_json(os.path.join(NS_LOGS, 'disk.json'), {}),
                'network':read_json(os.path.join(NS_LOGS, 'network.json'), {}),
                'integrity':read_json(os.path.join(NS_LOGS, 'integrity.json'), {}),
                'process': read_json(os.path.join(NS_LOGS,'process.json'),{}),
                'user': read_json(os.path.join(NS_LOGS,'user.json'),{}),
                'services': read_json(os.path.join(NS_LOGS,'service.json'),{}),
                'logwatch': read_json(os.path.join(NS_LOGS,'logwatch.json'),{}),
                'alerts': last_lines(os.path.join(NS_LOGS,'alerts.log'), 200),
                'projects_count': len([x for x in os.listdir(os.path.join(NS_HOME,'projects')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME,'projects')) else 0,
                'modules_count': len([x for x in os.listdir(os.path.join(NS_HOME,'modules')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME,'modules')) else 0,
                'version': read_text(os.path.join(NS_HOME,'version.txt'),'unknown'),
                'csrf': sess.get('csrf','') if auth_enabled() else 'public',
                'voice_enabled': cfg_get('jarvis.voice_enabled', False),
                # Add monitor enabled state flags for dashboard UI
                'integrity_enabled': monitor_enabled('integrity'),
                'process_enabled': monitor_enabled('process'),
                'userlogins_enabled': monitor_enabled('userlogins'),
                'services_enabled': monitor_enabled('services'),
                'logs_enabled': monitor_enabled('logs'),
                'network_enabled': monitor_enabled('network'),
                'cpu_enabled': monitor_enabled('cpu'),
                'memory_enabled': monitor_enabled('memory'),
                'disk_enabled': monitor_enabled('disk'),
                'scheduler_enabled': monitor_enabled('scheduler'),
                'authenticated': sess is not None and sess.get('user') != 'public'
            }
            self._set_headers(200); self.wfile.write(json.dumps(data).encode('utf-8')); return

        if parsed.path == '/api/whoami':
            info = {
                'ns_home': NS_HOME,
                'ns_www': NS_WWW,
                'ns_www_is_symlink': os.path.islink(NS_WWW),
                'index_exists': os.path.isfile(INDEX),
                'index_sha256': hashlib.sha256(read_text(INDEX,'').encode('utf-8')).hexdigest() if os.path.isfile(INDEX) else None,
                'server_sha256': hashlib.sha256(read_text(os.path.join(NS_WWW,'server.py'), '').encode('utf-8')).hexdigest() if os.path.isfile(os.path.join(NS_WWW,'server.py')) else None,
                'time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            self._set_headers(200); self.wfile.write(json.dumps(info).encode('utf-8')); return

        if parsed.path == '/api/config':
            if not require_auth(self): return
            self._set_headers(200, 'text/plain; charset=utf-8'); self.wfile.write(read_text(CONFIG, '').encode('utf-8')); return

        if parsed.path == '/api/logs':
            if not require_auth(self): return
            q = parse_qs(parsed.query); name = (q.get('name', ['launcher.log'])[0]).replace('..','')
            p = os.path.join(NS_HOME, name)
            if not os.path.exists(p): p = os.path.join(NS_LOGS, name)
            lines = []
            try:
                with open(p,'r',encoding='utf-8') as f: lines=f.read().splitlines()[-200:]
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'name': name, 'lines': lines}).encode('utf-8')); return

        if parsed.path == '/api/fs':
            if not require_auth(self): return
            q = parse_qs(parsed.query); d = q.get('dir',[''])[0]
            if not d: d = NS_HOME
            d = os.path.abspath(d)
            if not d.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            out=[]
            try:
                for entry in os.scandir(d):
                    if entry.name.startswith('.'): continue
                    if os.path.abspath(d).startswith(NS_KEYS) and entry.is_file(): continue
                    out.append({'name':entry.name,'is_dir':entry.is_dir(),'size':(entry.stat().st_size if entry.is_file() else 0)})
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'dir':d,'entries':out}).encode('utf-8')); return

        if parsed.path == '/api/fs_read':
            if not require_auth(self): return
            q = parse_qs(parsed.query); p = (q.get('path',[''])[0])
            full = os.path.abspath(p)
            if not full.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            if not os.path.exists(full) or not os.path.isfile(full):
                self._set_headers(404); self.wfile.write(b'{"error":"not found"}'); return
            try:
                size = os.path.getsize(full)
                content = open(full,'rb').read(500_000).decode('utf-8','ignore')
                self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'path':full,'size':size,'content':content}).encode('utf-8')); return
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8')); return

        if parsed.path == '/site':
            index = os.path.join(SITE_DIR,'index.html')
            self._set_headers(200,'text/html; charset=utf-8'); self.wfile.write(read_text(index,'<h1>No site yet</h1>').encode('utf-8')); return

        if parsed.path.startswith('/site/'):
            p = parsed.path[len('/site/'):]
            full = os.path.join(SITE_DIR, p)
            if not os.path.abspath(full).startswith(SITE_DIR): self._set_headers(403); self.wfile.write(b'{}'); return
            if os.path.exists(full):
                self._set_headers(200, 'text/html; charset=utf-8'); self.wfile.write(read_text(full).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return

        self._set_headers(404); self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        # Enhanced connection logging for POST requests
        ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        path = self.path
        
        # Log all POST connections to security.log
        security_log_path = os.path.join(NS_LOGS, 'security.log')
        try:
            Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
            with open(security_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [POST_REQUEST] IP={ip} Path={path} UserAgent='{user_agent[:100]}'\n")
        except Exception: pass
        
        parsed = urlparse(self.path)
        if not rate_limit_ok(self, parsed.path):
            # Log rate limit violations
            try:
                with open(security_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [RATE_LIMIT] IP={ip} Path={path} UserAgent='{user_agent[:100]}'\n")
            except Exception: pass
            py_alert('WARN', f'Rate limit hit by {ip} on {path}')
            self._set_headers(429); self.wfile.write(b'{"error":"rate"}'); return
            
        if banned(self):
            # Log banned IP attempts
            try:
                with open(security_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [BANNED_ACCESS] IP={ip} Path={path} UserAgent='{user_agent[:100]}'\n")
            except Exception: pass
            py_alert('WARN', f'Banned IP {ip} attempted access to {path}')
            self._set_headers(429); self.wfile.write(b'{"error":"locked"}'); return
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''

        if parsed.path == '/api/login':
            # Enhanced login attempt logging with detailed connection info
            ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            
            try: data = json.loads(body or '{}'); user=data.get('user',''); pwd=data.get('pass',''); otp=data.get('otp','')
            except Exception: data={}; user=''; pwd=''; otp=''
            
            # Log all login attempts regardless of success/failure
            security_log_path = os.path.join(NS_LOGS, 'security.log')
            try:
                Path(os.path.dirname(security_log_path)).mkdir(parents=True, exist_ok=True)
                with open(security_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [LOGIN_ATTEMPT] IP={ip} User={user} UserAgent='{user_agent[:100]}'\n")
            except Exception: pass
            
            if not user or not pwd:
                # Log invalid login attempts with missing credentials
                try:
                    with open(security_log_path, 'a', encoding='utf-8') as f:
                        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [LOGIN_INVALID] IP={ip} Reason=missing_credentials UserAgent='{user_agent[:100]}'\n")
                except Exception: pass
                self._set_headers(400); self.wfile.write(b'{"ok":false}'); return
                
            if check_login(user, pwd):
                sec = user_2fa_secret(user)
                if require_2fa() or sec:
                    now = totp_now(sec)
                    if not otp or otp != now:
                        login_fail(self)
                        # Enhanced 2FA failure logging
                        try:
                            with open(security_log_path, 'a', encoding='utf-8') as f:
                                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [2FA_FAIL] IP={ip} User={user} UserAgent='{user_agent[:100]}'\n")
                        except Exception: pass
                        self._set_headers(401); self.wfile.write(b'{"ok":false,"need_2fa":true}'); return
                        
                token, csrf = new_session(user)
                login_ok(self)
                py_alert('INFO', f'LOGIN OK user={user} ip={ip}')
                audit(f'LOGIN OK user={user} ip={ip} user_agent={user_agent[:50]}')
                self._set_headers(200, 'application/json', {'Set-Cookie': f'NSSESS={token}; Path=/; HttpOnly; SameSite=Strict'})
                self.wfile.write(json.dumps({'ok':True,'csrf':csrf}).encode('utf-8')); return
                
            login_fail(self); 
            py_alert('WARN', f'LOGIN FAIL user={user} ip={ip}')
            audit(f'LOGIN FAIL user={user} ip={ip} user_agent={user_agent[:50]}')
            self._set_headers(401); self.wfile.write(b'{"ok":false}'); return

        if not require_auth(self): return

        if parsed.path == '/api/control':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            action = data.get('action',''); target = data.get('target','')
            flag = os.path.join(NS_CTRL, f'{target}.disabled')
            if action == 'enable' and target:
                try:
                    if os.path.exists(flag): os.remove(flag)
                    audit(f'MONITOR ENABLE {target} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            if action == 'disable' and target:
                try:
                    open(flag,'w').close()
                    audit(f'MONITOR DISABLE {target} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            self_path = read_text(SELF_PATH_FILE).strip() or os.path.join(NS_HOME, 'bin', 'novashield.sh')
            if action in ('backup','version','restart_monitors','clear_logs'):
                try:
                    if action=='backup': os.system(f'\"{self_path}\" --backup >/dev/null 2>&1 &')
                    if action=='version': os.system(f'\"{self_path}\" --version-snapshot >/dev/null 2>&1 &')
                    if action=='restart_monitors': os.system(f'\"{self_path}\" --restart-monitors >/dev/null 2>&1 &')
                    if action=='clear_logs':
                        # Clear old log entries (keep last 100 lines of each log)
                        log_files = [
                            os.path.join(NS_LOGS, 'audit.log'),
                            os.path.join(NS_LOGS, 'alerts.log'),
                            os.path.join(NS_HOME, 'session.log')
                        ]
                        for log_file in log_files:
                            if os.path.exists(log_file):
                                try:
                                    with open(log_file, 'r', encoding='utf-8') as f:
                                        lines = f.readlines()
                                    if len(lines) > 100:
                                        with open(log_file, 'w', encoding='utf-8') as f:
                                            f.writelines(lines[-100:])
                                except Exception as e:
                                    print(f"Error clearing {log_file}: {e}")
                    audit(f'CONTROL {action} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            self._set_headers(400); self.wfile.write(b'{"ok":false}'); return

        if parsed.path == '/api/chat':
            if not require_auth(self): return
            try: 
                data = json.loads(body or '{}')
            except Exception: 
                py_alert('WARN', f'Chat API invalid JSON from {self.client_address[0]}')
                self._set_headers(400); self.wfile.write(json.dumps({'ok':False,'error':'invalid json'}).encode('utf-8')); return
                
            prompt = data.get('prompt','')
            if not prompt.strip():
                self._set_headers(400); self.wfile.write(json.dumps({'ok':False,'error':'empty prompt'}).encode('utf-8')); return
                
            # Get session and username instead of just IP
            sess = get_session(self)
            username = sess.get('user', 'public') if sess else 'public'
            user_ip = self.client_address[0]
            
            try:
                reply = ai_reply(prompt, username, user_ip)
                voice_enabled = cfg_get('jarvis.voice_enabled', False)
                
                # Log to chat.log with username
                try: 
                    open(CHATLOG,'a',encoding='utf-8').write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} User:{username} IP:{user_ip} Q:{prompt} A:{reply}\n')
                except Exception: 
                    py_alert('WARN', f'Failed to write chat log for {username}@{user_ip}')
                    
                response_data = {'ok': True, 'reply': reply}
                if voice_enabled:
                    response_data['speak'] = True
                    
                self._set_headers(200); self.wfile.write(json.dumps(response_data).encode('utf-8')); return
            except Exception as e:
                py_alert('ERROR', f'Chat AI error for {user_ip}: {str(e)}')
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':'ai error'}).encode('utf-8')); return
        
        # Enhanced Jarvis AI memory management
        if parsed.path == '/api/jarvis/memory':
            if not require_auth(self): return
            sess = get_session(self)
            username = sess.get('user', 'public') if sess else 'public'
            
            if self.command == 'GET':
                # Load user's encrypted memory
                try:
                    user_memory = load_user_memory(username)
                    self._set_headers(200)
                    self.wfile.write(json.dumps({
                        'ok': True,
                        'memory': user_memory.get('memory', {}),
                        'preferences': user_memory.get('preferences', {}),
                        'history': user_memory.get('conversations', [])  # Use 'conversations' as history
                    }).encode('utf-8'))
                except Exception:
                    self._set_headers(200)
                    self.wfile.write(json.dumps({
                        'ok': True,
                        'memory': {},
                        'preferences': {},
                        'history': []
                    }).encode('utf-8'))
                return
            
            if self.command == 'POST':
                # Save user's encrypted memory
                try:
                    data = json.loads(body or '{}')
                    
                    # Load existing memory or start with default
                    user_memory = load_user_memory(username)
                    
                    # Update user's memory with new data
                    user_memory['memory'] = data.get('memory', {})
                    user_memory['preferences'] = data.get('preferences', {})
                    # Use 'conversations' instead of 'history' for consistency with ai_reply
                    user_memory['conversations'] = data.get('history', [])
                    user_memory['last_updated'] = time.time()
                    user_memory['last_seen'] = time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Save encrypted memory
                    save_user_memory(username, user_memory)
                    
                    self._set_headers(200)
                    self.wfile.write(json.dumps({'ok': True}).encode('utf-8'))
                except Exception as e:
                    py_alert('ERROR', f'Failed to save memory for {username}: {str(e)}')
                    self._set_headers(500)
                    self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
                return
        
        # Tools management API
        if parsed.path == '/api/tools/scan':
            if not require_auth(self): return
            try:
                tools_info = scan_system_tools()
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    'ok': True,
                    'tools': tools_info
                }).encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return
        
        if parsed.path == '/api/tools/install':
            if not require_auth(self): return
            try:
                output = install_missing_tools()
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    'ok': True,
                    'output': output
                }).encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return
        
        if parsed.path == '/api/tools/execute':
            if not require_auth(self): return
            try:
                data = json.loads(body or '{}')
                tool_name = data.get('tool', '')
                custom_command = data.get('command', '')
                
                if not tool_name:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({'ok': False, 'error': 'No tool specified'}).encode('utf-8'))
                    return
                
                # Handle custom command execution
                if tool_name == 'custom' and custom_command:
                    output = execute_custom_command(custom_command)
                else:
                    output = execute_tool(tool_name)
                    
                audit(f'TOOL_EXEC tool={tool_name} command="{custom_command if custom_command else tool_name}" ip={self.client_address[0]}')
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    'ok': True,
                    'output': output
                }).encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return
        
        if parsed.path == '/api/webgen':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            title = data.get('title','Untitled'); content = data.get('content','')
            slug = ''.join([c.lower() if c.isalnum() else '-' for c in title]).strip('-') or f'page-{int(time.time())}'
            Path(SITE_DIR).mkdir(parents=True, exist_ok=True)
            page_path = os.path.join(SITE_DIR, f'{slug}.html')
            write_text(page_path, f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head><body><h1>{title}</h1><div>{content}</div></body></html>')
            pages = [p for p in os.listdir(SITE_DIR) if p.endswith('.html')]
            links = '\n'.join([f'<li><a href="/site/{p}">{p}</a></li>' for p in pages if p!='index.html'])
            write_text(os.path.join(SITE_DIR,'index.html'), f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site</title></head><body><h1>Site</h1><ul>{links}</ul></body></html>')
            audit(f'WEBGEN page={slug}.html ip={self.client_address[0]}')
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'page':f'/site/{slug}.html'}).encode('utf-8')); return

        # File manager actions
        if parsed.path == '/api/fs_write':
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); content=data.get('content','')
            full=os.path.abspath(path)
            if (not full.startswith(NS_HOME)) or full.startswith(NS_KEYS):
                self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: write_text(full, content); audit(f'FS WRITE {full} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mkdir':
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path','')
            full=os.path.abspath(path)
            if (not full.startswith(NS_HOME)) or full.startswith(NS_KEYS):
                self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: Path(full).mkdir(parents=True, exist_ok=True); audit(f'FS MKDIR {full} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mv':
            try: data=json.loads(body or '{}')
            except Exception: data={}
            src=data.get('src',''); dst=data.get('dst','')
            srcf=os.path.abspath(src); dstf=os.path.abspath(dst)
            if (not srcf.startswith(NS_HOME)) or (not dstf.startswith(NS_HOME)) or srcf.startswith(NS_KEYS) or dstf.startswith(NS_KEYS):
                self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: os.rename(srcf,dstf); audit(f'FS MV {srcf} -> {dstf} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_rm':
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); full=os.path.abspath(path)
            if (not full.startswith(NS_HOME)) or full.startswith(NS_KEYS):
                self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try:
                if os.path.isdir(full): os.rmdir(full)
                elif os.path.isfile(full): os.remove(full)
                audit(f'FS RM {full} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/security':
            if not require_auth(self): return
            # Comprehensive security dashboard data - moved from duplicate do_POST
            try:
                # Read and parse log files
                auth_logs = []
                audit_logs = []
                security_logs = []
                integrity_logs = []
                
                # Parse session log for detailed authentication events
                session_path = os.path.join(NS_HOME, 'session.log')
                alerts_path = os.path.join(NS_LOGS, 'alerts.log')
                security_path = os.path.join(NS_LOGS, 'security.log')
                audit_path = os.path.join(NS_LOGS, 'audit.log')
                
                stats = {
                    'auth_success': 0,
                    'auth_fail': 0,
                    'active_sessions': 0,
                    'audit_count': 0,
                    'security_count': 0,
                    'threat_count': 0,
                    'integrity_files': 0,
                    'integrity_changes': 0,
                    'last_audit': 'Never'
                }
                
                # Parse session log for detailed authentication events
                if os.path.exists(session_path):
                    try:
                        with open(session_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()[-50:]  # Last 50 lines
                            for line in lines:
                                line = line.strip()
                                if not line: continue
                                
                                parts = line.split(' ', 2)
                                if len(parts) >= 3:
                                    timestamp = f"{parts[0]} {parts[1]}"
                                    message = parts[2]
                                    
                                    log_entry = {
                                        'timestamp': timestamp,
                                        'message': message,
                                        'level': 'info'
                                    }
                                    
                                    if 'SUCCESSFUL_LOGIN' in message:
                                        stats['auth_success'] += 1
                                        log_entry['level'] = 'success'
                                        auth_logs.append(log_entry)
                                    elif 'FAILED_LOGIN' in message:
                                        stats['auth_fail'] += 1
                                        log_entry['level'] = 'error'
                                        auth_logs.append(log_entry)
                    except Exception as e:
                        print(f"Error reading session log: {e}")
                
                # Count active sessions with expiry check
                try:
                    sessions_db = read_json(SESSIONS, {})
                    current_time = int(time.time())
                    active_count = 0
                    for session_id, session_data in sessions_db.items():
                        if isinstance(session_data, dict):
                            session_expiry = session_data.get('expires', 0)
                            if session_expiry > current_time:
                                active_count += 1
                    stats['active_sessions'] = active_count
                except Exception as e:
                    print(f"Error counting active sessions: {e}")
                    stats['active_sessions'] = 0
                
                # Parse security log for dedicated security events
                if os.path.exists(security_path):
                    try:
                        with open(security_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()[-100:]  # Increased to 100 for comprehensive logs
                            for line in lines:
                                line = line.strip()
                                if not line: continue
                                
                                parts = line.split(' ', 3)
                                if len(parts) >= 4:
                                    timestamp = f"{parts[0]} {parts[1]}"
                                    level_type = parts[2].strip('[]').lower()
                                    message = parts[3]
                                    
                                    log_entry = {
                                        'timestamp': timestamp,
                                        'message': message,
                                        'level': level_type
                                    }
                                    
                                    # Enhanced categorization for new log types
                                    if level_type in ['threat', 'critical']:
                                        stats['threat_count'] += 1
                                        log_entry['level'] = 'critical'
                                    elif level_type in ['auth_fail', 'forbidden', 'unauthorized', 'csrf_fail', '2fa_fail']:
                                        stats['auth_fail'] += 1
                                        log_entry['level'] = 'error'
                                        auth_logs.append(log_entry)
                                    elif level_type in ['auth_success']:
                                        stats['auth_success'] += 1
                                        log_entry['level'] = 'success'
                                        auth_logs.append(log_entry)
                                    elif level_type in ['connection', 'post_request']:
                                        log_entry['level'] = 'info'
                                    elif level_type in ['rate_limit', 'banned_access']:
                                        log_entry['level'] = 'warning'
                                        stats['threat_count'] += 1
                                    elif level_type in ['login_attempt', 'login_invalid']:
                                        log_entry['level'] = 'info'
                                        auth_logs.append(log_entry)
                                    
                                    security_logs.append(log_entry)
                                    stats['security_count'] += 1
                    except Exception as e:
                        print(f"Error reading security log: {e}")
                
                # Parse audit log for detailed system events
                if os.path.exists(audit_path):
                    try:
                        with open(audit_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()[-50:]  # Last 50 lines
                            for line in lines:
                                line = line.strip()
                                if not line: continue
                                
                                parts = line.split(' ', 2)
                                if len(parts) >= 3:
                                    timestamp = f"{parts[0]} {parts[1]}"
                                    message = parts[2]
                                    
                                    log_entry = {
                                        'timestamp': timestamp,
                                        'message': message,
                                        'level': 'info'
                                    }
                                    
                                    if 'LOGIN OK' in message or 'LOGIN SUCCESS' in message:
                                        stats['auth_success'] += 1
                                        log_entry['level'] = 'success'
                                        auth_logs.append(log_entry)
                                    elif 'LOGIN FAIL' in message:
                                        stats['auth_fail'] += 1
                                        log_entry['level'] = 'error'
                                        auth_logs.append(log_entry)
                                    elif any(kw in message for kw in ['MONITOR', 'CONTROL', 'FS']):
                                        audit_logs.append(log_entry)
                                    
                                    stats['audit_count'] += 1
                                    stats['last_audit'] = timestamp
                    except Exception as e:
                        print(f"Error reading audit log: {e}")
                
                # Parse alerts for security events
                if os.path.exists(alerts_path):
                    try:
                        with open(alerts_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()[-50:]
                            for line in lines:
                                line = line.strip()
                                if not line: continue
                                
                                parts = line.split(' ', 3)
                                if len(parts) >= 4:
                                    timestamp = f"{parts[0]} {parts[1]}"
                                    level = parts[2].strip('[]').lower()
                                    message = parts[3]
                                    
                                    log_entry = {
                                        'timestamp': timestamp,
                                        'message': message,
                                        'level': level
                                    }
                                    
                                    if level in ['crit', 'error']:
                                        stats['threat_count'] += 1
                                    
                                    # Add to security logs if it's a security-related alert
                                    if any(kw in message.lower() for kw in ['network', 'integrity', 'suspicious', 'attack', 'breach']):
                                        security_logs.append(log_entry)
                                        stats['security_count'] += 1
                    except Exception as e:
                        print(f"Error reading alerts log: {e}")
                
                # Check integrity monitoring
                integrity_state_path = os.path.join(NS_CTRL, 'integrity.state')
                if os.path.exists(integrity_state_path):
                    try:
                        integrity_data = read_json(integrity_state_path, {})
                        stats['integrity_files'] = integrity_data.get('files', 0)
                        stats['integrity_changes'] = integrity_data.get('changes_detected', 0)
                        
                        # Add recent integrity events to logs
                        recent_changes = integrity_data.get('recent_changes', [])
                        for change in recent_changes[-20:]:  # Last 20 changes
                            integrity_logs.append({
                                'timestamp': change.get('timestamp', 'Unknown'),
                                'message': f"File change detected: {change.get('file', 'unknown')} ({change.get('type', 'modified')})",
                                'level': 'warning'
                            })
                    except Exception as e:
                        print(f"Error reading integrity state: {e}")
                else:
                    # Fallback to integrity.json
                    integrity_json = read_json(os.path.join(NS_LOGS, 'integrity.json'), {})
                    stats['integrity_files'] = integrity_json.get('files', 0)
                    stats['integrity_changes'] = integrity_json.get('changes', 0)
                
                response = {
                    'ok': True,
                    'stats': stats,
                    'logs': {
                        'auth': auth_logs[-20:],  # Last 20 auth events
                        'audit': audit_logs[-20:],  # Last 20 audit events  
                        'security': security_logs[-20:],  # Last 20 security events
                        'integrity': integrity_logs[-20:]  # Last 20 integrity events
                    }
                }
                
                self._set_headers(200); 
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
                
            except Exception as e:
                print(f"Security API error: {e}")
                self._set_headers(500); 
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
                return

        self._set_headers(400); self.wfile.write(b'{"ok":false}')

def pick_host_port():
    cfg_reload()
    host = cfg_get('http.host','127.0.0.1')
    port = _coerce_int(cfg_get('http.port',8765), 8765)
    if _coerce_bool(cfg_get('http.allow_lan', False), False):
        host = '0.0.0.0'
    try:
        socket.getaddrinfo(host, port)
    except Exception:
        host = '127.0.0.1'
    return host, port

def tls_params():
    if not _coerce_bool(cfg_get('security.tls_enabled', False), False):
        return None
    crt = cfg_get('security.tls_cert','keys/tls.crt')
    key = cfg_get('security.tls_key','keys/tls.key')
    return os.path.join(NS_HOME,crt), os.path.join(NS_HOME,key)

if __name__ == '__main__':
    host, port = pick_host_port()
    os.chdir(NS_WWW)
    crt_key = tls_params()
    for h in (host, '127.0.0.1', '0.0.0.0'):
        try:
            httpd = HTTPServer((h, port), Handler)
            if crt_key:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(crt_key[0], crt_key[1])
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
                scheme='https'
            else:
                scheme='http'
            print(f"NovaShield Web Server on {scheme}://{h}:{port}")
            httpd.serve_forever()
        except Exception as e:
            print(f"Bind failed on {h}:{port}: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue
PY
}

write_dashboard(){
  write_file "${NS_WWW}/index.html" 644 <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NovaShield — JARVIS Edition</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <header>
    <div class="brand">
      <div class="ring"></div>
      <h1>NovaShield <span class="mini">JARVIS</span></h1>
      <div class="by">Created by @MrNova420</div>
    </div>
    <div class="actions">
      <button id="btn-420-theme" type="button" title="Toggle 420 themed colors (purple, green, blue)">🌿 420 Mode</button>
      <button id="btn-refresh" type="button" title="Refresh all dashboard data and status information">Refresh Dashboard</button>
      <button data-act="backup" type="button" title="Create a backup of important system files and configurations">Create Backup</button>
      <button data-act="version" type="button" title="Create a system snapshot with current state and version info">Create Snapshot</button>
      <button data-act="restart_monitors" type="button" title="Restart all monitoring services and background processes">Restart Monitors</button>
      <a href="/logout" class="logout-link" aria-label="Logout">
        <button type="button" title="Sign out and return to login screen">Logout</button>
      </a>
    </div>
  </header>

  <nav class="tabs" aria-label="Main">
    <button data-tab="ai" class="active" type="button">Jarvis</button>
    <button data-tab="alerts" type="button">Alerts</button>
    <button data-tab="status" type="button">Status</button>
    <button data-tab="security" type="button">Security</button>
    <button data-tab="tools" type="button">Tools</button>
    <button data-tab="files" type="button">Files</button>
    <button data-tab="terminal" type="button">Terminal</button>
    <button data-tab="webgen" type="button">Web Builder</button>
    <button data-tab="config" type="button">Config</button>
  </nav>

  <main>
    <section id="tab-status" class="tab" aria-labelledby="Status">
      <p class="section-description">Real-time system monitoring dashboard showing CPU load, memory usage, disk space, network connectivity, and security status. Use the monitor controls below to enable/disable specific monitoring modules.</p>
      
      <section class="grid">
        <div class="card" id="card-cpu" title="System CPU load averages with warning and critical thresholds"><h2>CPU Load</h2><div class="value" id="cpu"></div></div>
        <div class="card" id="card-mem" title="Memory usage percentage with available memory and threshold monitoring"><h2>Memory Usage</h2><div class="value" id="mem"></div></div>
        <div class="card" id="card-disk" title="Disk space usage for all mounted filesystems with free space reporting"><h2>Disk Space</h2><div class="value" id="disk"></div></div>
        <div class="card" id="card-net" title="Network connectivity status and external reachability checks"><h2>Network Status</h2><div class="value" id="net"></div></div>
        <div class="card" id="card-int" title="File system integrity monitoring and critical file change detection"><h2>File Integrity</h2><div class="value" id="int"></div></div>
        <div class="card" id="card-proc" title="Running process monitoring and resource usage tracking"><h2>Process Monitor</h2><div class="value" id="proc"></div></div>
        <div class="card" id="card-user" title="User login monitoring and session tracking"><h2>User Sessions</h2><div class="value" id="user"></div></div>
        <div class="card" id="card-svc" title="System service status monitoring and health checks"><h2>Service Status</h2><div class="value" id="svc"></div></div>
        <div class="card" id="card-meta" title="System metadata including uptime, load averages, and performance metrics"><h2>System Info</h2><div class="value" id="meta"></div></div>
      </section>
      <div class="panel">
        <h3>Monitor Controls</h3>
        <p class="panel-description">Enable or disable individual monitoring modules. Active monitors will continuously collect data and generate alerts when thresholds are exceeded.</p>
        <div class="toggles">
          <button class="toggle" data-target="cpu" type="button" title="Monitor CPU load averages and performance">CPU Monitor</button>
          <button class="toggle" data-target="memory" type="button" title="Monitor memory usage and availability">Memory Monitor</button>
          <button class="toggle" data-target="disk" type="button" title="Monitor disk space usage and I/O">Disk Monitor</button>
          <button class="toggle" data-target="network" type="button" title="Monitor network connectivity and external checks">Network Monitor</button>
          <button class="toggle" data-target="integrity" type="button" title="Monitor file system changes and integrity">Integrity Monitor</button>
          <button class="toggle" data-target="process" type="button" title="Monitor running processes and resource usage">Process Monitor</button>
          <button class="toggle" data-target="userlogins" type="button" title="Monitor user logins and session activity">User Monitor</button>
          <button class="toggle" data-target="services" type="button" title="Monitor system service status and health">Service Monitor</button>
          <button class="toggle" data-target="logs" type="button" title="Monitor system logs for important events">Log Monitor</button>
          <button class="toggle" data-target="scheduler" type="button" title="Monitor scheduled tasks and automation">Scheduler Monitor</button>
        </div>
      </div>
    </section>

    <section id="tab-alerts" class="tab" aria-labelledby="Alerts">
      <div class="panel">
        <h3>System Alerts</h3>
        <p class="panel-description">Critical system alerts and notifications. Shows warnings about high resource usage, security threats, failed services, and other important system events that require attention.</p>
        <ul id="alerts"></ul>
      </div>
    </section>

    <section id="tab-security" class="tab" aria-labelledby="Security Logs">
      <h2>Security Monitoring</h2>
      <p class="section-description">Real-time security monitoring and logging system that tracks all connection attempts, authentication events, and system integrity changes. View detailed logs with IP addresses, timestamps, and threat analysis.</p>
      
      <div class="security-controls">
        <button id="btn-refresh-security" type="button" title="Refresh security logs from the server">Refresh Logs</button>
        <button id="btn-clear-logs" type="button" title="Clear old security log entries">Clear Old Logs</button>
        <select id="log-filter" title="Filter logs by event type">
          <option value="all">All Events</option>
          <option value="auth">Authentication</option>
          <option value="audit">Audit Trail</option>
          <option value="session">Sessions</option>
          <option value="security">Security Events</option>
        </select>
      </div>
      
      <div class="security-grid">
        <div class="security-card">
          <h3>Authentication Events</h3>
          <p class="card-description">Tracks all login attempts (successful and failed) with detailed IP address logging, user agent information, and authentication failure reasons. Monitors active user sessions and login patterns.</p>
          <div class="log-stats">
            <span id="auth-success-count">0</span> successful logins |
            <span id="auth-fail-count">0</span> failed attempts |
            <span id="active-sessions-count">0</span> active sessions
          </div>
          <ul id="auth-logs" class="log-list"></ul>
        </div>
        
        <div class="security-card">
          <h3>Audit Trail</h3>
          <p class="card-description">Logs all system operations including file modifications, backup creation, configuration changes, and administrative actions. Provides a complete audit history of user activities.</p>
          <div class="log-stats">
            <span id="audit-count">0</span> audit events |
            Last: <span id="last-audit">Never</span>
          </div>
          <ul id="audit-logs" class="log-list"></ul>
        </div>
        
        <div class="security-card">
          <h3>Security Events</h3>
          <p class="card-description">Comprehensive security monitoring including unauthorized access attempts, CSRF failures, rate limiting violations, IP-based restrictions, and threat detection. Every website connection is logged with full details.</p>
          <div class="log-stats">
            <span id="security-count">0</span> security events |
            <span id="threat-count">0</span> threats detected
          </div>
          <ul id="security-logs" class="log-list"></ul>
        </div>
        
        <div class="security-card">
          <h3>System Integrity</h3>
          <p class="card-description">Monitors critical system files for unauthorized changes, tracks file permissions, and detects potential security compromises. Alerts on suspicious file system activity.</p>
          <div class="log-stats">
            Files monitored: <span id="integrity-files">0</span> |
            Changes detected: <span id="integrity-changes">0</span>
          </div>
          <ul id="integrity-logs" class="log-list"></ul>
        </div>
      </div>
    </section>

    <section id="tab-tools" class="tab" aria-labelledby="Tools">
      <div class="panel">
        <h3>System Tools & Utilities</h3>
        <p class="panel-description">Automated tool detection, installation, and execution system. Jarvis can discover available tools, install missing ones, and execute them with a single click. All tool outputs are displayed in dedicated result panels.</p>
        
        <div class="tools-controls">
          <button id="btn-scan-tools" type="button" title="Scan system for available tools and utilities">Scan Tools</button>
          <button id="btn-install-missing" type="button" title="Automatically install commonly used security and system tools">Install Missing Tools</button>
          <button id="btn-refresh-tools" type="button" title="Refresh the tools list and check for updates">Refresh Tools</button>
          <select id="tool-category" title="Filter tools by category">
            <option value="all">All Categories</option>
            <option value="security">Security Tools</option>
            <option value="network">Network Tools</option>
            <option value="system">System Tools</option>
            <option value="monitoring">Monitoring Tools</option>
            <option value="forensics">Forensics Tools</option>
            <option value="custom">Custom Scripts</option>
          </select>
        </div>
        
        <div class="tools-grid">
          <div class="tool-category">
            <h4>Security Tools</h4>
            <div class="tool-buttons" id="security-tools">
              <button class="tool-btn" data-tool="nmap" title="Network Mapper - Port scanning and network discovery">
                <span class="tool-icon">🔍</span>
                <span class="tool-name">Nmap</span>
                <span class="tool-status" id="nmap-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="netstat" title="Display network connections and listening ports">
                <span class="tool-icon">📡</span>
                <span class="tool-name">Netstat</span>
                <span class="tool-status" id="netstat-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="ss" title="Modern replacement for netstat - socket statistics">
                <span class="tool-icon">🔌</span>
                <span class="tool-name">SS</span>
                <span class="tool-status" id="ss-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="iptables" title="Configure Linux firewall rules">
                <span class="tool-icon">🛡️</span>
                <span class="tool-name">IPTables</span>
                <span class="tool-status" id="iptables-status">Checking...</span>
              </button>
            </div>
          </div>
          
          <div class="tool-category">
            <h4>Network Tools</h4>
            <div class="tool-buttons" id="network-tools">
              <button class="tool-btn" data-tool="ping" title="Test network connectivity to hosts">
                <span class="tool-icon">📶</span>
                <span class="tool-name">Ping</span>
                <span class="tool-status" id="ping-status">Available</span>
              </button>
              <button class="tool-btn" data-tool="curl" title="Transfer data to/from servers - HTTP client">
                <span class="tool-icon">🌐</span>
                <span class="tool-name">Curl</span>
                <span class="tool-status" id="curl-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="wget" title="Download files from web servers">
                <span class="tool-icon">⬇️</span>
                <span class="tool-name">Wget</span>
                <span class="tool-status" id="wget-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="dig" title="DNS lookup utility for domain name resolution">
                <span class="tool-icon">🔍</span>
                <span class="tool-name">Dig</span>
                <span class="tool-status" id="dig-status">Checking...</span>
              </button>
            </div>
          </div>
          
          <div class="tool-category">
            <h4>System Tools</h4>
            <div class="tool-buttons" id="system-tools">
              <button class="tool-btn" data-tool="htop" title="Interactive process viewer and system monitor">
                <span class="tool-icon">📊</span>
                <span class="tool-name">Htop</span>
                <span class="tool-status" id="htop-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="lsof" title="List open files and network connections">
                <span class="tool-icon">📂</span>
                <span class="tool-name">Lsof</span>
                <span class="tool-status" id="lsof-status">Checking...</span>
              </button>
              <button class="tool-btn" data-tool="df" title="Display filesystem disk space usage">
                <span class="tool-icon">💾</span>
                <span class="tool-name">DF</span>
                <span class="tool-status" id="df-status">Available</span>
              </button>
              <button class="tool-btn" data-tool="ps" title="Display running processes">
                <span class="tool-icon">⚙️</span>
                <span class="tool-name">PS</span>
                <span class="tool-status" id="ps-status">Available</span>
              </button>
            </div>
          </div>
          
          <div class="tool-category">
            <h4>Custom Scripts</h4>
            <div class="tool-buttons" id="custom-tools">
              <button class="tool-btn" data-tool="system-info" title="Generate comprehensive system information report">
                <span class="tool-icon">📋</span>
                <span class="tool-name">System Info</span>
                <span class="tool-status" id="system-info-status">Ready</span>
              </button>
              <button class="tool-btn" data-tool="security-scan" title="Perform basic security vulnerability scan">
                <span class="tool-icon">🔒</span>
                <span class="tool-name">Security Scan</span>
                <span class="tool-status" id="security-scan-status">Ready</span>
              </button>
              <button class="tool-btn" data-tool="log-analyzer" title="Analyze system logs for anomalies and patterns">
                <span class="tool-icon">🔍</span>
                <span class="tool-name">Log Analyzer</span>
                <span class="tool-status" id="log-analyzer-status">Ready</span>
              </button>
            </div>
          </div>
        </div>
        
        <div class="tool-result-panel">
          <h4>Tool Output</h4>
          <div class="result-controls">
            <button id="clear-results" type="button" title="Clear the tool output display">Clear Output</button>
            <button id="save-results" type="button" title="Save the current output to a file">Save Output</button>
            <span id="active-tool">No tool selected</span>
          </div>
          <pre id="tool-output" class="tool-output" placeholder="Tool output will appear here..."></pre>
          
          <div class="manual-command-panel">
            <h5>Manual Command Execution</h5>
            <p class="panel-description">Execute custom commands directly. Use with caution - commands run with full system access.</p>
            <div class="command-input-group">
              <input id="manual-command" type="text" placeholder="Enter command (e.g., ps aux, netstat -tuln, df -h)" title="Type any system command to execute" />
              <button id="execute-command" type="button" title="Execute the entered command">Execute</button>
            </div>
            <div class="command-suggestions">
              <button class="cmd-suggestion" data-cmd="ps aux">ps aux</button>
              <button class="cmd-suggestion" data-cmd="df -h">df -h</button>
              <button class="cmd-suggestion" data-cmd="netstat -tuln">netstat -tuln</button>
              <button class="cmd-suggestion" data-cmd="top -n 1">top -n 1</button>
              <button class="cmd-suggestion" data-cmd="uname -a">uname -a</button>
              <button class="cmd-suggestion" data-cmd="whoami">whoami</button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section id="tab-files" class="tab" aria-labelledby="Files">
      <div class="panel">
        <h3>File Manager</h3>
        <p class="panel-description">Browse, view, and manage files on your system. Navigate directories, view file contents, create new directories, and save edited files. Files are displayed with size and permissions information.</p>
        <div class="filebar">
          <input id="cwd" value="~/.novashield" title="Current directory path - enter a path and click List to navigate" />
          <button id="btn-list" type="button" title="List files and directories in the current path">List Directory</button>
        </div>
        <div id="filelist"></div>
        <div id="viewer" class="panel" style="display:none; margin-top:10px;">
          <h3 id="viewer-title">File Viewer</h3>
          <pre id="viewer-content" style="white-space:pre-wrap; overflow-x:auto;"></pre>
        </div>
        <div class="file-actions">
          <input id="newpath" placeholder="Path to create or save" title="Enter path for new directory or file to save" />
          <button id="btn-mkdir" type="button" title="Create a new directory at the specified path">Create Directory</button>
          <button id="btn-save" type="button" title="Save the current viewer content to the specified path">Save File</button>
        </div>
      </div>
    </section>

    <section id="tab-terminal" class="tab" aria-labelledby="Terminal">
      <div class="panel">
        <h3>Web Terminal</h3>
        <p class="panel-description">Interactive command-line terminal access through your web browser. Provides full shell access with real-time input/output, command history, and proper keyboard handling. Automatically connects when you switch to this tab.</p>
        <div class="terminal-controls">
          <button id="terminal-fullscreen" type="button" title="Toggle fullscreen mode">🔲 Fullscreen</button>
          <button id="terminal-reconnect" type="button" title="Reconnect to terminal">🔄 Reconnect</button>
        </div>
        <div class="terminal-wrapper">
          <div id="term" tabindex="0"></div>
          <input id="terminal-input" type="text" style="position: absolute; left: -9999px; opacity: 0;" autocomplete="off" />
        </div>
        <div class="term-hint">Type commands here. Press Ctrl-C to interrupt running processes. Terminal has idle timeout for security.</div>
      </div>
    </section>

    <section id="tab-ai" class="tab active" aria-labelledby="Jarvis">
      <div class="panel">
        <h3>Jarvis AI Assistant <span class="ai-status" id="ai-status">🤖 Online</span></h3>
        <p class="panel-description">Your intelligent AI assistant with advanced system knowledge, learning capabilities, and personality. Jarvis remembers your preferences, learns from interactions, and provides contextual assistance with NovaShield operations, security analysis, and system management.</p>
        
        <div class="ai-stats">
          <div class="stat-item">
            <span class="stat-label">Conversations:</span>
            <span class="stat-value" id="conversation-count">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Commands Learned:</span>
            <span class="stat-value" id="commands-learned">25+</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Memory Bank:</span>
            <span class="stat-value" id="memory-size">0 KB</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Last Active:</span>
            <span class="stat-value" id="last-interaction">Never</span>
          </div>
        </div>
        
        <div class="ai-quick-actions">
          <button class="quick-action" data-command="status" title="Get current system status">📊 Status</button>
          <button class="quick-action" data-command="security scan" title="Perform security analysis">🔒 Security</button>
          <button class="quick-action" data-command="what's my ip" title="Get IP information">🌐 My IP</button>
          <button class="quick-action" data-command="backup" title="Create system backup">💾 Backup</button>
          <button class="quick-action" data-command="alerts" title="Show recent alerts">⚠️ Alerts</button>
          <button class="quick-action" data-command="help" title="Show available commands">❓ Help</button>
        </div>
        
        <div id="chat">
          <div id="chatlog"></div>
          <div class="chatbox">
            <input id="prompt" placeholder="Ask Jarvis anything... I can help with system status, security, tools, or just have a conversation!" title="Type your message or question for Jarvis - I learn and remember!" />
            <button id="send" type="button" title="Send your message to Jarvis">Send Message</button>
            <button id="voice-input" type="button" title="Use voice input (if supported)" style="display:none;">🎤</button>
          </div>
        </div>
        
        <div class="ai-learning-panel">
          <h4>🧠 Learning & Memory</h4>
          <div class="learning-stats">
            <div class="memory-item">
              <span class="memory-label">Preferred Theme:</span>
              <span class="memory-value" id="preferred-theme">jarvis-dark</span>
            </div>
            <div class="memory-item">
              <span class="memory-label">Most Used Commands:</span>
              <span class="memory-value" id="top-commands">status, help, backup</span>
            </div>
            <div class="memory-item">
              <span class="memory-label">Interaction Pattern:</span>
              <span class="memory-value" id="interaction-pattern">Technical user</span>
            </div>
            <div class="memory-item">
              <span class="memory-label">Last Topics:</span>
              <span class="memory-value" id="recent-topics">System monitoring, security</span>
            </div>
          </div>
          <button id="clear-memory" type="button" title="Clear Jarvis memory and start fresh">Clear Memory</button>
          <button id="export-memory" type="button" title="Export conversation history">Export History</button>
        </div>
      </div>
    </section>

    <section id="tab-webgen" class="tab" aria-labelledby="Web Builder">
      <div class="panel">
        <h3>Webpage Builder</h3>
        <p class="panel-description">Create custom HTML webpages and save them to your system. Enter a page title and HTML content to generate a complete webpage with proper structure and styling. Useful for creating documentation, reports, or custom pages.</p>
        <input id="wtitle" placeholder="Page title (e.g., 'My Report')" title="Title for your webpage - will be used in the HTML title tag" />
        <textarea id="wcontent" placeholder="HTML content (e.g., <h1>Hello</h1><p>Content here</p>)" title="HTML content for your webpage - can include any valid HTML"></textarea>
        <button id="wmake" type="button" title="Generate and save the webpage with your title and content">Create Webpage</button>
        <div id="wresult"></div>
      </div>
    </section>

    <section id="tab-config" class="tab" aria-labelledby="Config">
      <div class="panel">
        <h3>Configuration Viewer</h3>
        <p class="panel-description">View current NovaShield configuration settings including enabled features, monitoring thresholds, security options, and system paths. This is a read-only view - edit the configuration file directly to make changes.</p>
        <pre id="config" style="white-space:pre-wrap;"></pre>
      </div>
    </section>
  </main>

  <!-- Full-screen blackout + login overlay -->
  <div id="login" class="login" style="display:none;" aria-modal="true" role="dialog" aria-labelledby="login-title">
    <div class="login-card">
      <div class="login-logo">
        <span class="ring"></span>
        <span class="login-title" id="login-title">NovaShield Access</span>
      </div>
      <div class="login-sub">Authentication required to access dashboard</div>
      <label for="li-user" class="visually-hidden">Username</label>
      <input id="li-user" autocomplete="username" placeholder="Username" />
      <label for="li-pass" class="visually-hidden">Password</label>
      <input id="li-pass" type="password" autocomplete="current-password" placeholder="Password" />
      <label for="li-otp" class="visually-hidden">2FA Code</label>
      <input id="li-otp" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="2FA code (if enabled)" />
      <button id="li-btn" type="button">Sign in</button>
      <div id="li-msg" class="msg" role="status" aria-live="polite"></div>
    </div>
  </div>

  <script src="/static/app.js"></script>
</body>
</html>
HTML

  write_file "${NS_WWW}/style.css" 644 <<'CSS'
:root { --bg:#0a1a3d; --card:#0f1d42; --text:#e1f3ff; --muted:#8bb4d9; --ok:#00d884; --warn:#ffb347; --crit:#ff5757; --accent:#00c4f7; --ring:#00ffe1; --info:#00a8ff; --success:#16a34a; }

/* 420 Theme Variables */
:root.theme-420 { 
  --bg:#0a0f1a; 
  --card:#1a0f2a; 
  --text:#e1ffe1; 
  --muted:#b9d9b9; 
  --ok:#7fff00; 
  --warn:#ff8c00; 
  --crit:#ff4500; 
  --accent:#9370db; 
  --ring:#7fff00; 
  --info:#8a2be2; 
  --success:#32cd32; 
  --purple-bright: #e9b3ff;
  --green-bright: #7fff00;
  --blue-bright: #4169e1;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1400px 700px at 15% -25%,rgba(0,159,255,.15),transparent),linear-gradient(180deg,#021933,#0d1b3a 40%,#1a2b5c 100%);color:var(--text);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial}

/* 420 Theme Body Background */
.theme-420 body{background:radial-gradient(1400px 700px at 15% -25%,rgba(147,112,219,.15),transparent),linear-gradient(180deg,#0a0a0a,#1a0f2a 40%,#2a1a4a 100%)}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #0e223a;background:linear-gradient(180deg,rgba(0,208,255,.06),transparent)}
.brand{display:flex;align-items:center;gap:12px}
.brand h1{margin:0;font-size:20px;letter-spacing:.6px}
.brand .mini{color:var(--accent);font-weight:700;margin-left:6px}
.by{font-size:12px;color:var(--muted)}
.ring{width:20px;height:20px;border-radius:50%;box-shadow:0 0 0 3px rgba(0,255,225,.3),inset 0 0 0 2px rgba(0,255,225,.6),0 0 18px 2px rgba(0,255,225,.4)}
.actions button{background:#091425;color:#fff;border:1px solid #143055;border-radius:10px;padding:8px 12px;margin-left:8px;cursor:pointer}
.logout-link{margin-left:8px}
.tabs{display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid #0e223a;background:rgba(0,12,24,.4)}
.tabs button{background:#0a1426;border:1px solid #173764;border-radius:8px;color:#cfe6ff;padding:8px 10px;cursor:pointer}
.tabs button.active{outline:2px solid var(--accent); color:#fff}
main{padding:16px}
.tab{display:none}
.tab.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid #112540;border-radius:14px;padding:12px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.card h2{margin:0 0 8px 0;font-size:16px;color:#d1eaff}
.value{margin:0;font-size:13px;color:#cbd5e1;white-space:pre-wrap}
.panel{background:var(--card);border:1px solid #112540;border-radius:14px;padding:12px;margin-top:14px}
.panel h3{margin:0 0 8px 0;color:#d1eaff}
#alerts{list-style:none;margin:0;padding:0;max-height:360px;overflow:auto}
#alerts li{font-size:12px;border-bottom:1px solid #10233e;padding:6px 0;color:#e5e7eb}
.toggle{background:#081326;border:1px solid #15345f;border-radius:10px;color:#fff;padding:8px 10px;margin:4px;cursor:pointer}
.toggle.disabled{background:#4a1a1a;border-color:#8b4242;color:#ffb3b3}
.toggle:hover{background:#0e1a36}
.toggle.disabled:hover{background:#5a2222}
.ok{outline:2px solid var(--ok)} .warn{outline:2px solid var(--warn)} .crit{outline:2px solid var(--crit)}
#chat{display:flex;flex-direction:column;gap:8px}
#chatlog{height:220px;overflow:auto;border:1px solid #143055;border-radius:8px;padding:8px;background:#091425}
.chatbox{display:flex;gap:8px}
.chatbox input{flex:1;padding:8px;border-radius:8px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
.filebar{display:flex;gap:8px;margin-bottom:8px}
.filebar input{flex:1;padding:8px;border-radius:8px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
#filelist{font-size:13px;white-space:pre-wrap;background:#081426;border:1px solid #143055;border-radius:8px;padding:8px}
textarea#wcontent{width:100%;height:160px;background:#0b1830;color:#d7e3ff;border:1px solid #143055;border-radius:8px;padding:8px}
#term{background:#000;color:#9fe4b9;border:1px solid #173764;border-radius:10px;height:300px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;padding:8px;white-space:pre-wrap;outline:none}
.term-hint{color:#93a3c0;font-size:12px;margin-top:6px}

/* Security Logs Section */
.security-controls{display:flex;gap:12px;margin-bottom:20px;align-items:center;flex-wrap:wrap}
.security-controls button, .security-controls select{padding:8px 16px;border-radius:8px;border:1px solid #143055;background:#0e1726;color:#d7e3ff;cursor:pointer;transition:all 0.3s ease}
.security-controls button:hover{background:#173764;border-color:#1e5a96}
.security-controls select{min-width:150px}

.security-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-top:20px}
.security-card{background:var(--card);border:1px solid #143055;border-radius:12px;padding:16px;transition:all 0.3s ease}
.security-card:hover{border-color:#1e5a96;box-shadow:0 4px 12px rgba(0,208,255,0.1)}
.security-card h3{margin:0 0 12px 0;color:var(--accent);font-size:16px;font-weight:600}

.log-stats{font-size:12px;color:var(--muted);margin-bottom:12px;padding:8px;background:#0a1426;border-radius:6px;border-left:3px solid var(--accent)}
.log-stats span{color:var(--text);font-weight:600}

.log-list{max-height:200px;overflow-y:auto;margin:0;padding:0;list-style:none;background:#0a1426;border-radius:8px;border:1px solid #143055}
.log-list li{padding:8px 12px;border-bottom:1px solid #143055;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.4}
.log-list li:last-child{border-bottom:none}
.log-list li:hover{background:#0e1726}

.log-entry{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.log-time{color:var(--muted);font-size:11px;white-space:nowrap;flex-shrink:0}
.log-message{flex:1;word-break:break-word}
.log-level{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase}
.log-level.success{background:var(--ok);color:#000}
.log-level.warning{background:var(--warn);color:#000}
.log-level.error{background:var(--crit);color:#fff}
.log-level.info{background:var(--accent);color:#000}

/* Enhanced clickable log entries */
.log-entry.clickable {
    cursor: pointer;
    transition: all 0.2s ease;
    position: relative;
}

.log-entry.clickable:hover {
    background: rgba(13, 35, 57, 0.6);
    border-radius: 4px;
}

.log-entry.expanded {
    background: rgba(13, 35, 57, 0.8);
    border-radius: 4px 4px 0 0;
}

.log-expand {
    color: var(--accent);
    font-weight: bold;
    font-size: 14px;
    margin-left: 8px;
    user-select: none;
}

.log-details {
    padding: 12px;
    background: rgba(5, 15, 25, 0.8);
    border: 1px solid #143055;
    border-top: none;
    border-radius: 0 0 4px 4px;
    font-size: 11px;
    line-height: 1.5;
}

.detail-item {
    margin: 4px 0;
    display: flex;
    gap: 8px;
}

.detail-item strong {
    color: var(--accent);
    min-width: 80px;
    flex-shrink: 0;
}

.detail-item:first-child {
    margin-top: 0;
}

.detail-item:last-child {
    margin-bottom: 0;
}

/* Enhanced alert level badges */
.alert-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.alert-badge.ok{background:linear-gradient(135deg,var(--ok),#22c55e);color:#000;box-shadow:0 2px 4px rgba(0,216,132,0.3)}
.alert-badge.warn{background:linear-gradient(135deg,var(--warn),#fbbf24);color:#000;box-shadow:0 2px 4px rgba(255,179,71,0.3)}
.alert-badge.crit{background:linear-gradient(135deg,var(--crit),#ef4444);color:#fff;box-shadow:0 2px 4px rgba(255,87,87,0.3)}
.alert-badge.info{background:linear-gradient(135deg,var(--info),#3b82f6);color:#fff;box-shadow:0 2px 4px rgba(0,168,255,0.3)}

/* Status indicators with better contrast */
.status-ok{color:var(--ok);font-weight:600}
.status-warn{color:var(--warn);font-weight:600}
.status-crit{color:var(--crit);font-weight:600}
.status-info{color:var(--info);font-weight:600}

@media (max-width:980px){ .grid{grid-template-columns:1fr}; .security-grid{grid-template-columns:1fr}; .security-controls{flex-direction:column;align-items:stretch} }

/* Full-screen login overlay and lock-state */
.login{position:fixed;inset:0;background:rgba(0,0,0,.88);display:flex;align-items:center;justify-content:center;z-index:10000}
.login-card{background:#0c162b;border:1px solid #15345f;border-radius:14px;width:min(92vw,380px);padding:18px;color:#e5f0ff;box-shadow:0 10px 30px rgba(0,0,0,.5)}
.login-logo{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.login-title{font-weight:700;letter-spacing:.4px}
.login-sub{font-size:12px;color:#a9b8d6;margin-bottom:10px}
.login-card input{width:100%;margin:8px 0;padding:10px;border-radius:10px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
.login-card button{width:100%;padding:10px;border-radius:10px;background:#0a1426;border:1px solid #173764;color:#cfe6ff;cursor:pointer}
.msg{min-height:18px;font-size:12px;color:#fda4af;margin-top:8px}
.visually-hidden{position:absolute!important;height:1px;width:1px;overflow:hidden;clip:rect(1px,1px,1px,1px);white-space:nowrap;border:0;padding:0;margin:-1px}

/* When login is active: disable and blur everything behind */
body.login-active{overflow:hidden}
body.login-active header, body.login-active nav, body.login-active main{
  filter:blur(6px) brightness(0.6);
  pointer-events:none;
  user-select:none;
}

/* Small ring used in branding/login */
.login .ring{width:24px;height:24px}

/* JARVIS-specific styling */
#chat {
    background-color: rgba(0, 15, 30, 0.8);
    border-radius: 15px;
    border: 1px solid rgba(0, 208, 255, 0.3);
    box-shadow: 0 0 20px rgba(0, 208, 255, 0.1);
    padding: 15px;
}

#chatlog {
    height: 250px;
    overflow-y: auto;
    padding: 10px;
    background: rgba(5, 20, 40, 0.7);
    border-radius: 8px;
    margin-bottom: 12px;
    font-family: 'Courier New', monospace;
    line-height: 1.4;
}

#chatlog .user-msg {
    margin-bottom: 8px;
    color: #e9b3ff;
    font-weight: 500;
    padding: 6px 10px;
    background: rgba(233, 179, 255, 0.1);
    border-radius: 12px;
    border-left: 3px solid #e9b3ff;
}

#chatlog .jarvis-msg {
    margin-bottom: 12px;
    color: #7fff00;
    position: relative;
    padding: 6px 10px 6px 22px;
    background: rgba(127, 255, 0, 0.1);
    border-radius: 12px;
    border-left: 3px solid #7fff00;
}

#chatlog .jarvis-msg::before {
    content: '';
    position: absolute;
    left: 0;
    top: 5px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: radial-gradient(circle, #00ffe1 0%, rgba(0,255,225,0) 70%);
    box-shadow: 0 0 8px rgba(0, 255, 225, 0.8);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { opacity: 0.7; }
    50% { opacity: 1; }
    100% { opacity: 0.7; }
}

/* Terminal improvements */
.terminal-controls {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
    align-items: center;
}

.terminal-controls button {
    padding: 6px 12px;
    border-radius: 6px;
    border: 1px solid #143055;
    background: #0e1726;
    color: #d7e3ff;
    cursor: pointer;
    font-size: 12px;
    transition: all 0.3s ease;
}

.terminal-controls button:hover {
    background: #173764;
    border-color: #1e5a96;
}

.terminal-wrapper {
    position: relative;
}

.terminal-wrapper.fullscreen {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 9999;
    background: #000;
    padding: 20px;
}

.terminal-wrapper.fullscreen #term {
    height: calc(100vh - 80px);
    width: 100%;
    max-width: none;
}

#term {
    font-family: 'Courier New', monospace;
    white-space: pre-wrap;
    padding: 12px;
    line-height: 1.2;
    height: 350px;
    background-color: rgba(0, 10, 20, 0.95);
    color: #c0f0d0;
    border: 1px solid rgba(0, 208, 255, 0.4);
    border-radius: 8px;
    box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.5);
    overflow: auto;
    outline: none;
    resize: vertical;
    min-height: 200px;
}

/* Description styles for enhanced user guidance */
.section-description, .panel-description, .card-description {
    font-size: 14px;
    color: #93a3c0;
    margin-bottom: 16px;
    line-height: 1.5;
    padding: 12px;
    background: rgba(10, 20, 38, 0.6);
    border-radius: 8px;
    border-left: 3px solid var(--accent);
}

.card-description {
    font-size: 12px;
    margin-bottom: 10px;
    padding: 8px;
    background: rgba(5, 15, 25, 0.8);
}

.section-description {
    margin-top: 8px;
    font-weight: 500;
}

/* Tools Panel Styles */
.tools-controls {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
    flex-wrap: wrap;
}

.tools-controls button, .tools-controls select {
    background: var(--card);
    color: #cfe6ff;
    border: 1px solid #173764;
    border-radius: 8px;
    padding: 6px 12px;
    cursor: pointer;
    font-size: 12px;
}

.tools-controls button:hover {
    background: #173764;
    border-color: var(--accent);
}

.tools-grid {
    display: grid;
    gap: 16px;
    margin-bottom: 20px;
}

.tool-category h4 {
    color: var(--accent);
    margin: 0 0 10px 0;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.tool-buttons {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 8px;
}

.tool-btn {
    background: var(--card);
    border: 1px solid #173764;
    border-radius: 10px;
    padding: 10px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    color: #cfe6ff;
    transition: all 0.2s;
}

.tool-btn:hover {
    border-color: var(--accent);
    background: rgba(13, 35, 57, 0.8);
    transform: translateY(-1px);
}

.tool-btn.installed {
    border-color: #10b981;
}

.tool-btn.missing {
    border-color: #ef4444;
    opacity: 0.7;
}

.tool-icon {
    font-size: 18px;
}

.tool-name {
    font-size: 12px;
    font-weight: 500;
}

.tool-status {
    font-size: 10px;
    opacity: 0.8;
}

.tool-result-panel {
    background: rgba(5, 15, 25, 0.6);
    border: 1px solid #173764;
    border-radius: 10px;
    padding: 12px;
    margin-top: 16px;
}

.result-controls {
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
    align-items: center;
}

.result-controls button {
    background: var(--card);
    color: #cfe6ff;
    border: 1px solid #173764;
    border-radius: 6px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 11px;
}

.tool-output {
    background: #000;
    color: #0ff;
    border: 1px solid #173764;
    border-radius: 6px;
    padding: 10px;
    min-height: 150px;
    max-height: 300px;
    overflow-y: auto;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    white-space: pre-wrap;
}

/* Manual Command Panel */
.manual-command-panel {
    margin-top: 16px;
    padding: 12px;
    background: rgba(5, 15, 25, 0.6);
    border: 1px solid #173764;
    border-radius: 8px;
}

.manual-command-panel h5 {
    margin: 0 0 8px 0;
    color: var(--accent);
    font-size: 13px;
}

.command-input-group {
    display: flex;
    gap: 8px;
    margin: 8px 0;
}

.command-input-group input {
    flex: 1;
    background: #0a1426;
    border: 1px solid #173764;
    border-radius: 6px;
    padding: 6px 10px;
    color: var(--text);
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

.command-input-group button {
    background: var(--card);
    color: #cfe6ff;
    border: 1px solid #173764;
    border-radius: 6px;
    padding: 6px 12px;
    cursor: pointer;
    font-size: 11px;
}

.command-input-group button:hover {
    border-color: var(--accent);
    background: rgba(13, 35, 57, 0.8);
}

.command-suggestions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 8px;
}

.cmd-suggestion {
    background: rgba(13, 35, 57, 0.6);
    color: #cfe6ff;
    border: 1px solid #173764;
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    transition: all 0.2s;
}

.cmd-suggestion:hover {
    border-color: var(--accent);
    background: rgba(13, 35, 57, 0.9);
}

/* Enhanced AI Styles */
.ai-status {
    font-size: 12px;
    color: var(--accent);
    margin-left: 8px;
}

.ai-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 8px;
    margin: 12px 0;
    padding: 10px;
    background: rgba(5, 15, 25, 0.6);
    border-radius: 8px;
}

.stat-item {
    text-align: center;
}

.stat-label {
    display: block;
    font-size: 10px;
    color: #94a3b8;
    margin-bottom: 2px;
}

.stat-value {
    display: block;
    font-size: 12px;
    color: var(--accent);
    font-weight: 500;
}

.ai-quick-actions {
    display: flex;
    gap: 6px;
    margin: 12px 0;
    flex-wrap: wrap;
}

.quick-action {
    background: var(--card);
    color: #cfe6ff;
    border: 1px solid #173764;
    border-radius: 6px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 10px;
    transition: all 0.2s;
}

.quick-action:hover {
    border-color: var(--accent);
    background: rgba(13, 35, 57, 0.8);
}

.ai-learning-panel {
    margin-top: 16px;
    padding: 12px;
    background: rgba(5, 15, 25, 0.6);
    border: 1px solid #173764;
    border-radius: 10px;
}

.ai-learning-panel h4 {
    margin: 0 0 10px 0;
    color: var(--accent);
    font-size: 13px;
}

.learning-stats {
    display: grid;
    gap: 6px;
    margin-bottom: 10px;
}

.memory-item {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
}

.memory-label {
    color: #94a3b8;
}

.memory-value {
    color: #cfe6ff;
    font-weight: 500;
}

#voice-input {
    margin-left: 4px;
    padding: 8px;
    border-radius: 50%;
    width: 36px;
}
CSS

  write_file "${NS_WWW}/app.js" 644 <<'JS'
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Text-to-Speech functionality
let voiceEnabled = false;
let speechSynthesis = null;

// Initialize text-to-speech
function initializeTTS() {
    if ('speechSynthesis' in window) {
        speechSynthesis = window.speechSynthesis;
        // Test if voices are available
        const voices = speechSynthesis.getVoices();
        return true;
    }
    return false;
}

// Speak text if voice is enabled
function speak(text) {
    if (!voiceEnabled || !speechSynthesis || !text) return;
    
    try {
        // Cancel any ongoing speech
        speechSynthesis.cancel();
        
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 0.9;
        utterance.pitch = 1.0;
        utterance.volume = 0.8;
        
        // Try to select a voice (prefer female for Jarvis)
        const voices = speechSynthesis.getVoices();
        const femaleVoice = voices.find(voice => 
            voice.name.toLowerCase().includes('female') || 
            voice.name.toLowerCase().includes('zira') ||
            voice.name.toLowerCase().includes('hazel')
        );
        if (femaleVoice) {
            utterance.voice = femaleVoice;
        }
        
        speechSynthesis.speak(utterance);
    } catch (error) {
        console.warn('Text-to-speech failed:', error);
    }
}

// Tab lazy loading and polling management
let activeTab = 'ai';
let statusPolling = null;
let loadedTabs = new Set(['ai', 'alerts']); // Pre-load Jarvis and Alerts

const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ 
  tabs.forEach(x=>x.classList.remove('active')); 
  b.classList.add('active'); 
  $$('.tab').forEach(x=>x.classList.remove('active')); 
  const tabId = 'tab-'+b.dataset.tab;
  $('#'+tabId).classList.add('active'); 
  
  activeTab = b.dataset.tab;
  
  // Lazy load tab content if not loaded yet
  if (!loadedTabs.has(activeTab)) {
    loadTabContent(activeTab);
    loadedTabs.add(activeTab);
  }
  
  // Manage polling based on active tab
  managePolling(activeTab);
  
  // Auto-actions when switching tabs
  if (b.dataset.tab === 'files') {
    const cwdEl = $('#cwd');
    if (cwdEl && cwdEl.value) {
      list(cwdEl.value);
    }
  } else if (b.dataset.tab === 'terminal') {
    if (!ws) connectTerm();
    // Focus the hidden input for mobile keyboard support
    const termInput = $('#terminal-input');
    if (termInput) {
      setTimeout(() => {
        termInput.focus();
        // Try to trigger mobile keyboard
        termInput.click();
      }, 100);
    }
  } else if (b.dataset.tab === 'security') {
    refreshSecurityLogs();
  } else if (b.dataset.tab === 'config') {
    loadConfig();
  }
});

function loadTabContent(tabName) {
  // Load tab-specific content on demand
  if (tabName === 'status') {
    // Status tab is always loaded since it's the main dashboard
    refresh();
  } else if (tabName === 'security') {
    refreshSecurityLogs();
  } else if (tabName === 'config') {
    loadConfig();
  } else if (tabName === 'alerts') {
    loadAlerts();
  }
}

function managePolling(tabName) {
  // Stop all polling first
  if (statusPolling) {
    clearInterval(statusPolling);
    statusPolling = null;
  }
  
  // Start appropriate polling for active tab
  if (tabName === 'status') {
    // Poll status data when Status tab is active
    statusPolling = setInterval(refresh, 5000);
  } else if (tabName === 'alerts') {
    // Light polling for alerts
    statusPolling = setInterval(loadAlerts, 10000);
  }
  // Other tabs don't need continuous polling
}

let CSRF = '';

$('#btn-refresh').onclick = () => location.reload();

// 420 Theme Toggle
$('#btn-420-theme').onclick = () => {
  const root = document.documentElement;
  const btn = $('#btn-420-theme');
  const is420Active = root.classList.contains('theme-420');
  
  if (is420Active) {
    root.classList.remove('theme-420');
    btn.textContent = '🌿 420 Mode';
    btn.title = 'Toggle 420 themed colors (purple, green, blue)';
    localStorage.setItem('theme-420', 'false');
    toast('🌿 420 Theme Disabled');
  } else {
    root.classList.add('theme-420');
    btn.textContent = '🌿 Classic';
    btn.title = 'Switch back to classic blue theme';
    localStorage.setItem('theme-420', 'true');
    toast('🌿 420 Theme Activated - Purple & Green Power!');
  }
};

// Initialize 420 theme on page load
if (localStorage.getItem('theme-420') === 'true') {
  document.documentElement.classList.add('theme-420');
  const btn = $('#btn-420-theme');
  if (btn) {
    btn.textContent = '🌿 Classic';
    btn.title = 'Switch back to classic blue theme';
  }
}

// Header actions
$$('header .actions button[data-act]').forEach(btn=>{
  btn.onclick = async () => {
    const act = btn.dataset.act;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = originalText + '...';
    
    try {
      const response = await api('/api/control', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body: JSON.stringify({action: act})});
      const result = await response.json();
      if (result.ok) {
        toast(`✓ ${act.charAt(0).toUpperCase() + act.slice(1)} completed successfully`);
      } else {
        toast(`✗ ${act} failed: ${result.error || 'Unknown error'}`);
      }
    } catch(e) {
      console.error(e); 
      toast(`✗ Failed to trigger ${act}: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  };
});

function toast(msg){
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position='fixed'; t.style.right='14px'; t.style.bottom='14px';
  t.style.background='#0a1426'; t.style.border='1px solid #173764'; t.style.borderRadius='8px'; t.style.padding='8px 10px'; t.style.color='#cfe6ff'; t.style.zIndex=9999;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2500);
}

async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  if(r.status===401){
    showLogin(); throw new Error('unauthorized');
  }
  if(r.status===403){
    toast('Forbidden or CSRF'); throw new Error('forbidden');
  }
  if(!r.ok){ throw new Error('API error'); }
  return r;
}

function human(val, unit=''){ if(val===undefined || val===null) return '?'; return `${val}${unit}`; }
function setCard(id, text){ const el = $('#'+id); if(el) el.textContent = text; }

async function refresh(){
  try{
    const r = await api('/api/status'); const j = await r.json();
    CSRF = j.csrf || '';
    // If we got here successfully, ensure login overlay is off
    hideLogin();

    // Enhanced CPU information
    const cpu = j.cpu || {};
    setCard('cpu', `Load: ${human(cpu.load1)} (1m) | Warn: ${cpu.warn || '2.0'} | Crit: ${cpu.crit || '4.0'} | Status: ${cpu.level || 'OK'}`);
    
    // Enhanced Memory information  
    const mem = j.memory || {};
    const memUsed = mem.used_pct || '?';
    const memWarn = mem.warn || 85;
    const memCrit = mem.crit || 95;
    setCard('mem', `Used: ${human(memUsed, '%')} | Available: ${human(100 - (parseInt(memUsed) || 0), '%')} | Warn: ${human(memWarn, '%')} | Crit: ${human(memCrit, '%')} | Status: ${mem.level || 'OK'}`);
    
    // Enhanced Disk information
    const dsk = j.disk || {};
    const diskUsed = dsk.use_pct || '?';
    setCard('disk', `Mount: ${dsk.mount || '/'} | Used: ${human(diskUsed, '%')} | Free: ${human(100 - (parseInt(diskUsed) || 0), '%')} | Warn: ${dsk.warn || 85}% | Status: ${dsk.level || 'OK'}`);
    
    // Enhanced Network information
    const net = j.network || {};
    const netInfo = [];
    if (net.ip) netInfo.push(`Local: ${net.ip}`);
    if (net.public_ip && net.public_ip !== 'disabled' && net.public_ip !== 'unavailable') {
        netInfo.push(`Public: ${net.public_ip}`);
    }
    if (net.external_checks === 'true' || net.external_checks === true) {
        netInfo.push(`Loss: ${human(net.loss_pct, '%')}`);
        if (net.rtt_avg_ms) netInfo.push(`RTT: ${human(net.rtt_avg_ms, 'ms')}`);
    } else {
        netInfo.push('External checks: disabled');
    }
    netInfo.push(`Status: ${net.level || 'OK'}`);
    setCard('net', netInfo.join(' | '));
    
    // Enhanced monitor status information
    setCard('int', `Integrity monitoring: ${j.integrity_enabled ? 'Active' : 'Inactive'} | Files watched: ${j.integrity_files || '?'}`);
    setCard('proc', `Process monitoring: ${j.process_enabled ? 'Active' : 'Inactive'} | Suspicious patterns: ${j.suspicious_count || '?'}`);
    setCard('user', `User sessions: ${j.active_sessions || '?'} | Login monitoring: ${j.userlogins_enabled ? 'Active' : 'Inactive'}`);
    setCard('svc', `Service monitoring: ${j.services_enabled ? 'Active' : 'Inactive'} | Services watched: ${j.services_count || '?'}`);
    
    // Enhanced meta information
    const uptimeStr = j.uptime ? ` | Uptime: ${j.uptime}` : '';
    const loadAvg = cpu.load1 ? ` | Load: ${cpu.load1}` : '';
    setCard('meta', `Projects: ${j.projects_count || 0} | Modules: ${j.modules_count || 0} | Version: ${j.version}${uptimeStr}${loadAvg} | Last update: ${new Date().toLocaleTimeString()}`);
    
    // Alerts with better formatting
    const ul = $('#alerts'); if(ul){ 
        ul.innerHTML=''; 
        const alerts = (j.alerts||[]).slice(-50).reverse(); // Show last 50 alerts
        if (alerts.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No recent alerts';
            li.style.fontStyle = 'italic';
            li.style.color = '#93a3c0';
            ul.appendChild(li);
        } else {
            alerts.forEach(line => { 
                const li = document.createElement('li'); 
                li.textContent = line;
                // Color code alerts by level
                if (line.includes('[CRIT]')) li.style.color = '#ef4444';
                else if (line.includes('[WARN]')) li.style.color = '#f59e0b';
                else if (line.includes('[ERROR]')) li.style.color = '#ef4444';
                else li.style.color = '#e5e7eb';
                ul.appendChild(li);
            });
        }
    }
    
    // Status level styling
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const cardId = {memory:'card-mem', disk:'card-disk', network:'card-net', cpu:'card-cpu'}[k];
      const el = $('#'+cardId);
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    
    // Configuration display
    const conf = await (await api('/api/config')).text(); 
    const cfgEl = $('#config'); 
    if(cfgEl) cfgEl.textContent = conf;
    
  }catch(e){ 
    console.error(e);
    if (e.message === 'unauthorized') {
        showLogin();
    }
  }
}

// Load alerts data  
async function loadAlerts() {
  try {
    const r = await api('/api/status');
    const j = await r.json();
    CSRF = j.csrf || '';
    
    const alertsEl = $('#alerts');
    if (alertsEl && j.alerts) {
      alertsEl.innerHTML = '';
      const alerts = j.alerts.slice(-10); // Show last 10 alerts
      if (alerts.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No recent alerts';
        alertsEl.appendChild(li);
      } else {
        alerts.forEach(alert => {
          const li = document.createElement('li');
          li.textContent = alert;
          alertsEl.appendChild(li);
        });
      }
    }
  } catch(e) {
    console.error('Failed to load alerts:', e);
  }
}

// Load configuration data
async function loadConfig() {
  try {
    const r = await api('/api/status');
    const j = await r.json(); 
    CSRF = j.csrf || '';
    
    const cfgEl = $('#config');
    if (cfgEl && j.config) {
      cfgEl.textContent = j.config;
    }
  } catch(e) {
    console.error('Failed to load config:', e);
  }
}

// Load status data (alias for refresh function)
async function loadStatus() {
  await refresh();
}

// Load security logs (alias for refreshSecurityLogs function)
async function loadSecurityLogs() {
  await refreshSecurityLogs();
}

// Load files for file manager (trigger initial directory listing)
function loadFiles() {
  const cwdEl = $('#cwd');
  if (cwdEl && cwdEl.value) {
    list(cwdEl.value);
  }
}

// Monitors toggles
async function post(action,target){
  try{ 
    await api('/api/control',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({action,target})}); 
    toast(`✓ ${action} ${target}`); 
  }catch(e){ 
    toast(`✗ Action failed: ${action} ${target}`); 
  }
}

$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    if (!t) return;
    
    // Check if CSRF is available
    if (!CSRF) {
      toast('⚠️ Initializing system... please wait and try again');
      return;
    }
    
    const originalText = b.textContent;
    b.disabled = true;
    
    // Simple toggle logic - try to disable if currently enabled (shows "X Monitor")
    // or enable if currently disabled (shows "Enable X")
    let action;
    if (originalText.includes('Enable')) {
      action = 'enable';
      b.textContent = 'Enabling...';
    } else {
      action = 'disable'; 
      b.textContent = 'Disabling...';
    }
    
    try{ 
      const response = await api('/api/control',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({action,target:t})}); 
      const result = await response.json();
      
      if (result.ok) {
        toast(`✓ ${t} monitor ${action}d successfully`);
        // Update button text to reflect new state
        if (action === 'disable') {
          b.textContent = `Enable ${t.charAt(0).toUpperCase() + t.slice(1)}`;
          b.classList.add('disabled');
        } else {
          b.textContent = `${t.charAt(0).toUpperCase() + t.slice(1)} Monitor`;
          b.classList.remove('disabled');
        }
        
        // Refresh status if on status tab
        if (activeTab === 'status') {
          setTimeout(refresh, 1000); // Delay refresh to allow action to complete
        }
      } else {
        toast(`✗ Failed to ${action} ${t} monitor: ${result.error || 'Unknown error'}`);
        b.textContent = originalText; // Restore original text on failure
      }
    }catch(e){
      console.error(`Toggle error for ${t}:`, e);
      toast(`✗ Failed to ${action} ${t} monitor: ${e.message}`);
      b.textContent = originalText; // Restore original text on failure
    } finally {
      b.disabled = false;
    }
  };
});

// File Manager
const btnList = $('#btn-list');
if (btnList) btnList.onclick = () => list($('#cwd').value);

async function list(dir){
  try{
    let d = dir || '';
    if(d.trim().startsWith('~')) d=''; // let server default to NS_HOME
    const j = await (await api('/api/fs?dir='+encodeURIComponent(d))).json();
    const cwdEl = $('#cwd');
    if (cwdEl) cwdEl.value = j.dir;
    const wrap = $('#filelist'); 
    if (!wrap) return;
    wrap.innerHTML='';
    (j.entries||[]).forEach(e=>{
      const row = document.createElement('div');
      row.style.cursor='pointer';
      row.style.padding = '4px 8px';
      row.style.marginBottom = '2px';
      row.style.borderRadius = '4px';
      row.style.transition = 'background-color 0.2s ease';
      row.textContent = (e.is_dir?'📁 ':'📄 ') + e.name + (e.size?(' ('+formatFileSize(e.size)+')') : '');
      row.onmouseover = () => row.style.backgroundColor = 'rgba(0, 208, 255, 0.1)';
      row.onmouseout = () => row.style.backgroundColor = '';
      row.onclick = ()=>{ 
        if(e.is_dir){ 
          list(j.dir.replace(/\/+$/,'') + '/' + e.name); 
        } else { 
          viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name); 
        } 
      };
      wrap.appendChild(row);
    });
  }catch(e){ console.error(e); toast('List failed'); }
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function viewFile(path){
  try{
    const j = await (await api('/api/fs_read?path='+encodeURIComponent(path))).json();
    if(!j.ok){ toast('Open failed'); return; }
    $('#viewer-title').textContent = `Viewer — ${j.path} (${j.size} bytes)`;
    $('#viewer-content').textContent = j.content || '';
    $('#viewer').style.display = '';
  }catch(e){ console.error(e); toast('Open failed'); }
}
const btnMkdir = $('#btn-mkdir');
if (btnMkdir) btnMkdir.onclick=async()=>{
  const p=$('#newpath').value.trim(); if(!p) return;
  try{ await api('/api/fs_mkdir',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p})}); toast('mkdir ok'); list($('#cwd').value);}catch(e){toast('mkdir failed')}
}
const btnSave = $('#btn-save');
if (btnSave) btnSave.onclick=async()=>{
  const p=$('#newpath').value.trim(); const c=$('#viewer-content').textContent;
  if(!p) return; try{ await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p,content:c})}); toast('saved'); list($('#cwd').value);}catch(e){toast('save failed')}
}

// Jarvis chat - use canonical sendChat function
$('#send').onclick = sendChat;

// Add Enter key handler for chat input
$('#prompt').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendChat();
  }
});

// Web Terminal
let ws = null;
let termBuffer = '';

function connectTerm() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        return; // Already connected
    }
    
    try {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${proto}://${location.host}/ws/term`);
        const term = $('#term');
        const termInput = $('#terminal-input');
        term.textContent = 'Connecting to terminal...\n';
        ws.binaryType = 'arraybuffer';
        
        ws.onopen = () => { 
            term.textContent = '';
            // Ensure terminal is focusable and focused
            term.setAttribute('tabindex', '0');
            term.focus();
            
            // Focus hidden input for mobile keyboard support
            if (termInput) {
                termInput.focus();
                // Re-focus on click
                term.addEventListener('click', () => {
                    termInput.focus();
                });
            }
            
            // Send initial resize
            const termRect = term.getBoundingClientRect();
            const cols = Math.floor(termRect.width / 8) || 80;
            const rows = Math.floor(termRect.height / 16) || 24;
            ws.send(JSON.stringify({type: 'resize', cols, rows}));
            
            setupTerminalInput();
            toast('✓ Terminal connected');
        };
        
        ws.onmessage = (ev) => {
            if (ev.data instanceof ArrayBuffer) {
                const dec = new TextDecoder('utf-8', {fatal: false});
                const txt = dec.decode(new Uint8Array(ev.data));
                term.textContent += txt;
            } else {
                term.textContent += ev.data;
            }
            term.scrollTop = term.scrollHeight;
        };
        
        ws.onclose = () => { toast('Terminal closed'); ws = null; };
        ws.onerror = () => { toast('Terminal error'); ws = null; };
        
        // Remove any existing keydown handlers to prevent duplicates
        term.onkeydown = null;
        
        // Enhanced keydown handler with better key mapping
        term.onkeydown = (e) => {
            if (!ws || ws.readyState !== WebSocket.OPEN) return;
            e.preventDefault();
            
            let out = '';
            if (e.key === 'Enter') out = '\r';
            else if (e.key === 'Backspace') out = '\x7f';
            else if (e.key === 'Delete') out = '\x1b[3~';
            else if (e.key === 'Tab') out = '\t';
            else if (e.key === 'Escape') out = '\x1b';
            else if (e.key === 'ArrowUp') out = '\x1b[A';
            else if (e.key === 'ArrowDown') out = '\x1b[B';
            else if (e.key === 'ArrowRight') out = '\x1b[C';
            else if (e.key === 'ArrowLeft') out = '\x1b[D';
            else if (e.key === 'Home') out = '\x1b[H';
            else if (e.key === 'End') out = '\x1b[F';
            else if (e.key === 'PageUp') out = '\x1b[5~';
            else if (e.key === 'PageDown') out = '\x1b[6~';
            else if (e.ctrlKey && e.key.toLowerCase() === 'c') out = '\x03';
            else if (e.ctrlKey && e.key.toLowerCase() === 'd') out = '\x04';
            else if (e.ctrlKey && e.key.toLowerCase() === 'z') out = '\x1a';
            else if (e.ctrlKey && e.key.toLowerCase() === 'l') out = '\x0c';
            else if (e.key.length === 1) out = e.key;
            
            if (out) { 
                ws.send(new TextEncoder().encode(out)); 
            }
        };
        
        // Ensure terminal stays focused when clicked
        term.onclick = () => term.focus();
        
    } catch (e) { 
        console.error(e); 
        toast('Terminal connection failed'); 
        ws = null;
    }
}

function setupTerminalInput() {
    const term = $('#term');
    const termInput = $('#terminal-input');
    
    // Mobile keyboard support
    term.onclick = () => {
        term.focus();
        // On mobile, also focus the hidden input to trigger virtual keyboard
        if (isMobile()) {
            termInput.focus();
            // Quickly refocus back to terminal to maintain visual focus
            setTimeout(() => term.focus(), 50);
        }
    };
    
    // Mirror hidden input to WebSocket
    termInput.oninput = () => {
        if (ws && ws.readyState === WebSocket.OPEN && termInput.value) {
            ws.send(new TextEncoder().encode(termInput.value));
            termInput.value = '';
        }
    };
    
    // Handle special keys from hidden input
    termInput.onkeydown = (e) => {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        
        let out = '';
        if (e.key === 'Enter') out = '\r';
        else if (e.key === 'Backspace') out = '\x7f';
        else if (e.key === 'Tab') { out = '\t'; e.preventDefault(); }
        
        if (out) {
            ws.send(new TextEncoder().encode(out));
            e.preventDefault();
        }
    };
}

function isMobile() {
    return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
           (window.innerWidth <= 768);
}

function toggleTerminalFullscreen() {
    const wrapper = $('.terminal-wrapper');
    const btn = $('#terminal-fullscreen');
    
    if (wrapper.classList.contains('fullscreen')) {
        wrapper.classList.remove('fullscreen');
        btn.textContent = '🔲 Fullscreen';
        document.removeEventListener('keydown', handleFullscreenEscape);
    } else {
        wrapper.classList.add('fullscreen');
        btn.textContent = '❌ Exit Fullscreen';
        document.addEventListener('keydown', handleFullscreenEscape);
        // Refocus terminal in fullscreen
        setTimeout(() => $('#term').focus(), 100);
    }
}

function handleFullscreenEscape(e) {
    if (e.key === 'Escape') {
        const wrapper = $('.terminal-wrapper');
        if (wrapper.classList.contains('fullscreen')) {
            toggleTerminalFullscreen();
            e.preventDefault();
        }
    }
}

// Terminal control event listeners
$('#terminal-fullscreen')?.addEventListener('click', toggleTerminalFullscreen);
$('#terminal-reconnect')?.addEventListener('click', () => {
    if (ws) {
        ws.close();
        ws = null;
    }
    setTimeout(connectTerm, 500);
});

function showLogin() {
    $('#login').style.display = 'flex';
    document.body.classList.add('login-active');
}

function hideLogin() {
    $('#login').style.display = 'none';
    document.body.classList.remove('login-active');
}

$('#li-btn').onclick = async () => {
    const user = $('#li-user').value.trim(), pass = $('#li-pass').value, otp = $('#li-otp').value.trim();
    const msgEl = $('#li-msg');
    
    if (!user || !pass) {
        msgEl.textContent = 'Please enter username and password';
        return;
    }
    
    try {
        msgEl.textContent = 'Authenticating...';
        const r = await fetch('/api/login', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({user, pass, otp})
        });
        
        if (r.ok) { 
            const j = await r.json(); 
            CSRF = j.csrf || ''; 
            hideLogin(); 
            toast('Login successful'); 
            refresh(); 
        } else if (r.status === 401) {
            const j = await r.json().catch(() => ({}));
            if (j.need_2fa) {
                msgEl.textContent = 'Please enter your 2FA code';
                $('#li-otp').focus();
            } else {
                msgEl.textContent = 'Invalid credentials';
            }
        } else {
            msgEl.textContent = 'Login failed';
        }
    } catch (e) { 
        msgEl.textContent = 'Connection error'; 
    }
};

// Check authentication status on page load
async function checkAuth() {
    try {
        const r = await fetch('/api/status');
        if (r.status === 401) {
            showLogin();
        } else {
            const j = await r.json();
            CSRF = j.csrf || '';
            hideLogin();
        }
    } catch (e) {
        showLogin();
    }
}

// Allow Enter key to submit login
$('#li-user').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') $('#li-pass').focus();
});
$('#li-pass').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        if ($('#li-otp').style.display !== 'none') {
            $('#li-otp').focus();
        } else {
            $('#li-btn').click();
        }
    }
});
$('#li-otp').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') $('#li-btn').click();
});

// Security Logs functionality
let securityData = null;

async function refreshSecurityLogs() {
    try {
        const r = await api('/api/security', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF': CSRF},
            body: JSON.stringify({})
        });
        securityData = await r.json();
        updateSecurityDisplay();
    } catch (e) {
        console.error('Failed to fetch security logs:', e);
        toast('Failed to refresh security logs');
    }
}

function updateSecurityDisplay() {
    if (!securityData) return;
    
    const stats = securityData.stats;
    const logs = securityData.logs;
    
    // Update statistics
    const setCount = (id, value) => {
        const el = $(id);
        if (el) el.textContent = value;
    };
    
    setCount('#auth-success-count', stats.auth_success);
    setCount('#auth-fail-count', stats.auth_fail);
    setCount('#active-sessions-count', stats.active_sessions);
    setCount('#audit-count', stats.audit_count);
    setCount('#security-count', stats.security_count);
    setCount('#threat-count', stats.threat_count);
    setCount('#integrity-files', stats.integrity_files);
    setCount('#integrity-changes', stats.integrity_changes);
    setCount('#last-audit', stats.last_audit);
    
    // Update log lists
    updateLogList('#auth-logs', logs.auth);
    updateLogList('#audit-logs', logs.audit);
    updateLogList('#security-logs', logs.security);
    updateLogList('#integrity-logs', logs.integrity);
}

function updateLogList(selector, logEntries) {
    const ul = $(selector);
    if (!ul) return;
    
    ul.innerHTML = '';
    
    if (!logEntries || logEntries.length === 0) {
        const li = document.createElement('li');
        li.innerHTML = '<div class="log-entry"><span class="log-message">No events recorded</span></div>';
        ul.appendChild(li);
        return;
    }
    
    logEntries.forEach((entry, index) => {
        const li = document.createElement('li');
        const levelClass = entry.level || 'info';
        const entryId = `entry-${selector.replace('#', '')}-${index}`;
        
        li.innerHTML = `
            <div class="log-entry clickable" data-entry-id="${entryId}">
                <span class="log-time">${entry.timestamp}</span>
                <span class="log-message">${escapeHtml(entry.message)}</span>
                <span class="log-level ${levelClass}">${levelClass}</span>
                <span class="log-expand">+</span>
            </div>
            <div class="log-details" id="${entryId}-details" style="display: none;">
                <div class="detail-item"><strong>Timestamp:</strong> ${entry.timestamp}</div>
                <div class="detail-item"><strong>Level:</strong> ${entry.level || 'info'}</div>
                <div class="detail-item"><strong>Message:</strong> ${escapeHtml(entry.message)}</div>
                ${entry.ip ? `<div class="detail-item"><strong>IP Address:</strong> ${entry.ip}</div>` : ''}
                ${entry.user ? `<div class="detail-item"><strong>User:</strong> ${entry.user}</div>` : ''}
                ${entry.user_agent ? `<div class="detail-item"><strong>User Agent:</strong> ${escapeHtml(entry.user_agent)}</div>` : ''}
                ${entry.details ? `<div class="detail-item"><strong>Details:</strong> ${escapeHtml(entry.details)}</div>` : ''}
            </div>
        `;
        
        // Add click handler for expandable details
        const logEntry = li.querySelector('.log-entry.clickable');
        logEntry.addEventListener('click', () => {
            const details = li.querySelector('.log-details');
            const expand = li.querySelector('.log-expand');
            
            if (details.style.display === 'none') {
                details.style.display = 'block';
                expand.textContent = '-';
                logEntry.classList.add('expanded');
            } else {
                details.style.display = 'none';
                expand.textContent = '+';
                logEntry.classList.remove('expanded');
            }
        });
        
        ul.appendChild(li);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Security controls event listeners
const btnRefreshSecurity = $('#btn-refresh-security');
if (btnRefreshSecurity) {
    btnRefreshSecurity.onclick = () => {
        btnRefreshSecurity.disabled = true;
        btnRefreshSecurity.textContent = 'Refreshing...';
        refreshSecurityLogs().finally(() => {
            btnRefreshSecurity.disabled = false;
            btnRefreshSecurity.textContent = 'Refresh Logs';
        });
    };
}

const btnClearLogs = $('#btn-clear-logs');
if (btnClearLogs) {
    btnClearLogs.onclick = async () => {
        if (!confirm('Are you sure you want to clear old security logs? This action cannot be undone.')) {
            return;
        }
        
        btnClearLogs.disabled = true;
        btnClearLogs.textContent = 'Clearing...';
        
        try {
            await api('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-CSRF': CSRF},
                body: JSON.stringify({action: 'clear_logs'})
            });
            toast('✓ Old logs cleared successfully');
            refreshSecurityLogs();
        } catch (e) {
            toast('✗ Failed to clear logs');
        } finally {
            btnClearLogs.disabled = false;
            btnClearLogs.textContent = 'Clear Old Logs';
        }
    };
}

const logFilter = $('#log-filter');
if (logFilter) {
    logFilter.onchange = () => {
        const filter = logFilter.value;
        // Hide/show log cards based on filter
        $$('.security-card').forEach(card => {
            const cardId = card.querySelector('h3').textContent.toLowerCase().replace(/\s+/g, '');
            if (filter === 'all') {
                card.style.display = 'block';
            } else {
                const shouldShow = (
                    (filter === 'auth' && cardId.includes('authentication')) ||
                    (filter === 'audit' && cardId.includes('audit')) ||
                    (filter === 'security' && cardId.includes('security')) ||
                    (filter === 'session' && cardId.includes('authentication'))  // Sessions are part of auth
                );
                card.style.display = shouldShow ? 'block' : 'none';
            }
        });
    };
}

// Tab switching enhancement to load security logs when security tab is selected
const originalTabHandling = document.querySelector('[data-tab="security"]');
if (originalTabHandling) {
    originalTabHandling.addEventListener('click', () => {
        // Refresh security logs when switching to security tab
        setTimeout(() => {
            if (!securityData) {
                refreshSecurityLogs();
            }
        }, 100);
    });
}

// Initialize the application
checkAuth(); 
refresh(); 
setInterval(refresh, 5000);

// Auto-refresh security logs every 30 seconds when security tab is active
setInterval(() => {
    const securityTab = $('#tab-security');
    if (securityTab && securityTab.classList.contains('active')) {
        refreshSecurityLogs();
    }
}, 30000);

// ========== TOOLS PANEL FUNCTIONALITY ==========
let availableTools = {};
let toolExecutionHistory = [];

// Initialize tools when tab is loaded
function initTools() {
    if (!loadedTabs.has('tools')) {
        loadedTabs.add('tools');
        scanSystemTools();
        bindToolEvents();
    }
}

function bindToolEvents() {
    // Tool control buttons
    $('#btn-scan-tools')?.addEventListener('click', scanSystemTools);
    $('#btn-install-missing')?.addEventListener('click', installMissingTools);
    $('#btn-refresh-tools')?.addEventListener('click', refreshToolStatus);
    
    // Tool category filter
    $('#tool-category')?.addEventListener('change', filterToolsByCategory);
    
    // Result panel controls
    $('#clear-results')?.addEventListener('click', () => {
        $('#tool-output').textContent = '';
        $('#active-tool').textContent = 'No tool selected';
    });
    
    $('#save-results')?.addEventListener('click', saveToolOutput);
    
    // Tool execution buttons
    $$('.tool-btn').forEach(btn => {
        btn.addEventListener('click', () => executeTool(btn.dataset.tool));
    });
    
    // Manual command execution
    $('#execute-command')?.addEventListener('click', executeManualCommand);
    $('#manual-command')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') executeManualCommand();
    });
    
    // Command suggestions
    $$('.cmd-suggestion').forEach(btn => {
        btn.addEventListener('click', () => {
            const cmdInput = $('#manual-command');
            if (cmdInput) cmdInput.value = btn.dataset.cmd;
        });
    });
}

async function scanSystemTools() {
    const outputEl = $('#tool-output');
    const scanBtn = $('#btn-scan-tools');
    
    if (scanBtn) scanBtn.textContent = 'Scanning...';
    if (outputEl) outputEl.textContent = 'Scanning system for available tools...\n';
    
    try {
        const response = await fetch('/api/tools/scan', {
            method: 'POST',
            headers: { 'X-CSRF': CSRF, 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            const data = await response.json();
            availableTools = data.tools || {};
            updateToolStatus(data.tools);
            if (outputEl) outputEl.textContent += `Found ${Object.keys(availableTools).length} tools\n`;
            toast('✓ Tool scan completed', 'success');
        }
    } catch (err) {
        console.error('Tool scan failed:', err);
        if (outputEl) outputEl.textContent += 'Error: Failed to scan tools\n';
        toast('✗ Tool scan failed', 'error');
    }
    
    if (scanBtn) scanBtn.textContent = 'Scan Tools';
}

function updateToolStatus(tools) {
    Object.entries(tools).forEach(([toolName, toolInfo]) => {
        const statusEl = $(`#${toolName}-status`);
        const btnEl = $(`.tool-btn[data-tool="${toolName}"]`);
        
        if (statusEl) {
            statusEl.textContent = toolInfo.available ? 'Available' : 'Missing';
            statusEl.style.color = toolInfo.available ? '#10b981' : '#ef4444';
        }
        
        if (btnEl) {
            btnEl.classList.toggle('installed', toolInfo.available);
            btnEl.classList.toggle('missing', !toolInfo.available);
            btnEl.disabled = !toolInfo.available;
        }
    });
}

async function installMissingTools() {
    const outputEl = $('#tool-output');
    const installBtn = $('#btn-install-missing');
    
    if (installBtn) installBtn.textContent = 'Installing...';
    if (outputEl) outputEl.textContent = 'Installing missing tools...\n';
    
    try {
        const response = await fetch('/api/tools/install', {
            method: 'POST',
            headers: { 'X-CSRF': CSRF, 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (outputEl) outputEl.textContent += data.output || 'Installation completed\n';
            await scanSystemTools(); // Refresh tool status
            toast('✓ Tools installation completed', 'success');
        }
    } catch (err) {
        console.error('Tool installation failed:', err);
        if (outputEl) outputEl.textContent += 'Error: Failed to install tools\n';
        toast('✗ Tool installation failed', 'error');
    }
    
    if (installBtn) installBtn.textContent = 'Install Missing Tools';
}

async function executeTool(toolName) {
    const outputEl = $('#tool-output');
    const activeToolEl = $('#active-tool');
    
    if (activeToolEl) activeToolEl.textContent = `Running: ${toolName}`;
    if (outputEl) outputEl.textContent = `Executing ${toolName}...\n`;
    
    try {
        const response = await fetch('/api/tools/execute', {
            method: 'POST',
            headers: { 'X-CSRF': CSRF, 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: toolName })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (outputEl) {
                outputEl.textContent = `=== ${toolName.toUpperCase()} OUTPUT ===\n`;
                outputEl.textContent += data.output || 'No output returned';
                outputEl.textContent += `\n\n=== COMPLETED ===\n`;
            }
            
            // Add to execution history
            toolExecutionHistory.unshift({
                tool: toolName,
                timestamp: new Date().toLocaleString(),
                output: data.output
            });
            
            toast(`✓ ${toolName} executed successfully`, 'success');
        }
    } catch (err) {
        console.error('Tool execution failed:', err);
        if (outputEl) outputEl.textContent += `Error: Failed to execute ${toolName}\n`;
        toast(`✗ ${toolName} execution failed`, 'error');
    }
}

function refreshToolStatus() {
    scanSystemTools();
}

function filterToolsByCategory() {
    const category = $('#tool-category')?.value;
    const toolCategories = $$('.tool-category');
    
    toolCategories.forEach(cat => {
        if (category === 'all') {
            cat.style.display = 'block';
        } else {
            const categoryId = cat.querySelector('.tool-buttons').id.replace('-tools', '');
            cat.style.display = categoryId === category ? 'block' : 'none';
        }
    });
}

function saveToolOutput() {
    const output = $('#tool-output')?.textContent;
    if (!output) return;
    
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tool-output-${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast('✓ Output saved to file', 'success');
}

async function executeManualCommand() {
    const cmdInput = $('#manual-command');
    const outputEl = $('#tool-output');
    const activeToolEl = $('#active-tool');
    
    if (!cmdInput || !cmdInput.value.trim()) {
        toast('⚠️ Please enter a command to execute');
        return;
    }
    
    const command = cmdInput.value.trim();
    
    // Security warning for dangerous commands
    const dangerousCommands = ['rm ', 'rmdir', 'dd ', 'mkfs', 'format', 'fdisk', 'shutdown', 'reboot', 'init ', 'kill -9'];
    const isDangerous = dangerousCommands.some(cmd => command.toLowerCase().includes(cmd));
    
    if (isDangerous) {
        if (!confirm(`⚠️ WARNING: "${command}" may be a dangerous command that could damage your system. Are you sure you want to execute it?`)) {
            return;
        }
    }
    
    if (activeToolEl) activeToolEl.textContent = `Running: ${command}`;
    if (outputEl) outputEl.textContent = `Executing: ${command}\n`;
    
    try {
        const response = await fetch('/api/tools/execute', {
            method: 'POST',
            headers: { 'X-CSRF': CSRF, 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: 'custom', command: command })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (outputEl) {
                outputEl.textContent = `=== COMMAND: ${command} ===\n`;
                outputEl.textContent += data.output || 'Command executed successfully (no output)';
                outputEl.textContent += '\n\n=== EXECUTION COMPLETE ===';
            }
            
            toast(`✓ Command executed successfully`, 'success');
        } else {
            const error = await response.text();
            if (outputEl) outputEl.textContent += `\nError: ${error}`;
            toast(`✗ Command execution failed`, 'error');
        }
    } catch (err) {
        console.error('Manual command execution failed:', err);
        if (outputEl) outputEl.textContent += `\nError: ${err.message}`;
        toast(`✗ Command execution failed: ${err.message}`, 'error');
    }
    
    // Clear the input
    cmdInput.value = '';
}

// ========== ENHANCED JARVIS AI FUNCTIONALITY ==========
let conversationHistory = [];
let userPreferences = {};
let jarvisMemory = {};

// Enhanced chat functionality
function initEnhancedAI() {
    loadJarvisMemory();
    updateAIStats();
    bindAIEvents();
    initializeVoice();
}

async function initializeVoice() {
    try {
        // Load voice_enabled setting from status API
        const response = await fetch('/api/status');
        if (response.ok) {
            const data = await response.json();
            voiceEnabled = data.voice_enabled || false;
        }
        
        // Initialize TTS if available and enabled
        if (voiceEnabled) {
            const ttsAvailable = initializeTTS();
            if (!ttsAvailable) {
                console.warn('Text-to-speech not available in this browser');
                voiceEnabled = false;
            }
        }
    } catch (error) {
        console.warn('Failed to initialize voice:', error);
        voiceEnabled = false;
    }
}

function bindAIEvents() {
    // Quick action buttons
    $$('.quick-action').forEach(btn => {
        btn.addEventListener('click', () => {
            const command = btn.dataset.command;
            $('#prompt').value = command;
            sendChat();
        });
    });
    
    // Memory management buttons
    $('#clear-memory')?.addEventListener('click', clearJarvisMemory);
    $('#export-memory')?.addEventListener('click', exportConversationHistory);
    
    // Voice input (if supported)
    if ('webkitSpeechRecognition' in window) {
        $('#voice-input').style.display = 'inline-block';
        $('#voice-input').addEventListener('click', startVoiceInput);
    }
}

async function loadJarvisMemory() {
    try {
        const response = await fetch('/api/jarvis/memory');
        if (response.ok) {
            const data = await response.json();
            jarvisMemory = data.memory || {};
            userPreferences = data.preferences || {};
            conversationHistory = data.history || [];
            updateAIStats();
        }
    } catch (err) {
        console.error('Failed to load Jarvis memory:', err);
    }
}

async function saveJarvisMemory() {
    try {
        await fetch('/api/jarvis/memory', {
            method: 'POST',
            headers: { 'X-CSRF': CSRF, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                memory: jarvisMemory,
                preferences: userPreferences,
                history: conversationHistory.slice(-50) // Keep last 50 interactions
            })
        });
    } catch (err) {
        console.error('Failed to save Jarvis memory:', err);
    }
}

function updateAIStats() {
    $('#conversation-count').textContent = conversationHistory.length;
    $('#memory-size').textContent = Math.round(JSON.stringify(jarvisMemory).length / 1024) + ' KB';
    $('#last-interaction').textContent = conversationHistory.length > 0 
        ? new Date(conversationHistory[conversationHistory.length - 1].timestamp).toLocaleString()
        : 'Never';
    
    // Update learning stats
    const topCommands = getTopCommands();
    $('#top-commands').textContent = topCommands.join(', ');
    $('#preferred-theme').textContent = userPreferences.theme || 'jarvis-dark';
    $('#interaction-pattern').textContent = analyzeInteractionPattern();
    $('#recent-topics').textContent = getRecentTopics().join(', ');
}

function getTopCommands() {
    const commandCounts = {};
    conversationHistory.forEach(entry => {
        if (entry.type === 'user') {
            const words = entry.message.toLowerCase().split(' ');
            words.forEach(word => {
                if (word.length > 3) {
                    commandCounts[word] = (commandCounts[word] || 0) + 1;
                }
            });
        }
    });
    
    return Object.entries(commandCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([cmd]) => cmd);
}

function analyzeInteractionPattern() {
    const totalMessages = conversationHistory.filter(e => e.type === 'user').length;
    if (totalMessages < 5) return 'New user';
    
    const commandMessages = conversationHistory.filter(e => 
        e.type === 'user' && 
        ['status', 'backup', 'scan', 'help', 'tools'].some(cmd => 
            e.message.toLowerCase().includes(cmd)
        )
    ).length;
    
    const ratio = commandMessages / totalMessages;
    if (ratio > 0.7) return 'Technical user';
    if (ratio > 0.4) return 'Mixed usage';
    return 'Conversational user';
}

function getRecentTopics() {
    const recent = conversationHistory.slice(-10);
    const topics = new Set();
    
    recent.forEach(entry => {
        if (entry.type === 'user') {
            const message = entry.message.toLowerCase();
            if (message.includes('security') || message.includes('scan')) topics.add('security');
            if (message.includes('status') || message.includes('monitor')) topics.add('monitoring');
            if (message.includes('backup') || message.includes('save')) topics.add('backup');
            if (message.includes('tool') || message.includes('install')) topics.add('tools');
            if (message.includes('network') || message.includes('ip')) topics.add('network');
        }
    });
    
    return Array.from(topics).slice(0, 3);
}

function clearJarvisMemory() {
    if (confirm('Clear all Jarvis memory and conversation history?')) {
        jarvisMemory = {};
        userPreferences = {};
        conversationHistory = [];
        $('#chatlog').innerHTML = '';
        saveJarvisMemory();
        updateAIStats();
        toast('✓ Jarvis memory cleared', 'success');
    }
}

function exportConversationHistory() {
    const data = {
        exported: new Date().toISOString(),
        user: userInfo?.username || 'unknown',
        conversations: conversationHistory,
        preferences: userPreferences,
        stats: {
            totalMessages: conversationHistory.length,
            pattern: analyzeInteractionPattern(),
            topCommands: getTopCommands(),
            recentTopics: getRecentTopics()
        }
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `jarvis-conversation-history-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('✓ Conversation history exported', 'success');
}

function startVoiceInput() {
    if (!('webkitSpeechRecognition' in window)) return;
    
    const recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    
    recognition.onstart = () => {
        $('#voice-input').textContent = '🔴';
        toast('🎤 Listening...', 'info');
    };
    
    recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        $('#prompt').value = transcript;
        toast('✓ Voice input received', 'success');
    };
    
    recognition.onend = () => {
        $('#voice-input').textContent = '🎤';
    };
    
    recognition.onerror = () => {
        toast('✗ Voice input failed', 'error');
        $('#voice-input').textContent = '🎤';
    };
    
    recognition.start();
}

// Canonical sendChat function
async function sendChat() {
  const prompt = $('#prompt').value.trim(); 
  if(!prompt) return;
  const log = $('#chatlog'); 
  const you = document.createElement('div'); 
  you.className = 'user-msg';
  you.textContent='You: '+prompt; 
  log.appendChild(you);
  try {
    const j = await (await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({prompt})})).json();
    const ai = document.createElement('div'); 
    ai.className = 'jarvis-msg';
    ai.textContent='Jarvis: '+j.reply; 
    log.appendChild(ai); 
    $('#prompt').value=''; 
    log.scrollTop=log.scrollHeight;
    
    // Speak the reply if voice is enabled and speak flag is set
    if (j.speak && voiceEnabled) {
      speak(j.reply);
    }
  } catch(e) { 
    const err = document.createElement('div'); 
    err.className = 'error-msg';
    err.textContent='Error: ' + e.message; 
    log.appendChild(err); 
    log.scrollTop=log.scrollHeight;
  }
}

// Enhanced sendChat with learning capabilities
const originalSendChat = window.sendChat;
window.sendChat = async function() {
    const prompt = $('#prompt');
    const message = prompt.value.trim();
    if (!message) return;
    
    // Add to conversation history
    conversationHistory.push({
        type: 'user',
        message: message,
        timestamp: new Date().toISOString()
    });
    
    // Call original sendChat
    await originalSendChat();
    
    // Update learning data
    updateUserLearning(message);
    saveJarvisMemory();
    updateAIStats();
    
    // Update last interaction
    $('#last-interaction').textContent = new Date().toLocaleString();
};

function updateUserLearning(message) {
    // Track command usage
    const lowerMessage = message.toLowerCase();
    
    // Update preferences based on usage patterns
    if (lowerMessage.includes('dark') || lowerMessage.includes('theme')) {
        userPreferences.theme = 'jarvis-dark';
    }
    
    // Track frequently used features
    if (!jarvisMemory.featureUsage) jarvisMemory.featureUsage = {};
    
    const features = ['status', 'backup', 'security', 'tools', 'monitor', 'scan', 'network'];
    features.forEach(feature => {
        if (lowerMessage.includes(feature)) {
            jarvisMemory.featureUsage[feature] = (jarvisMemory.featureUsage[feature] || 0) + 1;
        }
    });
}

// Initialize enhanced features when appropriate tabs are loaded
const originalTabClick = tabs[0]?.onclick;
tabs.forEach(b => {
    b.onclick = () => {
        // Call original tab switching logic
        tabs.forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        $$('.tab').forEach(x => x.classList.remove('active'));
        const tabId = 'tab-' + b.dataset.tab;
        $('#' + tabId).classList.add('active');
        
        activeTab = b.dataset.tab;
        
        // Initialize enhanced features for specific tabs
        if (activeTab === 'tools' && !loadedTabs.has('tools')) {
            initTools();
        }
        
        if (activeTab === 'ai' && !loadedTabs.has('ai-enhanced')) {
            loadedTabs.add('ai-enhanced');
            initEnhancedAI();
        }
        
        // Original polling and loading logic
        if (activeTab === 'status' && !loadedTabs.has('status')) {
            loadedTabs.add('status');
            loadStatus();
            if (!statusPolling) {
                statusPolling = setInterval(loadStatus, 3000);
            }
        } else if (activeTab !== 'status' && statusPolling) {
            clearInterval(statusPolling);
            statusPolling = null;
        }
        
        // Load other tabs on demand
        ['files', 'terminal', 'webgen', 'config', 'security'].forEach(tab => {
            if (activeTab === tab && !loadedTabs.has(tab)) {
                loadedTabs.add(tab);
                if (tab === 'files') loadFiles();
                else if (tab === 'terminal') connectTerm();
                else if (tab === 'config') loadConfig();
                else if (tab === 'security') loadSecurityLogs();
            }
        });
    };
});

// Initialize AI enhancements on page load
initEnhancedAI();
JS
}

setup_termux_service(){
  if ! command -v sv-enable >/dev/null 2>&1; then return 0; fi
  local svcdir="${HOME}/.termux/services/novashield"
  mkdir -p "$svcdir"
  write_file "$svcdir/run" 700 <<RUN
#!/data/data/com.termux/files/usr/bin/sh
exec python3 "${NS_WWW}/server.py" >>"${NS_HOME}/web.log" 2>&1
RUN
  sv-enable novashield || ns_warn "termux-services enable failed (non-blocking)"
  ns_ok "Termux service installed: sv-enable novashield"
}

setup_systemd_user(){
  if ! command -v systemctl >/dev/null 2>&1; then return 0; fi
  local udir="${HOME}/.config/systemd/user"; mkdir -p "$udir"
  write_file "$udir/novashield.service" 644 <<SERVICE
[Unit]
Description=NovaShield Web Server (User)
After=default.target

[Service]
Type=simple
ExecStart=${NS_WWW}/server.py
WorkingDirectory=${NS_WWW}
Restart=on-failure

[Install]
WantedBy=default.target
SERVICE
  systemctl --user daemon-reload || true
  ns_ok "systemd user service written. Enable with: systemctl --user enable --now novashield"
}

open_session(){ echo "$(ns_now) START ${NS_VERSION}" >>"$NS_SESSION"; }
close_session(){ echo "$(ns_now) STOP" >>"$NS_SESSION"; }

start_web(){
  ns_log "Starting web server..."
  
  # Ensure directories exist and generate required files
  ensure_dirs
  write_default_config
  generate_keys
  write_server_py
  write_dashboard
  
  # Verify prerequisites
  if ! command -v python3 >/dev/null 2>&1; then
    die "Python3 is required but not found. Run: $0 --install"
  fi
  
  if [ ! -f "${NS_WWW}/server.py" ]; then
    ns_warn "Server file missing, regenerating..."
    write_server_py || die "Failed to generate server.py"
  fi
  
  # Check if web server is already running by checking port
  local host port
  host=$(yaml_get "http" "host" "127.0.0.1")
  port=$(yaml_get "http" "port" "8765")
  
  if command -v netstat >/dev/null 2>&1; then
    if netstat -ln 2>/dev/null | grep -q ":${port}.*LISTEN"; then
      # Check if it's our process
      local existing_pid; existing_pid=$(safe_read_pid "${NS_PID}/web.pid")
      if [ "$existing_pid" -gt 0 ] && kill -0 "$existing_pid" 2>/dev/null; then
        ns_warn "Web server already running (PID $existing_pid)"
        return 0
      else
        ns_warn "Port $port is in use by another process. Attempting cleanup..."
        # Try to find and clean up stale processes
        pkill -f "python3.*server\.py" 2>/dev/null || true
        sleep 1
      fi
    fi
  fi
  
  # Stop any existing web server tracked by us
  stop_web || true
  
  # Start server with error handling
  python3 "${NS_WWW}/server.py" >"${NS_HOME}/web.log" 2>&1 &
  local pid=$!
  
  # Check if the process started successfully
  sleep 0.1
  if ! kill -0 "$pid" 2>/dev/null; then
    die "Failed to start web server process"
  fi
  safe_write_pid "${NS_PID}/web.pid" "$pid"
  
  # Give server a moment to start and verify it's running
  sleep 2
  if ! kill -0 "$pid" 2>/dev/null; then
    ns_err "Web server failed to start. Check ${NS_HOME}/web.log for errors"
    cat "${NS_HOME}/web.log" | tail -10 >&2
    return 1
  fi
  
  # Verify the server is actually responding
  local port; port=$(yaml_get "http" "port" "8765")
  local attempt=0
  while [ $attempt -lt 5 ]; do
    if command -v curl >/dev/null 2>&1; then
      if curl -s -f http://127.0.0.1:${port}/ >/dev/null 2>&1; then
        break
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q -O /dev/null http://127.0.0.1:${port}/ 2>/dev/null; then
        break
      fi
    else
      # No curl or wget available, just trust the port check
      break
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  
  ns_ok "Web server started (PID $pid)"
}

stop_web(){
  local any=0
  local failed=0
  
  if [ -f "${NS_PID}/web.pid" ]; then
    local pid; pid=$(safe_read_pid "${NS_PID}/web.pid")
    if [ "$pid" -gt 0 ]; then
      if kill -0 "$pid" 2>/dev/null; then
        ns_log "Stopping web server process $pid..."
        kill "$pid" 2>/dev/null || true
        sleep 1
        # Check if process is still running and force kill if needed
        if kill -0 "$pid" 2>/dev/null; then
          ns_warn "Process $pid didn't respond to TERM, using KILL..."
          kill -9 "$pid" 2>/dev/null || true
          sleep 0.5
          if kill -0 "$pid" 2>/dev/null; then
            ns_err "Failed to kill process $pid"
            failed=1
          fi
        fi
        any=1
      fi
    fi
    rm -f "${NS_PID}/web.pid"
  fi
  
  # Enhanced stray process detection and cleanup
  local host port
  host=$(yaml_get "http" "host" "127.0.0.1")
  port=$(yaml_get "http" "port" "8765")
  
  # Check if port is still in use
  local port_in_use=0
  if command -v netstat >/dev/null 2>&1; then
    netstat -ln 2>/dev/null | grep -q ":${port}.*LISTEN" && port_in_use=1
  elif command -v ss >/dev/null 2>&1; then
    ss -ln 2>/dev/null | grep -q ":${port}.*LISTEN" && port_in_use=1
  elif command -v lsof >/dev/null 2>&1; then
    lsof -i ":${port}" -sTCP:LISTEN >/dev/null 2>&1 && port_in_use=1
  fi
  
  if [ "$port_in_use" -eq 1 ]; then
    ns_warn "Port $port still in use after PID cleanup, attempting targeted cleanup..."
    
    # Use pkill with pattern matching for our specific server
    local server_pattern="${NS_WWW}/server.py"
    if command -v pkill >/dev/null 2>&1; then
      if pkill -f "$server_pattern" 2>/dev/null; then
        ns_log "Killed processes matching pattern: $server_pattern"
        any=1
        sleep 1
      fi
    fi
    
    # If lsof is available, use it to kill processes using the port
    if command -v lsof >/dev/null 2>&1 && command -v fuser >/dev/null 2>&1; then
      if fuser -k "${port}/tcp" 2>/dev/null; then
        ns_log "Used fuser to kill processes on port $port"
        any=1
        sleep 1
      fi
    fi
    
    # Final check if port is still in use
    if command -v netstat >/dev/null 2>&1; then
      if netstat -ln 2>/dev/null | grep -q ":${port}.*LISTEN"; then
        ns_err "Port $port is still in use after cleanup attempts"
        failed=1
      fi
    fi
  fi
  
  # Report results
  if [ "$failed" -eq 1 ]; then
    ns_err "Failed to completely stop web server"
    return 1
  elif [ "$any" -eq 1 ]; then
    ns_ok "Web server stopped"
    return 0
  else
    ns_log "Web server was not running"
    return 0
  fi
}

install_all(){
  ensure_dirs
  install_dependencies
  write_default_config
  generate_keys
  generate_self_signed_tls
  write_notify_py
  write_server_py
  write_dashboard
  ensure_auth_bootstrap
  setup_termux_service || true
  setup_systemd_user || true
  ns_ok "Install complete. Use: $0 --start"
}

start_all(){
  ensure_dirs; write_default_config; generate_keys; generate_self_signed_tls; write_notify_py; write_server_py; write_dashboard
  ensure_auth_bootstrap
  open_session
  start_monitors
  start_web
  ns_ok "NovaShield is running. Open the dashboard in your browser."
}

stop_all(){
  stop_monitors || true
  stop_web || true
  close_session
}

restart_monitors(){ stop_monitors || true; start_monitors; }

add_user(){
  local user pass salt
  read -rp "New username: " user
  read -rsp "Password (won't echo): " pass; echo
  salt=$(awk -F': ' '/auth_salt:/ {print $2}' "$NS_CONF" | tr -d ' "')
  [ -z "$salt" ] && salt="change-this-salt"
  local sha; sha=$(printf '%s' "${salt}:${pass}" | sha256sum | awk '{print $1}')
  if [ ! -f "$NS_SESS_DB" ]; then echo '{}' >"$NS_SESS_DB"; fi
  python3 - "$NS_SESS_DB" "$user" "$sha" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{})
ud[u]=s
j['_userdb']=ud
open(p,'w').write(json.dumps(j))
print('User stored')
PY
  ns_ok "User '$user' added. Enable/confirm auth in config.yaml (security.auth_enabled: true)"
}

enable_2fa(){
  local user secret
  read -rp "Username to set 2FA: " user
  secret=$(python3 - <<'PY'
import os,base64; print(base64.b32encode(os.urandom(10)).decode().strip('='))
PY
)
  echo "TOTP secret (Base32): $secret"
  echo "Add to your authenticator app (issuer: NovaShield, account: $user)."
  python3 - "$NS_SESS_DB" "$user" "$secret" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try: j=json.load(open(p))
except: j={}
t=j.get('_2fa',{})
t[u]=s
j['_2fa']=t
open(p,'w').write(json.dumps(j))
print('2FA secret stored')
PY
  ns_ok "2FA set for '$user'. Set security.require_2fa: true to enforce."
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
  echo
  ns_warn "No web users found but auth_enabled is true. Creating the first user."
  add_user
  echo
  read -r -p "Enable 2FA for this user now? [y/N]: " yn
  case "$yn" in [Yy]*) enable_2fa ;; esac
}

reset_auth(){
  ns_log "Resetting auth state (sessions, lockouts, rate limits)..."
  rm -f "${NS_SESS_DB}" "${NS_BANS_DB}" "${NS_RL_DB}" 2>/dev/null || true
  echo '{}' > "${NS_SESS_DB}"
  echo '{}' > "${NS_BANS_DB}"
  echo '{}' > "${NS_RL_DB}"
  ns_ok "Auth state reset. Re-add at least one user with: $0 --add-user"
}

usage(){ cat <<USG
NovaShield Terminal ${NS_VERSION} — JARVIS Edition
A comprehensive security monitoring and management system for Android/Termux and Linux

Usage: $0 [OPTION]

Core Commands:
  --install              Install NovaShield and dependencies
  --start                Start all services (monitors + web dashboard)
  --stop                 Stop all running services
  --status               Show service status and information
  --restart-monitors     Restart all monitoring processes

Web Dashboard:
  --web-start            Start only the web dashboard server
  --web-stop             Stop the web dashboard server

Security & Backup:
  --backup               Create encrypted backup snapshot
  --version-snapshot     Create version snapshot (no encryption)
  --encrypt <path>       Encrypt file or directory
  --decrypt <file.enc>   Decrypt file (prompts for output path)

User Management:
  --add-user             Add a new web dashboard user
  --enable-2fa           Enable 2FA for a user
  --reset-auth           Reset all authentication state

Network Configuration:
  --disable-external-checks  Disable external network monitoring (for restricted environments)
  --enable-external-checks   Enable external network monitoring

Optional Features (opt-in, disabled by default for stable behavior):
  --enable-auto-restart      Enable automatic restart of crashed services
  --enable-security-hardening  Enable enhanced security features
  --enable-strict-sessions   Enable strict session validation

Interactive:
  --menu                 Show interactive menu
  --help, -h             Show this help message

Configuration:
  Copy novashield.conf.example to ~/.novashield/novashield.conf to customize
  optional features permanently. All features default to stable behavior.

Examples:
  $0 --install                    # First-time setup
  $0 --start                      # Start everything (stable defaults)
  $0 --enable-auto-restart        # Enable auto-restart for this session
  $0 --encrypt /important/data    # Encrypt directory
  $0 --backup                     # Create backup

The web dashboard will be available at http://127.0.0.1:8765 after starting.
For Android/Termux users: All features are optimized for mobile terminal use.
USG
}

status(){
  echo "Version : ${NS_VERSION}"
  echo "Home    : ${NS_HOME}"
  echo "Termux  : ${IS_TERMUX}"
  
  # Improved web server status detection
  local web_pid; web_pid=$(safe_read_pid "${NS_PID}/web.pid" 2>/dev/null)
  if [ "$web_pid" -gt 0 ]; then
    echo "Web PID : $web_pid"
  else
    # Check if a web server is running but not tracked
    local port; port=$(yaml_get "http" "port" "8765")
    if command -v netstat >/dev/null 2>&1 && netstat -ln 2>/dev/null | grep -q ":${port}.*LISTEN"; then
      echo "Web PID : ? (running but not tracked)"
    else
      echo "Web PID : 0"
    fi
  fi
  
  for p in cpu memory disk network integrity process userlogins services logs scheduler supervisor; do
    local pid; pid=$(safe_read_pid "${NS_PID}/${p}.pid" 2>/dev/null)
    echo "$p PID: ${pid:-0}"
  done
}

menu(){
  PS3=$'\nSelect: '
  select opt in \
    "Start All" "Stop All" "Restart Monitors" "Status" \
    "Backup" "Version Snapshot" "Encrypt File/Dir" "Decrypt File" \
    "Add Web User" "Enable 2FA for User" "Reset Auth State" "Test Notification" "Open Dashboard URL" "Quit"; do
    case $REPLY in
      1) start_all;;
      2) stop_all;;
      3) restart_monitors;;
      4) status;;
      5) backup_snapshot;;
      6) version_snapshot;;
      7) read -rp "Path to file/dir: " p; if [ -d "$p" ]; then enc_dir "$p" "$p.tar.gz.enc"; else enc_file "$p" "$p.enc"; fi;;
      8) read -rp "Path to .enc: " p; read -rp "Output path: " o; dec_file "$p" "$o";;
      9) add_user;;
      10) enable_2fa;;
      11) reset_auth;;
      12) python3 "${NS_BIN}/notify.py" "WARN" "NovaShield Test" "This is a test notification";;
      13) h=$(awk -F': ' '/host:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); prt=$(awk -F': ' '/port:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); [ -z "$h" ] && h="127.0.0.1"; [ -z "$prt" ] && prt=8765; echo "Open: http://${h}:${prt}";;
      14) break;;
      *) echo "?";;
    esac
  done
}

if [ $# -eq 0 ]; then usage; exit 0; fi

# Load configuration file for opt-in features
load_config_file

case "${1:-}" in
  --help|-h) usage; exit 0;;
  --install) install_all;;
  --start) start_all;;
  --stop) stop_all;;
  --restart-monitors) restart_monitors;;
  --status) status;;
  --backup) backup_snapshot;;
  --version-snapshot) version_snapshot;;
  --disable-external-checks) 
    ns_log "Disabling external network checks in configuration"
    # Create or update config to disable external network checks
    write_default_config
    
    # Update external_checks to false and ping_host to localhost
    sed -i.bak 's/external_checks: true/external_checks: false/g; s/ping_host: "1\.1\.1\.1"/ping_host: "127.0.0.1"/g' "$NS_CONF"
    
    ns_ok "External network checks disabled. Restart monitors to apply changes.";;
  --enable-external-checks)
    ns_log "Enabling external network checks in configuration"
    # Create or update config to enable external network checks  
    write_default_config
    
    # Update external_checks to true and ping_host to 1.1.1.1
    sed -i.bak 's/external_checks: false/external_checks: true/g; s/ping_host: "127\.0\.0\.1"/ping_host: "1.1.1.1"/g' "$NS_CONF"
    
    ns_ok "External network checks enabled. Restart monitors to apply changes.";;
  --encrypt)
    shift; p="${1:-}"; [ -z "$p" ] && die "--encrypt <path>"
    [ ! -e "$p" ] && die "Path not found: $p"
    if [ -d "$p" ]; then
      enc_dir "$p" "${p}.tar.gz.enc"
      ns_ok "Directory encrypted to: ${p}.tar.gz.enc"
    else
      enc_file "$p" "${p}.enc"
      ns_ok "File encrypted to: ${p}.enc"
    fi;;
  --decrypt)
    shift; p="${1:-}"; [ -z "$p" ] && die "--decrypt <file.enc>"
    # Auto-generate output filename if not provided interactively
    if [ -t 0 ]; then
      read -rp "Output path (default: ${p%.enc}): " o
      [ -z "$o" ] && o="${p%.enc}"
    else
      o="${p%.enc}"
    fi
    dec_file "$p" "$o"
    ns_ok "Decrypted to: $o";;
  --web-start) start_web;;
  --web-stop) stop_web;;
  --add-user) add_user;;
  --enable-2fa) enable_2fa;;
  --reset-auth) reset_auth;;
  --enable-auto-restart)
    ns_log "Enabling auto-restart feature"
    export NOVASHIELD_AUTO_RESTART=1
    ns_ok "Auto-restart enabled for this session. To make permanent, add NOVASHIELD_AUTO_RESTART=1 to ~/.novashield/novashield.conf";;
  --enable-security-hardening)
    ns_log "Enabling security hardening features"
    export NOVASHIELD_SECURITY_HARDENING=1
    ns_ok "Security hardening enabled for this session. To make permanent, add NOVASHIELD_SECURITY_HARDENING=1 to ~/.novashield/novashield.conf";;
  --enable-strict-sessions)
    ns_log "Enabling strict session validation"
    export NOVASHIELD_STRICT_SESSIONS=1
    ns_ok "Strict sessions enabled for this session. To make permanent, add NOVASHIELD_STRICT_SESSIONS=1 to ~/.novashield/novashield.conf";;
  --menu) menu;;
  *) usage; exit 1;;
esac
