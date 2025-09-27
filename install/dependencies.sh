#!/usr/bin/env bash
# NovaShield Installation Module: Dependencies
# This module handles system dependency installation and verification

install_dependencies(){
  ns_log "Checking dependencies..."
  local need=(python3 awk sed grep tar gzip df du ps top uname head tail cut tr sha256sum curl ping find xargs)
  local missing=()
  
  # Enhanced Termux setup - fully automated and universal
  if [ "$IS_TERMUX" -eq 1 ]; then
    ns_log "Termux detected - performing automated mobile setup..."
    
    # Automated package updates (non-interactive)
    ns_log "Updating Termux packages (automated)..."
    pkg update -y >/dev/null 2>&1 || true
    pkg upgrade -y >/dev/null 2>&1 || true
    
    # Essential Termux packages for better experience (automated installation)
    ns_log "Installing essential Termux packages (automated)..."
    local termux_packages=(
      "termux-tools"     # Essential Termux utilities
      "termux-api"       # API access
      "procps"           # Better ps, top, etc.
      "htop"             # Enhanced system monitor
      "nano"             # Text editor
      "vim"              # Advanced editor
      "git"              # Version control
      "man"              # Manual pages
      "which"            # Which command
      "openssh"          # SSH capabilities
      "curl"             # HTTP client
      "wget"             # Download utility
      "python"           # Python interpreter
      "openssl-tool"     # SSL/TLS tools
      "termux-services"  # Service management
    )
    
    for pkg in "${termux_packages[@]}"; do
      PKG_INSTALL "$pkg" >/dev/null 2>&1 || ns_warn "Failed to install $pkg (non-critical)"
    done
    
    # Automated storage access setup (non-interactive)
    ns_log "Setting up Termux storage access (automated)..."
    if [ ! -d "$HOME/storage" ]; then
      # Create storage directory structure manually if termux-setup-storage fails
      mkdir -p "$HOME/storage" 2>/dev/null || true
      # Set environment for automated storage setup
      export TERMUX_SETUP_STORAGE_NONINTERACTIVE=1
      termux-setup-storage >/dev/null 2>&1 || {
        ns_warn "Automated storage setup not available - creating basic structure"
        mkdir -p "$HOME/storage/shared" 2>/dev/null || true
        mkdir -p "$HOME/storage/downloads" 2>/dev/null || true
      }
    fi
    
    # Enhanced terminal capabilities (automated)
    ns_log "Setting up enhanced terminal environment..."
    {
      echo "# NovaShield Termux Environment Setup"
      echo "export TERM=xterm-256color"
      echo "export NOVASHIELD_TERMUX=1"
      echo "export PATH=\"\$HOME/.novashield/bin:\$PATH\""
      echo "alias ll='ls -la'"
      echo "alias ns='$HOME/.novashield/bin/novashield.sh'"
    } >> "$HOME/.bashrc" 2>/dev/null || true
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
  
  # Install optional security tools
  if [ "$IS_TERMUX" -eq 1 ]; then
    # Install OpenSSL
    if command -v pkg >/dev/null 2>&1; then
      PKG_INSTALL openssl-tool || ns_warn "OpenSSL installation failed - crypto features disabled"
    else
      PKG_INSTALL openssl || ns_warn "OpenSSL installation failed - crypto features disabled"
    fi
    
    # Additional Termux-specific tools
    PKG_INSTALL proot || true
    PKG_INSTALL termux-services || ns_warn "termux-services install failed (non-critical)"
  fi
  
  # Install common security tools
  PKG_INSTALL nmap || ns_warn "nmap install failed"
  PKG_INSTALL netcat || PKG_INSTALL nc || ns_warn "netcat install failed"
  PKG_INSTALL lsof || ns_warn "lsof install failed"
  
  # Final verification
  local critical_missing=()
  for c in python3 awk sed grep; do
    if ! command -v "$c" >/dev/null 2>&1; then
      critical_missing+=("$c")
    fi
  done
  
  if [ ${#critical_missing[@]} -gt 0 ]; then
    for c in "${critical_missing[@]}"; do
      ns_err "Critical dependency '$c' is missing and could not be installed"
      return 1
    done
  fi
  
  echo "✓ Dependencies check completed"
}

# Export the function so it can be used when sourced
export -f install_dependencies 2>/dev/null || true