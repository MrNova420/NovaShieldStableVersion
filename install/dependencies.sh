#!/usr/bin/env bash
# NovaShield Installation Module: Dependencies
# This module handles system dependency installation and verification

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