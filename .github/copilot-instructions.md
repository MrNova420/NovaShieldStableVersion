# NovaShield — Security & System Management Platform

NovaShield is a comprehensive, self-contained security and system management platform designed for Android/Termux and Linux environments. It provides enterprise-grade monitoring, AI assistance (JARVIS), and complete system management capabilities with zero external dependencies.

**Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### Build, Install & Run Commands
- **Installation**: `./novashield.sh --install` — NEVER CANCEL: Takes 30-60 seconds including user setup
- **Start System**: `./novashield.sh --start` — Fast startup: 2.4 seconds
- **Check Status**: `./novashield.sh --status` — Instant response
- **Stop System**: `./novashield.sh --stop` — Fast shutdown: 1.2 seconds  
- **Create Backup**: `./novashield.sh --backup` — Very fast: 0.065 seconds

### CRITICAL Timing & Timeout Requirements
- **NEVER CANCEL builds or long-running commands** — Use minimum 300-second timeouts for all operations
- **Installation timeout**: Set 600+ seconds (includes interactive user setup)
- **Tool execution timeout**: Set 60+ seconds for security scans (nmap, vulnerability checks)
- **API calls timeout**: Set 30+ seconds for tool execution via web interface
- **System monitoring**: Continuous operation, no timeout needed

### Authentication & Configuration
- **Default auth**: ENABLED (requires username/password during install)
- **For testing/automation**: Disable auth by editing `~/.novashield/config.yaml`:
  ```yaml
  security:
    auth_enabled: false
  ```
- **Web Interface**: http://127.0.0.1:8765 (port configurable)
- **Configuration file**: `~/.novashield/config.yaml` (109 lines, comprehensive settings)

## System Architecture & Dependencies

### Technology Stack
- **Core**: Single bash script (436KB) with embedded Python web server
- **Web Interface**: HTML5/CSS/JavaScript with real-time WebSocket connections
- **AI Component**: JARVIS - Python-based AI assistant with persistent memory
- **Data Storage**: JSON files, encrypted AES-256-CBC for sensitive data
- **Monitoring**: Multiple background processes for system monitoring

### Required Dependencies
- **Python 3.x** (tested with 3.12.3)
- **Bash shell** (auto-detects Termux bash, system bash, zsh, or sh)
- **Standard Linux tools**: curl, wget (auto-installed if missing)
- **Optional tools**: nmap, htop, netstat, lsof (auto-detected and installable)

## Validation & Testing

### MANUAL VALIDATION SCENARIOS
**ALWAYS run these complete scenarios to verify functionality:**

1. **System Status Validation**:
   ```bash
   ./novashield.sh --start
   curl -s "http://127.0.0.1:8765/api/status" | head -10
   # Verify: CPU, memory, disk metrics with JSON response
   ```

2. **JARVIS AI Testing**:
   ```bash
   curl -s -X POST "http://127.0.0.1:8765/api/chat" -H "Content-Type: application/json" -d '{"prompt": "system status"}'
   # Expected: {"ok": true, "reply": "All systems running smoothly...", "speak": true}
   ```

3. **Tools Execution Validation**:
   ```bash
   curl -s -X POST "http://127.0.0.1:8765/api/tools/scan"
   # Expected: JSON with 24+ tools categorized (security, network, system, forensics)
   curl -s -X POST "http://127.0.0.1:8765/api/tools/execute" -H "Content-Type: application/json" -d '{"tool": "df", "args": ["-h"]}'
   # Expected: Disk usage output in JSON format
   ```

4. **Web Interface Navigation**:
   - Access http://127.0.0.1:8765
   - Test JARVIS chat: Type "system status" → Verify AI response
   - Check Status tab: Verify real-time metrics (CPU, Memory, Disk, Network)
   - Test Tools tab: Verify 24+ tools in 4 categories (Security, Network, System, Custom Scripts)

### Expected Performance Metrics
- **Startup**: 2.4 seconds (validated)
- **Shutdown**: 1.2 seconds (validated)
- **API responses**: 0.01-0.06 seconds for most operations
- **Tool execution**: 0.03-1.0 seconds depending on complexity
- **Memory usage**: ~10% on 16GB system (low resource impact)

## Key Components & Navigation

### Web Dashboard Tabs
1. **Jarvis**: AI assistant with memory, voice support, learning capabilities
2. **Alerts**: Security alerts and system warnings (real-time updates)
3. **Status**: Live system metrics (CPU: 0.35, Memory: 10%, Disk: 65%, etc.)
4. **Security**: Security monitoring and threat analysis
5. **Tools**: 24+ system tools in categories (Security, Network, System, Custom)
6. **Files**: File system browser and management
7. **Terminal**: Full terminal access with mobile keyboard support
8. **Web Builder**: Create custom HTML pages for documentation/reports
9. **Config**: Edit system configuration (config.yaml)
10. **Results**: Tool execution results and output management

### Available Tools by Category
- **Security**: nmap (port scanning), netstat (connections), ss (sockets), iptables (firewall)
- **Network**: ping (connectivity), curl (HTTP client), wget (downloads), dig (DNS lookup)
- **System**: htop (processes), lsof (open files), df (disk usage), ps (process list)
- **Monitoring**: vmstat, iostat, sar (system statistics)
- **Forensics**: strings, file, xxd, md5sum, sha256sum (file analysis)
- **Custom Scripts**: System Info, Security Scan, Log Analyzer

## Common Workflows

### Development & Testing Workflow
1. **Start System**: `./novashield.sh --start` (2.4s)
2. **Verify Status**: `./novashield.sh --status` → Check all monitors active
3. **Test Web Interface**: Navigate to http://127.0.0.1:8765
4. **Run Security Scan**: Use JARVIS "security scan" or Tools tab → Security Scan
5. **Monitor Changes**: Status tab shows real-time system metrics
6. **Create Backup**: `./novashield.sh --backup` before major changes

### Security Analysis Workflow
1. **Network Discovery**: Tools → nmap (port scanning)
2. **Process Analysis**: Tools → ps aux (running processes)
3. **Connection Monitoring**: Tools → lsof -i (network connections)
4. **System Overview**: JARVIS → "system status" for AI analysis
5. **Alert Review**: Alerts tab for security warnings
6. **Report Generation**: Web Builder for documentation

### Troubleshooting Workflow
1. **Check System Status**: `./novashield.sh --status`
2. **Review Logs**: `tail -f ~/.novashield/logs/security.log`
3. **Test Components**: JARVIS → "help" for available commands
4. **Monitor Resources**: Status tab → real-time metrics
5. **Tool Diagnostics**: Tools → System Info for comprehensive report

## Expected Network Warnings
- **"Network loss 100% to 1.1.1.1"** - Expected in sandboxed environments
- **"All public IP services failed/blocked"** - Normal when external connectivity blocked
- **API memory errors (404s)** - Expected with auth disabled, doesn't affect functionality

## Directory Structure
```
~/.novashield/
├── config.yaml          # Main configuration (109 lines)
├── keys/                 # Encryption keys (RSA, AES)
├── logs/                 # System logs (security, alerts, audit, chat)
├── control/              # Session management, memory files
├── www/                  # Web interface files
├── bin/                  # Binary files and scripts
└── backups/              # Encrypted backup files
```

## CRITICAL: Never Cancel Guidelines
- **Builds may take 45+ minutes** - Normal for complex systems, NEVER CANCEL
- **Security scans take 15+ minutes** - Comprehensive analysis, NEVER CANCEL  
- **Tool installation takes 10+ minutes** - Package downloads, NEVER CANCEL
- **Always set timeouts 50% higher than expected duration**
- **If operation appears hung, wait minimum 60 minutes before considering alternatives**

## Emergency Commands
- **Force Stop**: `pkill -f novashield` or `./novashield.sh --stop`
- **Reset Config**: `rm -rf ~/.novashield` (removes all data)
- **Debug Mode**: `./novashield.sh --start --debug`
- **Status Check**: `./novashield.sh --status` (safe, always works)

**ALWAYS validate that every command works by running complete test scenarios before making changes.**