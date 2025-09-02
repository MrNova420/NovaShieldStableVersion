# NovaShield — Enhanced JARVIS Edition (3.1.0)
*Production-Ready Security & System Management Platform*

![Enhanced AI-Powered Security Dashboard](https://private-user-images.githubusercontent.com/155208275/484666342-c251af56-56f1-4643-88d9-67d35bdc391e.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTY4MzAzMTEsIm5iZiI6MTc1NjgzMDAxMSwicGF0aCI6Ii8xNTUyMDgyNzUvNDg0NjY2MzQyLWMyNTFhZjU2LTU2ZjEtNDY0My04OGQ5LTY3ZDM1YmRjMzkxZS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwOTAyJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDkwMlQxNjIwMTFaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0zMzRjODhmMTlkM2EyZTE0M2M2NWJiNDFkMWI1MjdjYzdjNTU0ZGRlYTllMzU3N2NhODUyMWRhZWE5ZjQ0NDA0JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.7Mv5EhzzY64lFlWmcZfsUqEvVIYaWxGXXp8pkvltL1U)

![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)

**NovaShield** is a comprehensive, production-ready security and system management platform that transforms a single self-contained script into a powerful web-based dashboard. Designed specifically for Android/Termux and Linux environments, it provides enterprise-grade monitoring, advanced AI assistance, and complete system management capabilities with zero external dependencies.

## ✨ What's New in 3.1.0 - Complete Enhancement Overhaul

### 🚀 **Revolutionary Jarvis AI - Tool Execution Engine**
- **Execute Commands via Chat**: Say "run nmap localhost", "security scan", or "analyze performance" and Jarvis executes tools directly
- **Encrypted Per-User Memory**: AES-256-CBC encrypted conversation history and preferences for each user
- **Browser Text-to-Speech**: Web Speech API integration with voice selection and `jarvis.voice_enabled` config
- **Advanced System Integration**: Real-time access to system status, alerts, logs, and comprehensive system tools

### 🛡️ **Security Monitoring Revolution**
- **Fixed "Unidentified" Alerts**: Security panel now shows detailed information with real IP addresses, timestamps, and user agents
- **Clickable Expandable Logs**: All security events are clickable and expand to show full details including authentication data
- **Real-time Dashboard Access Logging**: Every website access logged with comprehensive security information
- **Enhanced Audit Trail**: Complete system operation logging with detailed event tracking

### 🖥️ **Terminal System Restoration**
- **Black Screen Issue FIXED**: Complete rewrite of terminal connection logic with proper shell resolution
- **Mobile Keyboard Support**: Auto-focus hidden input field for mobile keyboard activation on Termux/Android
- **Enhanced Shell Resolution**: Intelligent shell detection preferring Termux bash → /bin/bash → /bin/zsh → /bin/sh
- **Fullscreen Mode**: Toggle button with ESC key exit and proper focus management
- **Real Terminal Linking**: Direct connection to user's actual terminal environment

### 🎨 **User Interface & Experience Overhaul**
- **420 Theme Toggle**: Marijuana-themed color scheme with purple/green/blue styling (🌿 button in header)
- **Bright Chat Colors**: User messages in bright purple (#e9b3ff), Jarvis messages in bright green (#7fff00)
- **Enhanced Tools Panel**: Manual command execution interface with safety checks and command suggestions
- **Fixed Header Buttons**: All dashboard action buttons (backup, snapshot, restart monitors) now functional
- **Status Panel Repair**: Monitor control toggles working with proper CSRF validation and error handling

### 📱 **Enhanced Termux Integration**
- **Comprehensive Auto-Setup**: Automatic installation of essential packages (htop, nano, vim, git, openssh, nmap, etc.)
- **Storage Access Configuration**: Automated `termux-setup-storage` setup for external storage access
- **Enhanced Terminal Environment**: 256-color support and optimized terminal configuration
- **Security Tools Installation**: Automatic setup of nmap, netcat, wget, zip, lsof, tree, and security utilities

## 🚀 Revolutionary Features

### 🤖 **JARVIS AI Assistant — Advanced Intelligence**
- **Tool Execution from Chat**: Direct command execution via natural language ("run nmap localhost", "security audit")
- **Per-User Memory System**: Encrypted conversation history and preferences with AES-256-CBC encryption
- **Contextual Intelligence**: Provides personalized responses based on user behavior and real system state
- **Voice Input & Output**: Browser-based text-to-speech with configurable voice settings
- **Advanced Personality**: Human-like responses with proactive recommendations and system insights
- **Learning Capabilities**: Auto-optimization based on user interaction patterns and system analysis

**Example Interactions:**
```
User: "run nmap localhost"
Jarvis: "Running network scan on localhost... 
Found 3 open ports: 22 (SSH), 80 (HTTP), 8080 (NovaShield Dashboard)
Port 22 shows OpenSSH 8.2, consider updating for security."

User: "security scan" 
Jarvis: "Comprehensive security audit completed! Found 2 potential issues:
1. World-writable files in /tmp (moderate risk)  
2. 3 failed login attempts in last hour
Recommendation: Run 'sudo find / -perm -002 -type f' to review permissions."

User: "analyze performance"
Jarvis: "System performance analysis:
- CPU usage: 15% (normal)
- Memory: 2.1GB/4GB (53% utilized)  
- Disk I/O: Low activity
- Network: 45 Mbps available
Performance is optimal. No bottlenecks detected."
```

### 🛠️ **Comprehensive Tools Arsenal — 30+ System Utilities**
- **Security Tools**: nmap, iptables, vulnerability scanner, security audit, port analysis
- **Network Diagnostics**: ping, curl, wget, dig, traceroute, netstat, ss, bandwidth testing
- **System Monitoring**: htop, lsof, df, ps, top, iotop, iostat, vmstat, sar, uptime analysis
- **Forensics Kit**: strings, file, xxd, md5sum, sha256sum, log analysis, file integrity
- **Custom Scripts**: System info generator, security scanner, log analyzer, performance profiler

**Features Include:**
- **Auto-Detection**: Automatically detects installed tools with visual status indicators
- **One-Click Installation**: Supports apt, yum, dnf, pacman, and pkg package managers
- **Interactive Execution**: Real-time output capture with result management and export capabilities
- **Manual Command Interface**: Safe execution of custom commands with security validation
- **Command Suggestions**: Quick-access buttons for common operations with keyboard shortcuts

### 🔍 **Advanced System Analysis**
- **Security Scanning**: Multi-layer vulnerability assessment with automated threat detection
- **System Reporting**: Comprehensive hardware/software inventory with performance analysis
- **Log Analysis**: Pattern recognition with anomaly detection and behavioral analysis
- **Performance Monitoring**: Real-time bottleneck identification with optimization recommendations
- **Threat Assessment**: Risk scoring with automated security recommendations and remediation steps

### 🧠 **Enterprise Memory Management**
- **Encrypted Storage**: AES-256-CBC encryption for all user data and conversation history
- **Conversation History**: Up to 50 interactions per user with searchable archive and context preservation
- **Preference Tracking**: Themes, command usage patterns, interaction history, and personalized settings
- **Pattern Recognition**: Identifies technical vs conversational users with adaptive responses
- **Smart Suggestions**: Based on usage history, current system state, and learned user preferences
- **Export/Import**: Full conversation data backup/restore with encrypted transfer capabilities

### 🛡️ **Enhanced Security Monitoring**
- **Real-time System Monitoring**: CPU, memory, disk, network monitoring with AI-powered analysis and alerting
- **Process & Service Monitoring**: Track running processes and system services with threat detection and anomaly identification
- **User Activity Monitoring**: Monitor user logins, authentication events with behavioral analysis and suspicious activity detection
- **Log Analysis**: Automated log monitoring with AI-powered pattern recognition, alert generation, and forensic capabilities
- **Scheduler Monitoring**: Task and cron job monitoring with anomaly detection and unauthorized change alerts
- **Security Events**: Comprehensive tracking of login attempts, CSRF failures, rate limiting violations, and security incidents

### 🌐 **Advanced Web Dashboard**
- **JARVIS-themed Interface**: Futuristic, mobile-optimized web dashboard with customizable neon themes and 420 mode
- **AI Chat Interface**: Full-featured AI assistant with voice input, contextual responses, and command execution
- **Tools Management Panel**: Interactive tools execution with real-time output, result management, and manual command interface
- **Security Dashboard**: Real-time threat monitoring with clickable expandable alerts and detailed forensic information
- **Terminal Integration**: Full terminal access with mobile keyboard support, fullscreen mode, and proper shell linking
- **Status Management**: Live system monitoring with interactive toggles, CSRF protection, and comprehensive error handling

## 🚀 Quick Start

### Installation Options

#### Option 1: Full Auto-Setup (Recommended for Termux)
```bash
# Download and auto-install with enhanced Termux setup
curl -sSL https://raw.githubusercontent.com/MrNova420/NovaShieldStableVersion/main/novashield.sh -o novashield.sh
chmod +x novashield.sh
./novashield.sh --install
```

#### Option 2: Manual Setup
```bash
# Download script
wget https://raw.githubusercontent.com/MrNova420/NovaShieldStableVersion/main/novashield.sh
chmod +x novashield.sh

# Start NovaShield (auto-generates all components)
./novashield.sh --start
```

#### Option 3: Git Clone
```bash
# Clone repository
git clone https://github.com/MrNova420/NovaShieldStableVersion.git
cd NovaShieldStableVersion

# Install and start
./novashield.sh --install
./novashield.sh --start
```

### Enhanced Termux Auto-Setup

The `--install` command now provides comprehensive Termux environment setup:

```bash
./novashield.sh --install
```

**Auto-installs and configures:**
- **Core packages**: termux-tools, termux-api, procps, htop, nano, vim, git, openssh
- **Security tools**: nmap, netcat, wget, zip, lsof, tree, openssl-tool
- **Storage access**: Automated `termux-setup-storage` setup
- **Terminal optimization**: 256-color support and enhanced terminal configuration
- **Service management**: termux-services for auto-start capabilities
- **Development tools**: Python3, Node.js, build essentials

### Starting NovaShield

```bash
# Start with default settings
./novashield.sh --start

# Start with custom port
./novashield.sh --start --port 9090

# Start with specific interface
./novashield.sh --start --interface 0.0.0.0

# Start with debug logging
./novashield.sh --start --debug
```

### Accessing the Dashboard

Once started, access NovaShield at:
- **Local**: http://localhost:8080
- **Network**: http://[your-ip]:8080
- **Termux**: Use the auto-detected IP address shown on startup

## 💡 Usage Examples

### Jarvis AI Commands

**Security Operations:**
```
"security scan" - Comprehensive security audit
"run nmap localhost" - Network port scan
"check failed logins" - Authentication analysis
"analyze logs" - Log pattern analysis
"vulnerability assessment" - Security vulnerability scan
```

**System Management:**
```
"system status" - Real-time system overview
"performance analysis" - CPU, memory, disk analysis
"process monitor" - Running process analysis
"disk usage" - Storage analysis with recommendations
"network diagnostics" - Network connectivity testing
```

**Tools Execution:**
```
"run htop" - Interactive process monitor
"run netstat -tuln" - Network connection analysis  
"run df -h" - Disk space analysis
"run ps aux" - Process listing
"run lsof -i" - Open file and network analysis
```

### Enhanced Features

**Security Monitoring:**
- Click any security alert to expand and see full details (IP, timestamp, user agent, authentication data)
- Real-time dashboard access logging with comprehensive forensic information
- Enhanced audit trail with detailed event tracking and security analysis

**Terminal Access:**
- Click Terminal tab for immediate shell access with mobile keyboard support
- Fullscreen mode with ESC key exit and proper focus management
- Automatic shell resolution (Termux bash → /bin/bash → /bin/zsh → /bin/sh)

**Tools Panel:**
- Execute commands manually with safety checks and timeout protection
- Use one-click tool buttons for common operations (nmap, htop, netstat, etc.)
- Save tool output to files with proper formatting and result management

**420 Mode:**
- Click 🌿 button in header to toggle purple/green marijuana-themed color scheme
- Persistent theme state saved in localStorage
- Enhanced visual experience with bright chat colors

## 🔧 Advanced Configuration

### Jarvis AI Settings

**Enable Text-to-Speech:**
```bash
# Edit the generated config file
nano ~/.novashield/config.json

# Set voice enabled
{
  "jarvis": {
    "voice_enabled": true,
    "voice_language": "en-US",
    "voice_rate": 1.0,
    "voice_pitch": 1.0
  }
}
```

**Memory Management:**
- Per-user encrypted memory files stored in `~/.novashield/ctrl/memory_[username].enc`
- Automatic AES-256-CBC encryption using generated keys
- Conversation history and preferences preserved across sessions

### Security Configuration

**CSRF Protection:**
```bash
# Tokens are automatically generated and validated
# View current security settings:
./novashield.sh --status
```

**Enhanced Logging:**
```bash
# Enable debug logging
./novashield.sh --start --debug

# View security logs
tail -f ~/.novashield/logs/security.log
```

### Terminal Customization

**Shell Preferences:**
The system automatically detects and prefers:
1. Termux bash (`/data/data/com.termux/files/usr/bin/bash`)
2. System bash (`/bin/bash`)
3. Z shell (`/bin/zsh`)
4. POSIX shell (`/bin/sh`)

**Mobile Optimization:**
- Auto-focus hidden input field for mobile keyboard activation
- Touch-optimized interface with proper target sizing
- Swipe gestures and mobile-specific keyboard handling

## 🔐 Security & Privacy

### Data Protection
- **Encrypted Storage**: All user data encrypted with AES-256-CBC
- **Secure Memory**: Per-user encrypted conversation history and preferences
- **CSRF Protection**: Enhanced token validation across all interactive elements
- **Input Validation**: Command execution safety checks preventing dangerous operations
- **Access Logging**: Comprehensive audit trail with detailed event tracking

### Network Security
- **Local-First**: Designed for local network operation
- **No External Dependencies**: Uses only Python stdlib and system tools
- **Secure Communication**: All web traffic over secure connections when available
- **Rate Limiting**: Protection against abuse and automated attacks

### System Integrity
- **Self-Contained**: Single script with no external file dependencies
- **Graceful Degradation**: Features degrade gracefully when dependencies unavailable
- **Zero Breaking Changes**: Full backward compatibility maintained
- **Safe Execution**: Command validation and timeout protection

## 🛠️ Troubleshooting

### Common Issues

**Terminal Black Screen:**
```bash
# Fixed in 3.1.0 - if still experiencing issues:
./novashield.sh --debug --start
# Check browser console for WebSocket connection errors
```

**Mobile Keyboard Not Appearing:**
```bash
# Ensure you're using the Terminal tab (not Tools)
# Tap the terminal area to activate the hidden input field
# For Termux, ensure termux-api is installed
```

**Jarvis Not Responding:**
```bash
# Check Jarvis AI status
# Verify Python3 and required modules are available
# Check browser console for JavaScript errors
```

**Tools Not Working:**
```bash
# Install missing tools:
./novashield.sh --install

# For manual installation:
pkg install nmap htop netstat lsof  # Termux
sudo apt install nmap htop net-tools lsof  # Ubuntu/Debian
```

### Debug Mode

```bash
# Start with comprehensive debugging
./novashield.sh --start --debug

# View real-time logs
tail -f ~/.novashield/logs/debug.log
tail -f ~/.novashield/logs/security.log
tail -f ~/.novashield/logs/access.log
```

### Reset Configuration

```bash
# Reset to default settings (preserves user data)
./novashield.sh --reset

# Complete clean reset (removes all data)
rm -rf ~/.novashield
./novashield.sh --install
```

## 📱 Mobile/Termux Optimization

### Termux-Specific Features
- **Auto Package Management**: Automatic installation and updates of essential tools
- **Storage Integration**: Seamless access to device storage through termux-setup-storage
- **Service Management**: Integration with termux-services for auto-start capabilities
- **Performance Optimization**: Optimized for limited resources and battery efficiency

### Mobile Interface
- **Touch-Optimized**: Large touch targets and swipe-friendly interface
- **Responsive Design**: Adapts to various screen sizes and orientations
- **Keyboard Handling**: Intelligent mobile keyboard management for terminal usage
- **Offline Capability**: Full functionality without internet connectivity

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/MrNova420/NovaShieldStableVersion.git
cd NovaShieldStableVersion

# Test changes
./novashield.sh --test

# Run in development mode
./novashield.sh --start --debug
```

### Feature Requests
- Open issues on GitHub with detailed feature descriptions
- Include use cases and expected behavior
- Provide environment details (Termux/Linux, device info)

### Bug Reports
- Use the debug mode to capture detailed logs
- Include steps to reproduce the issue
- Specify your environment and NovaShield version

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **Termux Community**: For the excellent Android terminal emulator
- **JARVIS AI Inspiration**: From the Iron Man universe
- **Security Community**: For continuous feedback and improvement suggestions
- **Open Source Contributors**: For tools and libraries that make this possible

---

**NovaShield 3.1.0** - Transforming security monitoring from basic dashboards to comprehensive, AI-powered system management platforms. 🚀

*Built with ❤️ for the cybersecurity and system administration community.*