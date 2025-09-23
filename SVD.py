#!/data/data/com.termux/files/usr/bin/bash

# Ultimate Security Dashboard Setup Script for Termux (Updated 2025)
# Sets up a secure, private, encrypted, anonymous dashboard on Termux (Android).
# Features: Flask dashboard with authentication, Tor hidden service, OpenVPN, Proxychains, SSH, system monitoring.
# Improvements: Error handling, logging, dynamic paths, Flask auth, Ngrok option, Termux version check.
# WARNING: For personal/ethical use only. VPN server may require root (see https://www.reddit.com/r/termux/comments/1g1ug0x/vpn_server_on_termux/).
# Ensure Termux is from F-Droid/GitHub (not Play Store) for updates.

set -e  # Exit on error

# Define variables
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
LOGFILE="$HOME/security_dashboard.log"
NGROK_INSTALL="no"  # Set to "yes" to install Ngrok for public exposure (requires authtoken)

# Logging function
log() {
    echo "[$(date)] $1" | tee -a "$LOGFILE"
}

log "=== Starting Ultimate Security Dashboard Setup (Updated 2025) ==="
log "This will take 10-30 minutes."

# Check storage permission
if ! termux-setup-storage >/dev/null 2>&1; then
    log "Error: Storage permission required. Run 'termux-setup-storage' manually."
    exit 1
fi

# Check Termux version (approximate check via package manager)
log "Step 0: Checking Termux installation..."
if pkg_install_output=$(pkg_install termux-tools 2>&1 | grep -i "termux"); then
    log "Warning: Ensure Termux is from F-Droid/GitHub (v0.118.0+ recommended)."
fi

# Step 1: Update Termux and install basic packages
log "Step 1: Updating Termux and installing basics..."
pkg update -y && pkg upgrade -y | tee -a "$LOGFILE"
pkg install -y git python nodejs nano vim openssl tor nginx openvpn proxychains-ng openssh wget curl zip unzip htop | tee -a "$LOGFILE"
pip install flask psutil cryptography flask_httpauth --no-cache-dir | tee -a "$LOGFILE"

# Step 2: Optional Ngrok installation
if [ "$NGROK_INSTALL" = "yes" ]; then
    log "Step 2: Installing Ngrok..."
    if wget https://bin.equinox.io/c/bNyj1mQVY4/ngrok-v3-stable-linux-arm64.tgz; then
        tar -xvf ngrok-v3-stable-linux-arm64.tgz
        mv ngrok "$PREFIX/bin/"
        rm ngrok-v3-stable-linux-arm64.tgz
        log "Ngrok installed. Set authtoken: ./ngrok authtoken <token>"
    else
        log "Warning: Ngrok download failed. Skipping."
    fi
else
    log "Step 2: Skipping Ngrok installation."
fi

# Step 3: Install termux4all (if repo exists)
log "Step 3: Installing termux4all for additional tools..."
if git clone https://github.com/ShanSuharban/termux4all.git; then
    cd termux4all
    chmod +x *
    bash t4all.sh  # Assumes 'all' for automation; user can interact if run manually
    cd ..
    rm -rf termux4all
else
    log "Warning: termux4all clone failed. Skipping. Consider proot-distro or Kali Nethunter for security tools."
fi

# Step 4: Install Termux-Security for VPN/static generator
log "Step 4: Installing Termux-Security..."
if git clone https://github.com/CPScript/Termux-Security.git Termux-Sec; then
    cd Termux-Sec
    bash install.sh
    cd ..
    rm -rf Termux-Sec
else
    log "Warning: Termux-Security clone failed. Skipping VPN/static gen extras."
fi

# Step 5: Generate self-signed SSL certificate
log "Step 5: Generating self-signed SSL cert..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost" | tee -a "$LOGFILE"

# Step 6: Set up Flask Dashboard with authentication and system stats
log "Step 6: Creating secure dashboard..."
cat > dashboard.py << 'EOF'
from flask import Flask, render_template_string, request, redirect
from flask_httpauth import HTTPBasicAuth
import os
import subprocess
import psutil
from cryptography.fernet import Fernet
import threading
import time

app = Flask(__name__)
auth = HTTPBasicAuth()

# Authentication (change password in production!)
users = {"admin": "securepassword123"}  # Use env vars or secure storage for production

@auth.verify_password
def verify_password(username, password):
    return username in users and users[username] == password

# Encryption key for sensitive data
key = Fernet.generate_key()
cipher = Fernet(key)
ENCRYPTED_KEY = cipher.encrypt(key).decode()

# Global vars for service status
vpn_process = None
tor_process = None
ssh_process = None
proxy_active = False
prefix = os.environ.get('PREFIX', '/data/data/com.termux/files/usr')

def get_system_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return cpu_percent, memory.percent, disk.percent

def start_vpn():
    global vpn_process
    if vpn_process is None or vpn_process.poll() is not None:
        if os.path.exists('client.ovpn'):
            vpn_process = subprocess.Popen(['openvpn', '--config', 'client.ovpn', '--daemon'])
            time.sleep(5)
            return vpn_process.poll() is None
        return False
    return True

def stop_vpn():
    global vpn_process
    if vpn_process and vpn_process.poll() is None:
        vpn_process.terminate()
        vpn_process.wait()
    return True

def start_tor():
    global tor_process
    if tor_process is None or tor_process.poll() is not None:
        tor_process = subprocess.Popen(['tor'])
        time.sleep(10)
        return tor_process.poll() is None
    return True

def stop_tor():
    global tor_process
    if tor_process and tor_process.poll() is None:
        tor_process.terminate()
        tor_process.wait()
    return True

def start_ssh():
    global ssh_process
    if ssh_process is None or ssh_process.poll() is not None:
        ssh_process = subprocess.Popen(['sshd', '-D'])
        return ssh_process.poll() is None
    return True

def stop_ssh():
    global ssh_process
    if ssh_process and ssh_process.poll() is None:
        ssh_process.terminate()
        ssh_process.wait()
    return True

def toggle_proxy():
    global proxy_active
    proxy_active = not proxy_active
    os.environ['USE_PROXY'] = str(proxy_active)
    return proxy_active

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def home():
    cpu, mem, disk = get_system_info()
    vpn_status = "Active" if vpn_process and vpn_process.poll() is None else "Inactive"
    tor_status = "Active" if tor_process and tor_process.poll() is None else "Inactive"
    ssh_status = "Active" if ssh_process and ssh_process.poll() is None else "Inactive"
    proxy_status = "Active" if proxy_active else "Inactive"

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ultimate Security Dashboard</title>
        <style>
            body { font-family: Arial; background: #1a1a1a; color: #fff; padding: 20px; }
            button { padding: 10px; margin: 5px; background: #36a2eb; border: none; color: white; cursor: pointer; }
            button:hover { background: #2a80b9; }
            pre { background: #333; padding: 10px; }
            h1, h2 { color: #ffce56; }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <h1>🔒 Ultimate Security Dashboard</h1>
        <h2>System Stats</h2>
        <canvas id="statsChart" width="400" height="200"></canvas>
        <p>CPU: {{cpu}}% | Memory: {{mem}}% | Disk: {{disk}}%</p>

        <h2>VPN (OpenVPN)</h2>
        <p>Status: {{vpn}}</p>
        <form method="post" action="/vpn_start"><button>Start VPN</button></form>
        <form method="post" action="/vpn_stop"><button>Stop VPN</button></form>

        <h2>Tor (Anonymous Hosting)</h2>
        <p>Status: {{tor}}</p>
        <form method="post" action="/tor_start"><button>Start Tor</button></form>
        <form method="post" action="/tor_stop"><button>Stop Tor</button></form>
        <p>Onion Address: <span id="onion">Check /var/lib/tor/my_service/hostname</span></p>

        <h2>Secure SSH Server</h2>
        <p>Status: {{ssh}} (Port 8022)</p>
        <form method="post" action="/ssh_start"><button>Start SSH</button></form>
        <form method="post" action="/ssh_stop"><button>Stop SSH</button></form>

        <h2>Proxy (Proxychains)</h2>
        <p>Status: {{proxy}}</p>
        <form method="post" action="/toggle_proxy"><button>Toggle Proxy</button></form>

        <h2>Automation</h2>
        <p>Run Nmap scan: <form method="post" action="/run_nmap">
            <input type="text" name="target" placeholder="Target IP (e.g., 192.168.1.1)">
            <button>Scan</button></form>
        </p>
        <p>Static Generator: <form method="post" action="/static_gen"><button>Generate</button></form></p>

        <h2>Encrypted Configs</h2>
        <p>Key: {{key[:20]}}...</p>

        <script>
            fetch('/onion').then(r => r.text()).then(t => document.getElementById('onion').innerText = t);
            fetch('/stats_data').then(r => r.json()).then(data => {
                const ctx = document.getElementById('statsChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['CPU', 'Memory', 'Disk'],
                        datasets: [{
                            label: 'System Usage (%)',
                            data: data.data,
                            backgroundColor: ['#ff6384', '#36a2eb', '#ffce56'],
                            borderColor: ['#cc4b37', '#2a80b9', '#d4a017'],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        scales: {
                            y: { beginAtZero: true, max: 100, title: { display: true, text: 'Usage (%)' } },
                            x: { title: { display: true, text: 'Resource' } }
                        },
                        plugins: {
                            legend: { display: true },
                            title: { display: true, text: 'System Resource Usage' }
                        }
                    }
                });
            });
        </script>
    </body>
    </html>
    '''
    return render_template_string(html, cpu=cpu, mem=mem, disk=disk, vpn=vpn_status, tor=tor_status, ssh=ssh_status, proxy=proxy_status, key=ENCRYPTED_KEY)

@app.route('/stats_data')
def stats_data():
    cpu, mem, disk = get_system_info()
    return {"data": [cpu, mem, disk]}

@app.route('/vpn_start', methods=['POST'])
@auth.login_required
def vpn_start():
    success = start_vpn()
    return redirect('/')

@app.route('/vpn_stop', methods=['POST'])
@auth.login_required
def vpn_stop():
    stop_vpn()
    return redirect('/')

@app.route('/tor_start', methods=['POST'])
@auth.login_required
def tor_start():
    start_tor()
    return redirect('/')

@app.route('/tor_stop', methods=['POST'])
@auth.login_required
def tor_stop():
    stop_tor()
    return redirect('/')

@app.route('/ssh_start', methods=['POST'])
@auth.login_required
def ssh_start():
    start_ssh()
    return redirect('/')

@app.route('/ssh_stop', methods=['POST'])
@auth.login_required
def ssh_stop():
    stop_ssh()
    return redirect('/')

@app.route('/toggle_proxy', methods=['POST'])
@auth.login_required
def toggle_proxy_route():
    toggle_proxy()
    return redirect('/')

@app.route('/run_nmap', methods=['POST'])
@auth.login_required
def run_nmap():
    target = request.form['target']
    if not target:
        return "<pre>Error: No target specified</pre><a href='/'>Back</a>"
    result = subprocess.run(['proxychains', 'nmap', '-sV', target], capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre><a href='/'>Back</a>"

@app.route('/static_gen', methods=['POST'])
@auth.login_required
def static_gen():
    try:
        result = subprocess.run(['static_gen'], capture_output=True, text=True)
        return f"<pre>Generated: {result.stdout}</pre><a href='/'>Back</a>"
    except FileNotFoundError:
        return "<pre>Error: static_gen not found</pre><a href='/'>Back</a>"

@app.route('/onion')
@auth.login_required
def get_onion():
    try:
        with open(f'{prefix}/var/lib/tor/my_service/hostname', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return "Tor hidden service not initialized"

if __name__ == "__main__":
    threading.Thread(target=start_ssh, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'), debug=False)
EOF

# Step 7: Configure Tor hidden service
log "Step 7: Configuring Tor hidden service..."
mkdir -p "$PREFIX/var/lib/tor/my_service"
cat >> "$PREFIX/etc/tor/torrc" << EOF
HiddenServiceDir $PREFIX/var/lib/tor/my_service/
HiddenServicePort 80 127.0.0.1:5000
EOF

# Step 8: Set up sample OpenVPN config
log "Step 8: Setting up sample OpenVPN config..."
if [ ! -f "client.ovpn" ]; then
    cat > client.ovpn << EOF
client
dev tun
proto udp
remote vpn.example.com 1194  # Replace with your VPN server
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
EOF
    log "Sample client.ovpn created. Replace vpn.example.com and certs for production."
else
    log "client.ovpn already exists. Skipping creation."
fi

# Step 9: Configure Proxychains
log "Step 9: Configuring Proxychains..."
cat > "$PREFIX/etc/proxychains.conf" << EOF
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050  # Tor SOCKS
# Add fallback proxies if needed, e.g.:
# http 1.2.3.4 8080
EOF

# Step 10: Start services
start_service() {
    local cmd=$1 name=$2
    if pgrep -x "$name" >/dev/null; then
        log "$name already running."
    else
        $cmd &>/dev/null &
        sleep 5
        if pgrep -x "$name" >/dev/null; then
            log "$name started."
        else
            log "Error: Failed to start $name."
            exit 1
        fi
    fi
}

log "Step 10: Starting services..."
start_service "tor" "tor"
if [ -f "$PREFIX/var/lib/tor/my_service/hostname" ]; then
    onion_address=$(cat "$PREFIX/var/lib/tor/my_service/hostname")
    log "Tor Onion Address: $onion_address"
else
    log "Error: Tor hidden service failed to initialize."
    exit 1
fi
start_service "sshd" "sshd"
start_service "nginx -c $PREFIX/etc/nginx/nginx.conf" "nginx"

# Step 11: Set up cron for service monitoring
log "Step 11: Setting up cron for service monitoring..."
echo "*/5 * * * * pgrep tor >/dev/null || tor &" | crontab -
log "Cron job added to restart Tor every 5 minutes if down."

# Step 12: Start dashboard
log "Starting dashboard... Access locally at https://127.0.0.1:5000"
python dashboard.py >> "$LOGFILE" 2>&1 &

# Final output
log "=== Setup Complete! ==="
echo " - Local: https://127.0.0.1:5000 (Login: admin/securepassword123)"
echo " - Onion: $onion_address (use Tor Browser)"
echo " - SSH: ssh localhost -p 8022"
echo " - VPN: Edit client.ovpn and start via dashboard."
echo " - Proxy: Toggle in dashboard; use 'proxychains command' for apps."
echo " - Ngrok: Run './ngrok http 5000' if installed (requires authtoken)."
echo " - Logs: $LOGFILE"
echo " - Stop all: pkill -f 'tor|sshd|nginx|python|openvpn'"
echo "For automation, edit crontab: crontab -e"
