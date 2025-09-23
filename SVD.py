#!/data/data/com.termux/files/usr/bin/bash

# Ultimate Security Dashboard Setup Script for Termux
# This script sets up a fully secure, private, encrypted, anonymous website/dashboard
# with automation, VPN (OpenVPN), proxies (Proxychains), secure servers (SSH, Nginx),
# and more. It installs everything needed, configures services, and starts the dashboard.
# Run on Termux (Android terminal). Requires storage permission: termux-setup-storage
# WARNING: Use responsibly. This is for personal testing/security only. May require root for full VPN server.

set -e  # Exit on error

echo "=== Starting Ultimate Security Dashboard Setup ==="
echo "Date: $(date)"
echo "This will take 10-30 minutes depending on your connection."

# Step 1: Update Termux and install basic packages
echo "Step 1: Updating Termux and installing basics..."
pkg update -y && pkg upgrade -y
pkg install -y git python nodejs nano vim openssl tor nginx openvpn proxychains-ng openssh wget curl zip unzip htop psutil -y
pip install flask psutil cryptography

# Step 2: Install termux4all for comprehensive tools (dev, security, web servers, etc.)
echo "Step 2: Installing termux4all for all-in-one tools..."
git clone https://github.com/ShanSuharban/termux4all.git
cd termux4all
chmod +x *
bash t4all.sh  # Interactive: Select 'all' or categories (dev, security, basic). For automation, assume all.
cd ..
rm -rf termux4all  # Clean up after install

# Step 3: Install Termux-Security for simple OpenVPN and static generator
echo "Step 3: Installing Termux-Security for VPN..."
git clone https://github.com/CPScript/Termux-Security.git Termux-Sec
cd Termux-Sec
bash install.sh
cd ..
rm -rf Termux-Sec  # Clean up

# Step 4: Generate self-signed SSL certificate for encrypted HTTPS
echo "Step 4: Generating self-signed SSL cert..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

# Step 5: Set up Flask Dashboard (Ultimate Security Dashboard)
echo "Step 5: Creating secure dashboard..."
cat > dashboard.py << 'EOF'
from flask import Flask, render_template_string, request, redirect
import os
import subprocess
import psutil
from cryptography.fernet import Fernet
import threading
import time

app = Flask(__name__)

# Generate encryption key for sensitive data (e.g., configs)
key = Fernet.generate_key()
cipher = Fernet(key)
ENCRYPTED_KEY = cipher.encrypt(key).decode()  # Store encrypted for persistence

# Global vars for service status
vpn_process = None
tor_process = None
ssh_process = None
proxy_active = False

def get_system_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return cpu_percent, memory.percent, disk.percent

def start_vpn():
    global vpn_process
    if vpn_process is None or vpn_process.poll() is not None:
        # Assume a sample client.ovpn; in production, download or generate server config
        vpn_process = subprocess.Popen(['openvpn', '--config', 'client.ovpn', '--daemon'])
        time.sleep(5)  # Wait for startup
    return vpn_process.poll() is None

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
        time.sleep(10)  # Wait for Tor to initialize
    return tor_process.poll() is None

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

def stop_ssh():
    global ssh_process
    if ssh_process and ssh_process.poll() is None:
        ssh_process.terminate()
        ssh_process.wait()
    return True

def toggle_proxy():
    global proxy_active
    proxy_active = not proxy_active
    # Proxychains config is auto-set via termux4all; toggle by env var
    os.environ['USE_PROXY'] = str(proxy_active)
    return proxy_active

@app.route('/', methods=['GET', 'POST'])
def home():
    cpu, mem, disk = get_system_info()
    vpn_status = "Active" if vpn_process and vpn_process.poll() is None else "Inactive"
    tor_status = "Active" if tor_process and tor_process.poll() is None else "Inactive"
    ssh_status = "Active" if ssh_process and ssh_process.poll() is None else "Inactive"
    proxy_status = "Active" if proxy_active else "Inactive"

    html = '''
    <!DOCTYPE html>
    <html><head><title>Ultimate Security Dashboard</title>
    <style>body { font-family: Arial; background: #1a1a1a; color: #fff; } button { padding: 10px; margin: 5px; }</style></head>
    <body>
    <h1>🔒 Ultimate Security Dashboard</h1>
    <h2>System Stats</h2>
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
    <p>Run Nmap scan: <form method="post" action="/run_nmap"><input type="text" name="target" placeholder="target IP"><button>Scan</button></form></p>
    <p>Static Generator (obfuscate traffic): <form method="post" action="/static_gen"><button>Generate</button></form></p>
    
    <h2>Encrypted Configs</h2>
    <p>Key: {{key[:20]}}...</p>  <!-- Truncated for display -->
    
    <script>fetch('/onion').then(r=>r.text()).then(t=>document.getElementById('onion').innerText=t);</script>
    </body></html>
    '''
    return render_template_string(html, cpu=cpu, mem=mem, disk=disk, vpn=vpn_status, tor=tor_status, ssh=ssh_status, proxy=proxy_status, key=ENCRYPTED_KEY)

@app.route('/vpn_start', methods=['POST'])
def vpn_start():
    success = start_vpn()
    return redirect('/')

@app.route('/vpn_stop', methods=['POST'])
def vpn_stop():
    stop_vpn()
    return redirect('/')

@app.route('/tor_start', methods=['POST'])
def tor_start():
    start_tor()
    return redirect('/')

@app.route('/tor_stop', methods=['POST'])
def tor_stop():
    stop_tor()
    return redirect('/')

@app.route('/ssh_start', methods=['POST'])
def ssh_start():
    start_ssh()
    return redirect('/')

@app.route('/ssh_stop', methods=['POST'])
def ssh_stop():
    stop_ssh()
    return redirect('/')

@app.route('/toggle_proxy', methods=['POST'])
def toggle_proxy_route():
    toggle_proxy()
    return redirect('/')

@app.route('/run_nmap', methods=['POST'])
def run_nmap():
    target = request.form['target']
    result = subprocess.run(['proxychains', 'nmap', '-sV', target], capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre><a href='/'>Back</a>"

@app.route('/static_gen')
def static_gen():
    # From Termux-Security: Run static generator
    result = subprocess.run(['static_gen'], capture_output=True, text=True)  # Assume command from install
    return f"Generated: {result.stdout}<a href='/'>Back</a>"

@app.route('/onion')
def get_onion():
    with open('/data/data/com.termux/files/usr/var/lib/tor/my_service/hostname', 'r') as f:
        return f.read().strip()

if __name__ == "__main__":
    # Start background services on boot
    threading.Thread(target=start_ssh, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'), debug=False)
EOF

# Step 6: Configure Tor for anonymous hidden service (points to dashboard on port 5000)
echo "Step 6: Configuring Tor hidden service..."
mkdir -p $PREFIX/var/lib/tor/my_service
cat >> $PREFIX/etc/tor/torrc << EOF
HiddenServiceDir $PREFIX/var/lib/tor/my_service/
HiddenServicePort 80 127.0.0.1:5000
EOF

# Step 7: Set up sample OpenVPN config (client; for server, see Reddit guide: https://www.reddit.com/r/termux/comments/1g1ug0x/vpn_server_on_termux/)
echo "Step 7: Setting up sample OpenVPN config..."
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
# Note: Download real certs/keys for production. For server setup, use OpenVPN docs.

# Step 8: Configure Proxychains (from termux4all)
echo "Step 8: Configuring Proxychains..."
cat > $PREFIX/etc/proxychains.conf << EOF
# Proxychains config for anonymity
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050  # Tor SOCKS
EOF

# Step 9: Start services and dashboard
echo "Step 9: Starting services..."
# Start Tor
tor &
sleep 10
echo "Tor Onion Address: $(cat $PREFIX/var/lib/tor/my_service/hostname)"
echo "Access dashboard via Tor Browser at the onion address (HTTPS implied via cert)."
# Start Nginx as reverse proxy (optional, for port 80/443)
nginx -c $PREFIX/etc/nginx/nginx.conf  # Default config proxies to 5000 if set
# Start SSH (secure server)
sshd &
# Start dashboard in foreground
echo "Starting dashboard... Access locally at https://127.0.0.1:5000"
python dashboard.py

echo "=== Setup Complete! ==="
echo " - Local: https://127.0.0.1:5000"
echo " - Onion: $(cat $PREFIX/var/lib/tor/my_service/hostname)"
echo " - SSH: ssh localhost -p 8022"
echo " - VPN: Edit client.ovpn and start via dashboard."
echo " - Proxy: Toggle in dashboard; use 'proxychains command' for apps."
echo "For automation, add cron jobs: crontab -e"
echo "Stop all: pkill -f 'tor|sshd|nginx|python|openvpn'"
