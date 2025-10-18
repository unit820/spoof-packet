#!/usr/bin/env python3
"""
Complete Functional Packet Monitor Tool with Auto Virtual Environment Setup
Features:
- Auto-creates virtual environment
- Auto-installs dependencies in venv
- Real-time packet monitoring
- Protocol filtering
- Web portal for monitoring
- Both CLI and Web interfaces
- Proper packet capture and display
"""

import os
import sys
import time
import json
import threading
import subprocess
import platform
import socket
import select
import venv
from datetime import datetime
from pathlib import Path

def setup_virtual_environment():
    """Create and setup virtual environment automatically"""
    current_dir = Path(__file__).parent
    venv_path = current_dir / "packet_monitor_venv"
    
    # Check if we're already in a virtual environment
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    if in_venv:
        print("✅ Already running in a virtual environment")
        return True
    
    # Create virtual environment if it doesn't exist
    if not venv_path.exists():
        print("🐍 Creating virtual environment...")
        try:
            venv.create(venv_path, with_pip=True)
            print(f"✅ Virtual environment created at: {venv_path}")
        except Exception as e:
            print(f"❌ Failed to create virtual environment: {e}")
            return False
    
    # Determine the correct Python executable path
    if platform.system() == "Windows":
        python_executable = venv_path / "Scripts" / "python.exe"
        pip_executable = venv_path / "Scripts" / "pip.exe"
    else:
        python_executable = venv_path / "bin" / "python"
        pip_executable = venv_path / "bin" / "pip"
    
    # Check if we're already running from the venv
    if Path(sys.executable).resolve() != python_executable.resolve():
        print("🔄 Installing dependencies in virtual environment...")
        
        # Install requirements in the venv
        requirements = [
            "flask==2.3.3",
            "flask-socketio==5.3.6", 
            "psutil==5.9.5",
            "python-socketio==5.8.0",
            "eventlet==0.33.3",
            "Werkzeug==2.3.7"
        ]
        
        try:
            subprocess.run([
                str(pip_executable), "install"
            ] + requirements, check=True, capture_output=True)
            print("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
        
        # Restart the script using the venv Python
        print("🔄 Restarting from virtual environment...")
        try:
            os.execv(str(python_executable), [str(python_executable)] + sys.argv)
        except Exception as e:
            print(f"❌ Failed to restart with virtual environment: {e}")
            return False
    
    return True

# Continue with the main application only if venv is setup
if not setup_virtual_environment():
    print("❌ Virtual environment setup failed. Exiting.")
    sys.exit(1)

# Now import the required packages that are installed in the venv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import psutil

class UniversalPacketMonitor:
    def __init__(self):
        self.system = platform.system()
        self.monitoring = False
        self.modify_packets = False
        self.source_ip = None
        self.dest_ip = None
        self.current_interface = None
        self.current_protocol = "all"
        self.packet_count = 0
        self.modified_count = 0
        self.start_time = None
        self.monitor_thread = None
        self.monitor_process = None
        
        # Web interface components
        self.app = Flask(__name__)
        self.app.secret_key = 'packet_monitor_secret_2024'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')
        self.setup_web_routes()
        
        # Protocol definitions
        self.protocols = {
            '1': {'name': 'All Protocols', 'filter': ''},
            '2': {'name': 'TCP', 'filter': 'tcp'},
            '3': {'name': 'UDP', 'filter': 'udp'},
            '4': {'name': 'HTTP', 'filter': 'http or tcp port 80'},
            '5': {'name': 'DNS', 'filter': 'port 53'},
            '6': {'name': 'ICMP', 'filter': 'icmp'},
            '7': {'name': 'ARP', 'filter': 'arp'}
        }

        print("✅ Virtual environment activated and ready!")

    def setup_web_routes(self):
        """Setup web routes for the portal"""
        @self.app.route('/')
        def index():
            return self.web_index()
        
        @self.app.route('/dashboard')
        def dashboard():
            return self.web_dashboard()
        
        @self.app.route('/monitor')
        def monitor():
            return self.web_monitor()
        
        @self.app.route('/api/start', methods=['POST'])
        def api_start():
            return self.api_start_monitoring()
        
        @self.app.route('/api/stop', methods=['POST'])
        def api_stop():
            return self.api_stop_monitoring()
        
        @self.app.route('/api/stats')
        def api_stats():
            return self.api_get_stats()
        
        @self.app.route('/api/interfaces')
        def api_interfaces():
            return jsonify(self.get_network_interfaces())
        
        @self.app.route('/api/local_ip')
        def api_local_ip():
            return jsonify({'local_ip': self.get_local_ip()})
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f"Web client connected: {request.sid}")
            emit('connection_status', {'status': 'connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f"Web client disconnected: {request.sid}")

    def check_system_dependencies(self):
        """Check for system-level dependencies (Wireshark/tshark)"""
        print("🔍 Checking system dependencies...")
        
        # Check if tshark is available
        try:
            if self.system == "Windows":
                # Check common Wireshark installation paths
                wireshark_paths = [
                    r"C:\Program Files\Wireshark\tshark.exe",
                    r"C:\Program Files (x86)\Wireshark\tshark.exe"
                ]
                tshark_found = any(os.path.exists(path) for path in wireshark_paths)
                if tshark_found:
                    print("✅ Wireshark/tshark found")
                else:
                    print("❌ Wireshark/tshark not found")
                return tshark_found
            else:
                result = subprocess.run(["which", "tshark"], capture_output=True, text=True)
                if result.returncode == 0:
                    print("✅ tshark found")
                    return True
                else:
                    print("❌ tshark not found")
                    return False
        except Exception as e:
            print(f"❌ Error checking dependencies: {e}")
            return False

    def install_system_dependencies(self):
        """Guide user to install system dependencies"""
        print("\n📋 Please install Wireshark/tshark manually:")
        
        if self.system == "Linux":
            if subprocess.run(["which", "apt"], capture_output=True).returncode == 0:
                print("   sudo apt update && sudo apt install tshark")
                print("   Note: You might need to add your user to wireshark group:")
                print("   sudo usermod -a -G wireshark $USER")
                print("   Then logout and login again")
            elif subprocess.run(["which", "yum"], capture_output=True).returncode == 0:
                print("   sudo yum install wireshark wireshark-cli")
            elif subprocess.run(["which", "pacman"], capture_output=True).returncode == 0:
                print("   sudo pacman -S wireshark-qt")
        elif self.system == "Darwin":
            print("   brew install wireshark")
        elif self.system == "Windows":
            print("   Download from https://www.wireshark.org/")
        
        print("\n💡 After installation, restart this script.")
        return False

    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        try:
            if self.system == "Windows":
                # Try using Wireshark if available
                wireshark_paths = [
                    r"C:\Program Files\Wireshark\tshark.exe",
                    r"C:\Program Files (x86)\Wireshark\tshark.exe"
                ]
                tshark_path = None
                for path in wireshark_paths:
                    if os.path.exists(path):
                        tshark_path = path
                        break
                
                if tshark_path:
                    result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True)
                else:
                    # Fallback to system commands
                    result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True)
            else:
                result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
            
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    # Parse tshark output format: "1. eth0"
                    parts = line.split('.', 1)
                    if len(parts) == 2:
                        interface_name = parts[1].strip()
                        interfaces.append(interface_name)
            
            # If no interfaces found with tshark, use psutil as fallback
            if not interfaces:
                interfaces = list(psutil.net_if_addrs().keys())
            
            return interfaces
        except Exception as e:
            print(f"⚠️  Error getting interfaces: {e}")
            # Fallback to psutil
            return list(psutil.net_if_addrs().keys())

    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Try to get IP from default gateway
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            try:
                # Fallback: get first non-localhost IP
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            return addr.address
            except:
                pass
        return "Unknown"

    def get_tshark_command(self):
        """Get the correct tshark command for the current system"""
        if self.system == "Windows":
            wireshark_paths = [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe"
            ]
            for path in wireshark_paths:
                if os.path.exists(path):
                    return path
            return "tshark"  # Fallback
        else:
            return "tshark"

    def start_packet_capture(self, interface, protocol_filter, modify_packets=False, source_ip=None, dest_ip=None):
        """Start packet capture process"""
        try:
            tshark_cmd = self.get_tshark_command()
            
            # Build tshark command
            cmd = [
                tshark_cmd,
                "-i", interface,
                "-l",  # Line buffered
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst", 
                "-e", "frame.protocols",
                "-e", "frame.len",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport", 
                "-e", "udp.dstport"
            ]
            
            # Add protocol filter if specified
            if protocol_filter and protocol_filter != "all":
                cmd.extend(["-f", protocol_filter])
            
            print(f"Starting capture with command: {' '.join(cmd)}")
            
            # Start the process
            self.monitor_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            return True
            
        except Exception as e:
            print(f"❌ Error starting packet capture: {e}")
            return False

    def process_packets(self):
        """Process packets from tshark output"""
        while self.monitoring and self.monitor_process:
            try:
                # Read line from tshark output
                line = self.monitor_process.stdout.readline()
                if not line and self.monitor_process.poll() is not None:
                    break
                
                if line.strip():
                    self.parse_and_emit_packet(line.strip())
                    
            except Exception as e:
                print(f"❌ Error reading packet: {e}")
                break

    def parse_and_emit_packet(self, packet_line):
        """Parse a packet line from tshark and emit it"""
        try:
            fields = packet_line.split('\t')
            
            # Extract fields with safe indexing
            timestamp = fields[0] if len(fields) > 0 else datetime.now().strftime("%H:%M:%S")
            source_ip = fields[1] if len(fields) > 1 else "Unknown"
            dest_ip = fields[2] if len(fields) > 2 else "Unknown"
            protocols = fields[3] if len(fields) > 3 else "Unknown"
            length = fields[4] if len(fields) > 4 else "0"
            
            # Determine main protocol
            protocol = "Unknown"
            if "tcp" in protocols.lower():
                protocol = "TCP"
            elif "udp" in protocols.lower():
                protocol = "UDP" 
            elif "icmp" in protocols.lower():
                protocol = "ICMP"
            elif "arp" in protocols.lower():
                protocol = "ARP"
            elif "dns" in protocols.lower():
                protocol = "DNS"
            elif "http" in protocols.lower():
                protocol = "HTTP"
            
            # Check if packet should be modified
            modified = False
            if (self.modify_packets and 
                source_ip == self.source_ip and 
                dest_ip == self.dest_ip):
                self.modified_count += 1
                modified = True
            
            self.packet_count += 1
            
            packet_info = {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'protocol': protocol,
                'length': length,
                'packet_number': self.packet_count,
                'modified': modified
            }
            
            # Emit to web clients
            self.socketio.emit('new_packet', packet_info)
            
            # Print to console in CLI mode
            if not hasattr(self, 'web_mode_active') or not self.web_mode_active:
                mod_indicator = " 🛠️" if modified else ""
                print(f"[{timestamp}] {source_ip} -> {dest_ip} {protocol} {length} bytes{mod_indicator}")
                
        except Exception as e:
            print(f"❌ Error parsing packet: {e}")

    def stop_packet_capture(self):
        """Stop packet capture process"""
        if self.monitor_process:
            try:
                self.monitor_process.terminate()
                self.monitor_process.wait(timeout=5)
            except:
                try:
                    self.monitor_process.kill()
                except:
                    pass
            self.monitor_process = None

    def start_monitoring(self, interface, protocol_config, modify_packets=False, source_ip=None, dest_ip=None):
        """Start monitoring with given parameters"""
        # Stop any existing monitoring
        self.stop_monitoring()
        
        # Set monitoring parameters
        self.monitoring = True
        self.current_interface = interface
        self.current_protocol = protocol_config['name']
        self.modify_packets = modify_packets
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.packet_count = 0
        self.modified_count = 0
        self.start_time = datetime.now()
        
        # Start packet capture
        if self.start_packet_capture(interface, protocol_config['filter'], modify_packets, source_ip, dest_ip):
            # Start packet processing thread
            self.monitor_thread = threading.Thread(target=self.process_packets)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            return True
        else:
            self.monitoring = False
            return False

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        self.monitoring = False
        self.stop_packet_capture()
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)

    # CLI Interface Methods
    def display_interfaces(self, interfaces):
        """Display available interfaces in CLI"""
        print("\n" + "="*50)
        print("📡 Available Network Interfaces")
        print("="*50)
        
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")
        
        print("\n0. Exit")

    def select_interface_cli(self, interfaces):
        """Select interface in CLI mode"""
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interfaces)}): ").strip()
                if choice == '0':
                    return None
                
                choice_num = int(choice)
                if 1 <= choice_num <= len(interfaces):
                    return interfaces[choice_num - 1]
                else:
                    print(f"❌ Please enter a number between 1 and {len(interfaces)}")
            except ValueError:
                print("❌ Please enter a valid number")
            except KeyboardInterrupt:
                print("\n👋 Exiting...")
                return None

    def display_protocols_cli(self):
        """Display protocols in CLI"""
        print("\n" + "="*50)
        print("📊 Select Protocol to Monitor")
        print("="*50)
        
        for key, protocol in self.protocols.items():
            print(f"{key}. {protocol['name']}")

    def select_protocol_cli(self):
        """Select protocol in CLI"""
        while True:
            try:
                choice = input(f"\nSelect protocol (1-{len(self.protocols)}): ").strip()
                if choice in self.protocols:
                    return self.protocols[choice]
                else:
                    print(f"❌ Please enter a number between 1 and {len(self.protocols)}")
            except ValueError:
                print("❌ Please enter a valid number")
            except KeyboardInterrupt:
                return None

    def ask_modification_cli(self):
        """Ask about packet modification in CLI"""
        print("\n" + "="*50)
        print("🔧 Packet Modification")
        print("="*50)
        print("⚠️  WARNING: Only use on networks you own!")
        print("="*50)
        
        while True:
            choice = input("\nModify packet headers? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                return False
            else:
                print("❌ Please enter 'y' or 'n'")

    def get_modification_params_cli(self):
        """Get modification parameters in CLI"""
        local_ip = self.get_local_ip()
        print(f"\n📍 Your system IP: {local_ip}")
        
        while True:
            dest_ip = input("Enter destination IP to modify: ").strip()
            if self.validate_ip(dest_ip):
                return local_ip, dest_ip
            else:
                print("❌ Invalid IP address")

    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def run_cli_mode(self):
        """Run the CLI interface"""
        print("🛠️  Packet Monitor - CLI Mode")
        print("=" * 40)
        
        # Check system dependencies
        if not self.check_system_dependencies():
            if not self.install_system_dependencies():
                return
        
        # Get interfaces
        interfaces = self.get_network_interfaces()
        if not interfaces:
            print("❌ No network interfaces found")
            return
        
        # Select interface
        self.display_interfaces(interfaces)
        interface = self.select_interface_cli(interfaces)
        if not interface:
            return
        
        # Select protocol
        self.display_protocols_cli()
        protocol = self.select_protocol_cli()
        if not protocol:
            return
        
        # Ask about modification
        modify_packets = self.ask_modification_cli()
        source_ip, dest_ip = None, None
        
        if modify_packets:
            source_ip, dest_ip = self.get_modification_params_cli()
        
        # Start monitoring
        print(f"\n🚀 Starting monitoring on {interface}")
        print(f"📊 Protocol: {protocol['name']}")
        if modify_packets:
            print(f"🔧 Modification: ON (Source: {source_ip} -> Dest: {dest_ip})")
        print("Press Ctrl+C to stop")
        print("-" * 60)
        
        try:
            if self.start_monitoring(interface, protocol, modify_packets, source_ip, dest_ip):
                # Keep running until interrupted
                while self.monitoring:
                    time.sleep(1)
            else:
                print("❌ Failed to start monitoring")
                
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        finally:
            self.stop_monitoring()
            
        # Show summary
        duration = datetime.now() - self.start_time
        print(f"\n📊 Summary:")
        print(f"   Packets captured: {self.packet_count}")
        print(f"   Packets modified: {self.modified_count}")
        print(f"   Duration: {duration}")

    # Web Interface Methods
    def web_index(self):
        """Web portal main page"""
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Packet Monitor</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    color: #333;
                }
                .container { 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #2c3e50, #34495e);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 2.5em;
                }
                .header p {
                    margin: 10px 0 0 0;
                    opacity: 0.8;
                }
                .content {
                    padding: 40px;
                }
                .card-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                .card {
                    background: #f8f9fa;
                    padding: 25px;
                    border-radius: 10px;
                    border-left: 4px solid #3498db;
                    transition: transform 0.3s, box-shadow 0.3s;
                }
                .card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                }
                .card h3 {
                    margin-top: 0;
                    color: #2c3e50;
                }
                .btn {
                    display: inline-block;
                    background: #3498db;
                    color: white;
                    padding: 12px 25px;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: bold;
                    transition: background 0.3s, transform 0.3s;
                    border: none;
                    cursor: pointer;
                    margin: 5px;
                }
                .btn:hover {
                    background: #2980b9;
                    transform: translateY(-2px);
                }
                .btn-success {
                    background: #27ae60;
                }
                .btn-success:hover {
                    background: #219a52;
                }
                .status-bar {
                    background: #ecf0f1;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                }
                .status-item {
                    display: inline-block;
                    margin-right: 30px;
                }
                .status-value {
                    font-weight: bold;
                    color: #2c3e50;
                }
                .nav {
                    text-align: center;
                    margin: 20px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Packet Monitor Web Portal</h1>
                    <p>Real-time network packet monitoring and analysis tool</p>
                </div>
                
                <div class="content">
                    <div class="nav">
                        <a href="/dashboard" class="btn btn-success">🎛️ Control Panel</a>
                        <a href="/monitor" class="btn">📊 Live Monitor</a>
                    </div>
                    
                    <div class="card-grid">
                        <div class="card">
                            <h3>🔍 Real-time Monitoring</h3>
                            <p>Monitor network traffic in real-time with detailed packet analysis and protocol filtering.</p>
                        </div>
                        
                        <div class="card">
                            <h3>🛠️ Packet Modification</h3>
                            <p>Advanced packet modification capabilities for authorized network testing and analysis.</p>
                        </div>
                        
                        <div class="card">
                            <h3>📊 Web Interface</h3>
                            <p>Beautiful and intuitive web interface for monitoring and controlling packet capture.</p>
                        </div>
                    </div>
                    
                    <div class="status-bar">
                        <h3>System Status</h3>
                        <div class="status-item">
                            <span>Monitoring: </span>
                            <span class="status-value" id="status">Inactive</span>
                        </div>
                        <div class="status-item">
                            <span>Packets Captured: </span>
                            <span class="status-value" id="packets">0</span>
                        </div>
                        <div class="status-item">
                            <span>Interface: </span>
                            <span class="status-value" id="interface">None</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Update status every 2 seconds
                function updateStatus() {
                    fetch('/api/stats')
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('status').textContent = 
                                data.monitoring ? 'Active' : 'Inactive';
                            document.getElementById('status').style.color = 
                                data.monitoring ? '#27ae60' : '#e74c3c';
                            document.getElementById('packets').textContent = data.packet_count || 0;
                            document.getElementById('interface').textContent = data.interface || 'None';
                        })
                        .catch(err => {
                            console.error('Status update failed:', err);
                        });
                }
                
                setInterval(updateStatus, 2000);
                updateStatus(); // Initial update
            </script>
        </body>
        </html>
        '''

    def web_dashboard(self):
        """Web control panel"""
        interfaces = self.get_network_interfaces()
        local_ip = self.get_local_ip()
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Control Panel - Packet Monitor</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    color: #333;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #2c3e50, #34495e);
                    color: white;
                    padding: 30px;
                }}
                .header h1 {{
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }}
                .content {{
                    padding: 30px;
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 30px;
                }}
                @media (max-width: 768px) {{
                    .content {{
                        grid-template-columns: 1fr;
                    }}
                }}
                .card {{
                    background: #f8f9fa;
                    padding: 25px;
                    border-radius: 10px;
                    border-left: 4px solid #3498db;
                }}
                .card h3 {{
                    margin-top: 0;
                    color: #2c3e50;
                    border-bottom: 2px solid #ecf0f1;
                    padding-bottom: 10px;
                }}
                .form-group {{
                    margin: 15px 0;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 600;
                    color: #2c3e50;
                }}
                select, input {{
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }}
                select:focus, input:focus {{
                    outline: none;
                    border-color: #3498db;
                }}
                .btn {{
                    background: #3498db;
                    color: white;
                    padding: 12px 25px;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: background 0.3s, transform 0.3s;
                    margin: 5px;
                }}
                .btn:hover {{
                    background: #2980b9;
                    transform: translateY(-2px);
                }}
                .btn-stop {{
                    background: #e74c3c;
                }}
                .btn-stop:hover {{
                    background: #c0392b;
                }}
                .btn-success {{
                    background: #27ae60;
                }}
                .btn-success:hover {{
                    background: #219a52;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin-top: 20px;
                }}
                .stat-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .stat-value {{
                    font-size: 1.5em;
                    font-weight: bold;
                    color: #3498db;
                    display: block;
                }}
                .stat-label {{
                    font-size: 0.9em;
                    color: #7f8c8d;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 15px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎛️ Control Panel</h1>
                    <p>Configure and control packet monitoring settings</p>
                </div>
                
                <div class="content">
                    <div>
                        <div class="card">
                            <h3>⚙️ Monitoring Configuration</h3>
                            
                            <div class="warning">
                                <strong>⚠️ Legal Notice:</strong> Only use on networks you own or have explicit permission to monitor.
                            </div>
                            
                            <form id="monitorForm">
                                <div class="form-group">
                                    <label>Network Interface:</label>
                                    <select id="interface">
                                        {"".join(f'<option value="{iface}">{iface}</option>' for iface in interfaces)}
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label>Protocol Filter:</label>
                                    <select id="protocol">
                                        <option value="all">All Protocols</option>
                                        <option value="tcp">TCP</option>
                                        <option value="udp">UDP</option>
                                        <option value="http">HTTP</option>
                                        <option value="dns">DNS</option>
                                        <option value="icmp">ICMP</option>
                                        <option value="arp">ARP</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label>
                                        <input type="checkbox" id="modify"> 
                                        🔧 Enable Packet Modification
                                    </label>
                                </div>
                                
                                <div id="modOptions" style="display: none;">
                                    <div class="form-group">
                                        <label>Source IP:</label>
                                        <input type="text" id="sourceIp" value="{local_ip}" readonly>
                                    </div>
                                    <div class="form-group">
                                        <label>Destination IP:</label>
                                        <input type="text" id="destIp" placeholder="Enter destination IP">
                                    </div>
                                </div>
                                
                                <div style="margin-top: 25px;">
                                    <button type="button" class="btn btn-success" onclick="startMonitoring()">
                                        ▶️ Start Monitoring
                                    </button>
                                    <button type="button" class="btn btn-stop" onclick="stopMonitoring()">
                                        ⏹️ Stop Monitoring
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                    
                    <div>
                        <div class="card">
                            <h3>📊 Real-time Statistics</h3>
                            <div id="stats">
                                <div class="stats">
                                    <div class="stat-item">
                                        <span class="stat-value" id="statStatus">Inactive</span>
                                        <span class="stat-label">Status</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-value" id="statPackets">0</span>
                                        <span class="stat-label">Packets</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-value" id="statModified">0</span>
                                        <span class="stat-label">Modified</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-value" id="statDuration">0s</span>
                                        <span class="stat-label">Duration</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <h3>🔗 Quick Actions</h3>
                            <div>
                                <a href="/" class="btn">🏠 Dashboard</a>
                                <a href="/monitor" class="btn">📡 Live Monitor</a>
                                <button class="btn" onclick="clearStats()">🔄 Clear Stats</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Toggle modification options
                document.getElementById('modify').addEventListener('change', function() {{
                    document.getElementById('modOptions').style.display = this.checked ? 'block' : 'none';
                }});
                
                function startMonitoring() {{
                    const config = {{
                        interface: document.getElementById('interface').value,
                        protocol: document.getElementById('protocol').value,
                        modify_packets: document.getElementById('modify').checked,
                        source_ip: document.getElementById('sourceIp').value,
                        dest_ip: document.getElementById('destIp').value
                    }};
                    
                    if (config.modify_packets && !config.dest_ip) {{
                        alert('Please enter destination IP for packet modification');
                        return;
                    }}
                    
                    fetch('/api/start', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify(config)
                    }}).then(r => r.json()).then(data => {{
                        if (data.success) {{
                            alert('✅ ' + data.message);
                            updateStats();
                        }} else {{
                            alert('❌ ' + data.error);
                        }}
                    }}).catch(err => {{
                        alert('❌ Network error: ' + err);
                    }});
                }}
                
                function stopMonitoring() {{
                    fetch('/api/stop', {{ method: 'POST' }})
                        .then(r => r.json())
                        .then(data => {{
                            alert(data.message || 'Monitoring stopped');
                            updateStats();
                        }});
                }}
                
                function clearStats() {{
                    document.getElementById('statPackets').textContent = '0';
                    document.getElementById('statModified').textContent = '0';
                    document.getElementById('statDuration').textContent = '0s';
                }}
                
                function updateStats() {{
                    fetch('/api/stats')
                        .then(r => r.json())
                        .then(data => {{
                            document.getElementById('statStatus').textContent = 
                                data.monitoring ? 'Active' : 'Inactive';
                            document.getElementById('statStatus').style.color = 
                                data.monitoring ? '#27ae60' : '#e74c3c';
                            document.getElementById('statPackets').textContent = data.packet_count || 0;
                            document.getElementById('statModified').textContent = data.modified_count || 0;
                            
                            // Calculate duration
                            if (data.start_time) {{
                                const start = new Date(data.start_time);
                                const now = new Date();
                                const duration = Math.floor((now - start) / 1000);
                                document.getElementById('statDuration').textContent = duration + 's';
                            }}
                        }})
                        .catch(err => {{
                            console.error('Failed to update stats:', err);
                        }});
                }}
                
                // Update stats every 2 seconds
                setInterval(updateStats, 2000);
                updateStats(); // Initial update
            </script>
        </body>
        </html>
        '''

    def web_monitor(self):
        """Live monitoring page"""
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Live Monitor - Packet Monitor</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    color: #333;
                }
                .container { 
                    max-width: 1400px; 
                    margin: 0 auto; 
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #2c3e50, #34495e);
                    color: white;
                    padding: 25px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .header h1 {
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }
                .controls {
                    background: #ecf0f1;
                    padding: 15px 25px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .content {
                    padding: 0;
                }
                .btn {
                    background: #3498db;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 6px;
                    cursor: pointer;
                    text-decoration: none;
                    font-weight: bold;
                    transition: background 0.3s;
                }
                .btn:hover {
                    background: #2980b9;
                }
                .btn-stop {
                    background: #e74c3c;
                }
                .btn-stop:hover {
                    background: #c0392b;
                }
                #packets {
                    max-height: 70vh;
                    overflow-y: auto;
                    padding: 0;
                }
                .packet {
                    border-bottom: 1px solid #ecf0f1;
                    padding: 15px 25px;
                    background: white;
                    transition: background 0.3s;
                }
                .packet:hover {
                    background: #f8f9fa;
                }
                .packet.modified {
                    border-left: 4px solid #e74c3c;
                    background: #fff5f5;
                }
                .packet-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }
                .packet-number {
                    font-weight: bold;
                    color: #2c3e50;
                }
                .packet-time {
                    color: #7f8c8d;
                    font-size: 0.9em;
                }
                .packet-protocol {
                    background: #3498db;
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                    font-weight: bold;
                }
                .protocol-tcp { background: #27ae60; }
                .protocol-udp { background: #e67e22; }
                .protocol-http { background: #9b59b6; }
                .protocol-dns { background: #34495e; }
                .protocol-icmp { background: #e74c3c; }
                .protocol-arp { background: #f39c12; }
                .packet-details {
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                    gap: 15px;
                    font-size: 0.9em;
                }
                .packet-source, .packet-dest, .packet-length {
                    display: flex;
                    flex-direction: column;
                }
                .detail-label {
                    font-weight: bold;
                    color: #7f8c8d;
                    font-size: 0.8em;
                }
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                    color: #7f8c8d;
                }
                .empty-state i {
                    font-size: 3em;
                    margin-bottom: 15px;
                    display: block;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Live Packet Monitor</h1>
                    <div>
                        <a href="/dashboard" class="btn">🎛️ Control Panel</a>
                        <a href="/" class="btn">🏠 Dashboard</a>
                    </div>
                </div>
                
                <div class="controls">
                    <div>
                        <strong id="packetCount">0 packets</strong>
                    </div>
                    <div>
                        <button class="btn btn-stop" onclick="clearPackets()">🗑️ Clear</button>
                    </div>
                </div>
                
                <div class="content">
                    <div id="packets">
                        <div class="empty-state" id="emptyState">
                            <i>📡</i>
                            <h3>No packets captured yet</h3>
                            <p>Start monitoring from the control panel to see live network traffic</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
            <script>
                const socket = io();
                const packetsDiv = document.getElementById('packets');
                const emptyState = document.getElementById('emptyState');
                let packetCount = 0;
                
                socket.on('connect', function() {
                    console.log('Connected to live monitor');
                });
                
                socket.on('new_packet', function(packet) {
                    packetCount++;
                    updatePacketCount();
                    
                    if (emptyState.style.display !== 'none') {
                        emptyState.style.display = 'none';
                    }
                    
                    const div = document.createElement('div');
                    div.className = 'packet' + (packet.modified ? ' modified' : '');
                    
                    const time = packet.timestamp || new Date().toLocaleTimeString();
                    const protocolClass = 'packet-protocol protocol-' + (packet.protocol ? packet.protocol.toLowerCase() : 'unknown');
                    
                    div.innerHTML = `
                        <div class="packet-header">
                            <div>
                                <span class="packet-number">#${packet.packet_number}</span>
                                <span class="packet-time">${time}</span>
                            </div>
                            <span class="${protocolClass}">${packet.protocol || 'N/A'}</span>
                        </div>
                        <div class="packet-details">
                            <div class="packet-source">
                                <span class="detail-label">Source IP</span>
                                <span>${packet.source_ip || 'N/A'}</span>
                            </div>
                            <div class="packet-dest">
                                <span class="detail-label">Destination IP</span>
                                <span>${packet.dest_ip || 'N/A'}</span>
                            </div>
                            <div class="packet-length">
                                <span class="detail-label">Length</span>
                                <span>${packet.length || '0'} bytes</span>
                            </div>
                        </div>
                        ${packet.modified ? '<div style="color: #e74c3c; margin-top: 8px; font-weight: bold;">🛠️ MODIFIED</div>' : ''}
                    `;
                    
                    packetsDiv.insertBefore(div, packetsDiv.firstChild);
                    
                    // Limit to 200 packets for performance
                    if (packetsDiv.children.length > 200) {
                        packetsDiv.removeChild(packetsDiv.lastChild);
                    }
                });
                
                function updatePacketCount() {
                    document.getElementById('packetCount').textContent = packetCount + ' packets';
                }
                
                function clearPackets() {
                    packetsDiv.innerHTML = '';
                    packetsDiv.appendChild(emptyState);
                    emptyState.style.display = 'block';
                    packetCount = 0;
                    updatePacketCount();
                }
            </script>
        </body>
        </html>
        '''

    def api_start_monitoring(self):
        """API endpoint to start monitoring"""
        try:
            data = request.get_json()
            interface = data.get('interface')
            protocol_name = data.get('protocol', 'all')
            
            # Find protocol config
            protocol_config = {'name': protocol_name, 'filter': ''}
            if protocol_name != 'all':
                for key, proto in self.protocols.items():
                    if proto['name'].lower() == protocol_name.lower():
                        protocol_config = proto
                        break
                # Set filter based on protocol name if not found in predefined
                if protocol_config['filter'] == '':
                    protocol_config['filter'] = protocol_name
            
            modify_packets = data.get('modify_packets', False)
            source_ip = data.get('source_ip', '')
            dest_ip = data.get('dest_ip', '')
            
            if not interface:
                return jsonify({'success': False, 'error': 'No interface selected'})
            
            # Start monitoring
            if self.start_monitoring(interface, protocol_config, modify_packets, source_ip, dest_ip):
                return jsonify({
                    'success': True, 
                    'message': f'Monitoring started on {interface}',
                    'start_time': self.start_time.isoformat() if self.start_time else None
                })
            else:
                return jsonify({'success': False, 'error': 'Failed to start monitoring'})
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    def api_stop_monitoring(self):
        """API endpoint to stop monitoring"""
        self.stop_monitoring()
        return jsonify({'success': True, 'message': 'Monitoring stopped'})

    def api_get_stats(self):
        """API endpoint to get statistics"""
        return jsonify({
            'monitoring': self.monitoring,
            'packet_count': self.packet_count,
            'modified_count': self.modified_count,
            'interface': self.current_interface,
            'protocol': self.current_protocol,
            'start_time': self.start_time.isoformat() if self.start_time else None
        })

    def run_web_mode(self):
        """Run the web interface"""
        self.web_mode_active = True
        print("🌐 Starting Packet Monitor Web Portal...")
        print("📡 Access at: http://127.0.0.1:5001")
        print("⚡ Press Ctrl+C to stop")
        
        # Check system dependencies
        if not self.check_system_dependencies():
            if not self.install_system_dependencies():
                return
        
        try:
            self.socketio.run(self.app, host='127.0.0.1', port=5001, debug=False, use_reloader=False)
        except Exception as e:
            print(f"❌ Web server error: {e}")

    def run(self):
        """Main entry point"""
        if len(sys.argv) > 1 and sys.argv[1] == '--web':
            self.run_web_mode()
        else:
            self.run_cli_mode()

def main():
    """Main function"""
    print("=" * 60)
    print("🚀 Packet Monitor - Auto Virtual Environment Setup")
    print("=" * 60)
    
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Usage:")
        print("  python packet_monitor.py          # CLI mode")
        print("  python packet_monitor.py --web    # Web mode on http://127.0.0.1:5001")
        print("\nThe script will automatically:")
        print("  ✅ Create virtual environment")
        print("  ✅ Install all dependencies")
        print("  ✅ Activate the environment")
        print("  ✅ Start the application")
        return
    
    monitor = UniversalPacketMonitor()
    monitor.run()

if __name__ == "__main__":
    main()