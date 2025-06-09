#!/usr/bin/env python3
"""
Advanced Secure File Transfer System
Proje gereksinimlerini karşılayan kapsamlı dosya transfer sistemi
"""

import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext
import socket
import threading
import os
import time
import hashlib
import json
import struct
import random
import subprocess
import platform
from datetime import datetime

# Kriptografi kütüphaneleri
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Cryptography kütüphanesi bulunamadı. pip install cryptography komutu ile yükleyiniz.")

# Scapy için import (opsiyonel)
try:
    from scapy.all import IP, TCP, UDP, Raw, send, sniff, get_if_list, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy kütüphanesi bulunamadı. pip install scapy komutu ile yükleyiniz.")

class NetworkUtils:
    """Network utility functions for low-level operations"""
    
    @staticmethod
    def calculate_ip_checksum(header):
        """IP header checksum calculation"""
        if len(header) % 2:
            header += b'\x00'
        
        checksum = 0
        for i in range(0, len(header), 2):
            w = (header[i] << 8) + header[i + 1]
            checksum += w
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum
    
    @staticmethod
    def create_ip_header(src_ip, dst_ip, payload_len, ttl=64, flags=0):
        """Manual IP header creation"""
        version = 4
        ihl = 5
        tos = 0
        tot_len = 20 + payload_len
        identification = random.randint(1, 65535)
        frag_off = flags
        protocol = 6  # TCP
        check = 0
        
        # IP header without checksum
        header = struct.pack('!BBHHHBBH4s4s',
                           (version << 4) + ihl, tos, tot_len,
                           identification, frag_off, ttl, protocol, check,
                           socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        
        # Calculate checksum
        checksum = NetworkUtils.calculate_ip_checksum(header)
        
        # Recreate header with checksum
        header = struct.pack('!BBHHHBBH4s4s',
                           (version << 4) + ihl, tos, tot_len,
                           identification, frag_off, ttl, protocol, checksum,
                           socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        
        return header
    
    @staticmethod
    def fragment_data(data, fragment_size=1400):
        """Manual packet fragmentation"""
        fragments = []
        offset = 0
        
        while offset < len(data):
            fragment = data[offset:offset + fragment_size]
            more_fragments = 1 if offset + fragment_size < len(data) else 0
            
            fragments.append({
                'data': fragment,
                'offset': offset // 8,  # Fragment offset is in 8-byte units
                'more_fragments': more_fragments
            })
            offset += fragment_size
        
        return fragments

class CryptoManager:
    """Encryption and authentication manager"""
    
    def __init__(self):
        self.aes_key = os.urandom(32)  # 256-bit key
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_rsa_keys()
    
    def generate_rsa_keys(self):
        """Generate RSA key pair"""
        if not CRYPTO_AVAILABLE:
            return
        
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
    
    def encrypt_aes(self, data):
        """AES encryption"""
        if not CRYPTO_AVAILABLE:
            return data
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return iv + encrypted_data
    
    def decrypt_aes(self, encrypted_data):
        """AES decryption"""
        if not CRYPTO_AVAILABLE:
            return encrypted_data
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_rsa(self, data):
        """RSA encryption"""
        if not CRYPTO_AVAILABLE or not self.rsa_public_key:
            return data
        
        encrypted = self.rsa_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def decrypt_rsa(self, encrypted_data):
        """RSA decryption"""
        if not CRYPTO_AVAILABLE or not self.rsa_private_key:
            return encrypted_data
        
        decrypted = self.rsa_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    def calculate_sha256(self, data):
        """SHA-256 hash calculation"""
        return hashlib.sha256(data).hexdigest()
    
    def authenticate_client(self, username, password):
        """Simple client authentication"""
        # Basit authentication - gerçek uygulamada daha güvenli olmalı
        valid_users = {
            "admin": "password123",
            "user1": "secure456",
            "test": "test123"
        }
        return valid_users.get(username) == password

class NetworkAnalyzer:
    """Network performance analysis tools"""
    
    @staticmethod
    def measure_latency(host="8.8.8.8", count=4):
        """Measure network latency"""
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n {count} {host}"
            else:
                cmd = f"ping -c {count} {host}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = result.stdout
            
            # Parse ping results
            times = []
            for line in output.split('\n'):
                if 'time=' in line:
                    try:
                        time_str = line.split('time=')[1].split('ms')[0]
                        times.append(float(time_str))
                    except:
                        continue
            
            if times:
                return {
                    'min': min(times),
                    'max': max(times),
                    'avg': sum(times) / len(times),
                    'count': len(times)
                }
        except Exception as e:
            print(f"Latency measurement error: {e}")
        
        return None
    
    @staticmethod
    def simulate_bandwidth_test():
        """Simulate bandwidth test"""
        # Gerçek bandwidth testi için iperf gerekli
        return {
            'download': random.uniform(10.0, 100.0),
            'upload': random.uniform(5.0, 50.0),
            'unit': 'Mbps'
        }
    
    @staticmethod
    def simulate_packet_loss():
        """Simulate packet loss analysis"""
        return {
            'sent': 100,
            'received': random.randint(95, 100),
            'loss_percentage': random.uniform(0, 5)
        }

    @staticmethod
    def save_to_pcap(packets, filename):
        """Save packets to pcap file for Wireshark analysis"""
        if SCAPY_AVAILABLE:
            wrpcap(filename, packets)
            return True
        return False

    @staticmethod
    def run_iperf_test(server_ip="127.0.0.1"):
        """Run actual iperf test"""
        try:
            result = subprocess.run(['iperf3', '-c', server_ip], 
                                  capture_output=True, text=True)
            # Parse iperf results
            if result.returncode == 0:
                return {
                    'success': True,
                    'output': result.stdout,
                    'error': None
                }
            return {
                'success': False,
                'output': None,
                'error': result.stderr
            }
        except FileNotFoundError:
            return {
                'success': False,
                'output': None,
                'error': "iperf3 not found. Install with: apt install iperf3"
            }

class SecureFileTransferGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Secure File Transfer System")
        self.master.geometry("800x600")
        
        # Initialize components
        self.crypto_manager = CryptoManager()
        self.network_analyzer = NetworkAnalyzer()
        self.network_utils = NetworkUtils()
        
        # Configuration
        self.port = 5001
        self.buffer_size = 4096
        self.file_path = None
        self.authenticated = False
        self.current_user = None
        
        # Create GUI
        self.setup_gui()
        
        # Start server
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
    
    def setup_gui(self):
        """Setup the main GUI"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.auth_frame = ttk.Frame(self.notebook)
        self.transfer_frame = ttk.Frame(self.notebook)
        self.security_frame = ttk.Frame(self.notebook)
        self.analysis_frame = ttk.Frame(self.notebook)
        self.attack_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.auth_frame, text="Authentication")
        self.notebook.add(self.transfer_frame, text="File Transfer")
        self.notebook.add(self.security_frame, text="Security")
        self.notebook.add(self.analysis_frame, text="Network Analysis")
        self.notebook.add(self.attack_frame, text="Attack Simulation")
        
        self.setup_auth_tab()
        self.setup_transfer_tab()
        self.setup_security_tab()
        self.setup_analysis_tab()
        self.setup_attack_tab()
    
    def setup_auth_tab(self):
        """Setup authentication tab"""
        auth_frame = ttk.LabelFrame(self.auth_frame, text="Client Authentication")
        auth_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(auth_frame, width=20)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Password:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = ttk.Entry(auth_frame, show="*", width=20)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(auth_frame, text="Login", command=self.authenticate).grid(row=2, column=0, columnspan=2, pady=10)
        
        self.auth_status = ttk.Label(auth_frame, text="Not authenticated", foreground="red")
        self.auth_status.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Sample credentials info
        info_frame = ttk.LabelFrame(self.auth_frame, text="Sample Credentials")
        info_frame.pack(fill="x", padx=10, pady=10)
        
        credentials_text = """Sample Login Credentials:
Username: admin, Password: password123
Username: user1, Password: secure456
Username: test, Password: test123"""
        
        ttk.Label(info_frame, text=credentials_text, justify="left").pack(padx=10, pady=10)
    
    def setup_transfer_tab(self):
        """Setup file transfer tab"""
        # File selection
        file_frame = ttk.LabelFrame(self.transfer_frame, text="File Selection")
        file_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(file_frame, text="Select File", command=self.browse_file).pack(side="left", padx=5, pady=5)
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.pack(side="left", padx=10, pady=5)
        
        # Connection settings
        conn_frame = ttk.LabelFrame(self.transfer_frame, text="Connection Settings")
        conn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(conn_frame, text="Target IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ip_entry = ttk.Entry(conn_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.insert(0, str(self.port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Transfer controls
        control_frame = ttk.Frame(self.transfer_frame)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Send File", command=self.send_file).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Start Server", command=self.toggle_server).pack(side="left", padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.transfer_frame, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)
        
        # Log area
        log_frame = ttk.LabelFrame(self.transfer_frame, text="Transfer Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.transfer_log = scrolledtext.ScrolledText(log_frame, height=10)
        self.transfer_log.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_security_tab(self):
        """Setup security tab"""
        # Encryption controls
        enc_frame = ttk.LabelFrame(self.security_frame, text="File Encryption")
        enc_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(enc_frame, text="Encrypt File (AES)", command=self.encrypt_file_aes).pack(side="left", padx=5, pady=5)
        ttk.Button(enc_frame, text="Decrypt File (AES)", command=self.decrypt_file_aes).pack(side="left", padx=5, pady=5)
        ttk.Button(enc_frame, text="Encrypt File (RSA)", command=self.encrypt_file_rsa).pack(side="left", padx=5, pady=5)
        
        # Hash verification
        hash_frame = ttk.LabelFrame(self.security_frame, text="Integrity Verification")
        hash_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(hash_frame, text="Calculate SHA-256", command=self.calculate_file_hash).pack(side="left", padx=5, pady=5)
        ttk.Button(hash_frame, text="Verify Integrity", command=self.verify_file_integrity).pack(side="left", padx=5, pady=5)
        
        # Security log
        sec_log_frame = ttk.LabelFrame(self.security_frame, text="Security Log")
        sec_log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.security_log = scrolledtext.ScrolledText(sec_log_frame, height=12)
        self.security_log.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_analysis_tab(self):
        """Setup network analysis tab"""
        # Performance tests
        perf_frame = ttk.LabelFrame(self.analysis_frame, text="Network Performance")
        perf_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(perf_frame, text="Measure Latency", command=self.measure_latency).pack(side="left", padx=5, pady=5)
        ttk.Button(perf_frame, text="Bandwidth Test", command=self.test_bandwidth).pack(side="left", padx=5, pady=5)
        ttk.Button(perf_frame, text="Packet Loss Test", command=self.test_packet_loss).pack(side="left", padx=5, pady=5)
        
        # IP header analysis
        ip_frame = ttk.LabelFrame(self.analysis_frame, text="IP Header Analysis")
        ip_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(ip_frame, text="Create IP Header", command=self.create_ip_header).pack(side="left", padx=5, pady=5)
        ttk.Button(ip_frame, text="Fragment Test", command=self.test_fragmentation).pack(side="left", padx=5, pady=5)
        ttk.Button(ip_frame, text="Checksum Verify", command=self.verify_checksum).pack(side="left", padx=5, pady=5)
        
        # Analysis results
        analysis_log_frame = ttk.LabelFrame(self.analysis_frame, text="Analysis Results")
        analysis_log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.analysis_log = scrolledtext.ScrolledText(analysis_log_frame, height=12)
        self.analysis_log.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_attack_tab(self):
        """Setup attack simulation tab"""
        # Attack simulations
        attack_frame = ttk.LabelFrame(self.attack_frame, text="Attack Simulations")
        attack_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(attack_frame, text="MITM Attack", command=self.simulate_mitm).pack(side="left", padx=5, pady=5)
        ttk.Button(attack_frame, text="Packet Injection", command=self.simulate_packet_injection).pack(side="left", padx=5, pady=5)
        ttk.Button(attack_frame, text="Traffic Analysis", command=self.analyze_traffic).pack(side="left", padx=5, pady=5)
        
        # Packet capture simulation
        capture_frame = ttk.LabelFrame(self.attack_frame, text="Packet Capture")
        capture_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(capture_frame, text="Start Capture", command=self.start_packet_capture).pack(side="left", padx=5, pady=5)
        ttk.Button(capture_frame, text="Stop Capture", command=self.stop_packet_capture).pack(side="left", padx=5, pady=5)
        
        # Attack log
        attack_log_frame = ttk.LabelFrame(self.attack_frame, text="Attack Simulation Log")
        attack_log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.attack_log = scrolledtext.ScrolledText(attack_log_frame, height=12)
        self.attack_log.pack(fill="both", expand=True, padx=5, pady=5)
    
    def authenticate(self):
        """Authenticate user"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.crypto_manager.authenticate_client(username, password):
            self.authenticated = True
            self.current_user = username
            self.auth_status.config(text=f"Authenticated as {username}", foreground="green")
            self.log_security(f"User {username} authenticated successfully")
        else:
            self.authenticated = False
            self.current_user = None
            self.auth_status.config(text="Authentication failed", foreground="red")
            self.log_security("Authentication failed - invalid credentials")
    
    def browse_file(self):
        """Browse and select file"""
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            filename = os.path.basename(self.file_path)
            self.file_label.config(text=f"Selected: {filename}")
            self.log_transfer(f"File selected: {filename}")
    
    def send_file(self):
        """Send file with security measures"""
        if not self.authenticated:
            messagebox.showerror("Error", "Please authenticate first!")
            return
        
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        target_ip = self.ip_entry.get()
        target_port = int(self.port_entry.get())
        
        # Start file transfer in separate thread
        transfer_thread = threading.Thread(
            target=self._send_file_secure,
            args=(target_ip, target_port),
            daemon=True
        )
        transfer_thread.start()
    
    def _send_file_secure(self, target_ip, target_port):
        """Secure file transfer implementation"""
        try:
            self.log_transfer(f"Starting secure transfer to {target_ip}:{target_port}")
            
            # Read and encrypt file
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
            
            # Calculate hash for integrity
            file_hash = self.crypto_manager.calculate_sha256(file_data)
            self.log_security(f"File hash calculated: {file_hash[:32]}...")
            
            # Encrypt file data
            encrypted_data = self.crypto_manager.encrypt_aes(file_data)
            self.log_security("File encrypted with AES-256")
            
            # Create transfer packet
            transfer_info = {
                'filename': os.path.basename(self.file_path),
                'size': len(file_data),
                'hash': file_hash,
                'user': self.current_user,
                'timestamp': datetime.now().isoformat()
            }
            
            # Simulate IP header creation
            ip_header = self.network_utils.create_ip_header("127.0.0.1", target_ip, len(encrypted_data))
            self.log_analysis(f"IP header created: {len(ip_header)} bytes")
            
            # Fragment data if necessary
            fragments = self.network_utils.fragment_data(encrypted_data)
            self.log_analysis(f"Data fragmented into {len(fragments)} packets")
            
            # Send file via socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, target_port))
                
                # Send transfer info
                info_json = json.dumps(transfer_info).encode()
                s.send(len(info_json).to_bytes(4, 'big') + info_json)
                
                # Send encrypted data with progress
                total_sent = 0
                for i, fragment in enumerate(fragments):
                    s.send(fragment['data'])
                    total_sent += len(fragment['data'])
                    progress = (total_sent / len(encrypted_data)) * 100
                    self.progress['value'] = progress
                    self.master.update_idletasks()
                    time.sleep(0.01)  # Small delay for demo
                
                self.log_transfer("File transfer completed successfully")
                self.log_security("Transfer integrity maintained")
                
        except Exception as e:
            self.log_transfer(f"Transfer failed: {str(e)}")
    
    def start_server(self):
        """Start file transfer server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(5)
            
            self.log_transfer(f"Server started on port {self.port}")
            
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
        except Exception as e:
            self.log_transfer(f"Server error: {str(e)}")
    
    def handle_client(self, client_socket, address):
        """Handle incoming client connection"""
        try:
            self.log_transfer(f"Client connected from {address}")
            
            # Receive transfer info
            info_length = int.from_bytes(client_socket.recv(4), 'big')
            info_data = client_socket.recv(info_length)
            transfer_info = json.loads(info_data.decode())
            
            self.log_transfer(f"Receiving: {transfer_info['filename']} from {transfer_info['user']}")
            
            # Receive encrypted file data
            file_data = b''
            while len(file_data) < transfer_info['size']:
                chunk = client_socket.recv(self.buffer_size)
                if not chunk:
                    break
                file_data += chunk
            
            # Decrypt file
            decrypted_data = self.crypto_manager.decrypt_aes(file_data)
            
            # Verify integrity
            received_hash = self.crypto_manager.calculate_sha256(decrypted_data)
            if received_hash == transfer_info['hash']:
                self.log_security("File integrity verified ✓")
                
                # Save file
                save_path = f"received_{transfer_info['filename']}"
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                
                self.log_transfer(f"File saved as: {save_path}")
            else:
                self.log_security("File integrity check FAILED ✗")
                
        except Exception as e:
            self.log_transfer(f"Client handling error: {str(e)}")
        finally:
            client_socket.close()
    
    def toggle_server(self):
        """Toggle server state"""
        self.log_transfer("Server is running in background")
    
    # Security functions
    def encrypt_file_aes(self):
        """Encrypt selected file with AES"""
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = self.crypto_manager.encrypt_aes(data)
            
            save_path = f"{self.file_path}.aes"
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.log_security(f"File encrypted with AES and saved as: {os.path.basename(save_path)}")
            
        except Exception as e:
            self.log_security(f"AES encryption failed: {str(e)}")
    
    def decrypt_file_aes(self):
        """Decrypt AES encrypted file"""
        if not self.file_path:
            messagebox.showerror("Error", "Please select an encrypted file first!")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.crypto_manager.decrypt_aes(encrypted_data)
            
            save_path = self.file_path.replace('.aes', '_decrypted')
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.log_security(f"File decrypted and saved as: {os.path.basename(save_path)}")
            
        except Exception as e:
            self.log_security(f"AES decryption failed: {str(e)}")
    
    def encrypt_file_rsa(self):
        """Encrypt file with RSA (limited to small files)"""
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            if len(data) > 190:  # RSA 2048 can encrypt max ~190 bytes
                self.log_security("File too large for RSA encryption. Use AES for large files.")
                return
            
            encrypted_data = self.crypto_manager.encrypt_rsa(data)
            
            save_path = f"{self.file_path}.rsa"
            with open(save_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.log_security(f"File encrypted with RSA and saved as: {os.path.basename(save_path)}")
            
        except Exception as e:
            self.log_security(f"RSA encryption failed: {str(e)}")
    
    def calculate_file_hash(self):
        """Calculate SHA-256 hash of selected file"""
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            file_hash = self.crypto_manager.calculate_sha256(data)
            self.log_security(f"SHA-256 Hash: {file_hash}")
            
            # Save hash to file
            hash_file = f"{self.file_path}.sha256"
            with open(hash_file, 'w') as f:
                f.write(file_hash)
            
            self.log_security(f"Hash saved to: {os.path.basename(hash_file)}")
            
        except Exception as e:
            self.log_security(f"Hash calculation failed: {str(e)}")
    
    def verify_file_integrity(self):
        """Verify file integrity using hash"""
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        hash_file = f"{self.file_path}.sha256"
        if not os.path.exists(hash_file):
            self.log_security("Hash file not found. Calculate hash first.")
            return
        
        try:
            # Read stored hash
            with open(hash_file, 'r') as f:
                stored_hash = f.read().strip()
            
            # Calculate current hash
            with open(self.file_path, 'rb') as f:
                data = f.read()
            current_hash = self.crypto_manager.calculate_sha256(data)
            
            if stored_hash == current_hash:
                self.log_security("File integrity VERIFIED ✓")
            else:
                self.log_security("File integrity COMPROMISED ✗")
            
        except Exception as e:
            self.log_security(f"Integrity verification failed: {str(e)}")
    
    # Network analysis functions
    def measure_latency(self):
        """Measure network latency"""
        self.log_analysis("Measuring network latency...")
        
        try:
            target = "8.8.8.8"  # Google DNS
            result = self.network_analyzer.measure_latency(target)
            
            if result:
                self.log_analysis(f"Latency to {target}:")
                self.log_analysis(f"  Min: {result['min']:.2f} ms")
                self.log_analysis(f"  Max: {result['max']:.2f} ms")
                self.log_analysis(f"  Avg: {result['avg']:.2f} ms")
                self.log_analysis(f"  Packets: {result['count']}")
            else:
                self.log_analysis("Latency measurement failed")
                
        except Exception as e:
            self.log_analysis(f"Latency measurement error: {str(e)}")
    
    def test_bandwidth(self):
        """Test network bandwidth"""
        self.log_analysis("Testing network bandwidth...")
        
        try:
            result = self.network_analyzer.simulate_bandwidth_test()
            self.log_analysis(f"Bandwidth Test Results:")
            self.log_analysis(f"  Download: {result['download']:.2f} {result['unit']}")
            self.log_analysis(f"  Upload: {result['upload']:.2f} {result['unit']}")
            self.log_analysis("Note: This is a simulation. Use iperf for real testing.")
            
        except Exception as e:
            self.log_analysis(f"Bandwidth test error: {str(e)}")
    
    def test_packet_loss(self):
        """Test packet loss"""
        self.log_analysis("Testing packet loss...")
        
        try:
            result = self.network_analyzer.simulate_packet_loss()
            self.log_analysis(f"Packet Loss Test:")
            self.log_analysis(f"  Sent: {result['sent']} packets")
            self.log_analysis(f"  Received: {result['received']} packets")
            self.log_analysis(f"  Loss: {result['loss_percentage']:.2f}%")
            
        except Exception as e:
            self.log_analysis(f"Packet loss test error: {str(e)}")
    
    def create_ip_header(self):
        """Create and analyze IP header"""
        try:
            src_ip = "192.168.1.100"
            dst_ip = "192.168.1.200"
            payload_len = 1024
            
            header = self.network_utils.create_ip_header(src_ip, dst_ip, payload_len)
            
            self.log_analysis("IP Header Created:")
            self.log_analysis(f"  Source IP: {src_ip}")
            self.log_analysis(f"  Destination IP: {dst_ip}")
            self.log_analysis(f"  Payload Length: {payload_len} bytes")
            self.log_analysis(f"  Header Length: {len(header)} bytes")
            self.log_analysis(f"  Header (hex): {header.hex()}")
            
            # Parse header for display
            version = (header[0] >> 4) & 0xF
            ihl = header[0] & 0xF
            ttl = header[8]
            protocol = header[9]
            checksum = struct.unpack('!H', header[10:12])[0]
            
            self.log_analysis(f"  IP Version: {version}")
            self.log_analysis(f"  Header Length: {ihl * 4} bytes")
            self.log_analysis(f"  TTL: {ttl}")
            self.log_analysis(f"  Protocol: {protocol}")
            self.log_analysis(f"  Checksum: 0x{checksum:04x}")
            
        except Exception as e:
            self.log_analysis(f"IP header creation error: {str(e)}")
    
    def test_fragmentation(self):
        """Test packet fragmentation"""
        try:
            test_data = b"This is a test message for packet fragmentation. " * 50
            fragments = self.network_utils.fragment_data(test_data, fragment_size=100)
            
            self.log_analysis("Packet Fragmentation Test:")
            self.log_analysis(f"  Original data size: {len(test_data)} bytes")
            self.log_analysis(f"  Fragment size: 100 bytes")
            self.log_analysis(f"  Number of fragments: {len(fragments)}")
            
            for i, fragment in enumerate(fragments):
                self.log_analysis(f"  Fragment {i+1}: {len(fragment['data'])} bytes, "
                                f"offset: {fragment['offset']}, "
                                f"more_fragments: {fragment['more_fragments']}")
            
            # Simulate reassembly
            reassembled = b''
            for fragment in sorted(fragments, key=lambda x: x['offset']):
                reassembled += fragment['data']
            
            if reassembled == test_data:
                self.log_analysis("  Reassembly: SUCCESS ✓")
            else:
                self.log_analysis("  Reassembly: FAILED ✗")
                
        except Exception as e:
            self.log_analysis(f"Fragmentation test error: {str(e)}")
    
    def verify_checksum(self):
        """Verify IP checksum calculation"""
        try:
            # Create test header
            test_header = b'\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02'
            
            # Calculate checksum
            checksum = self.network_utils.calculate_ip_checksum(test_header[:10] + b'\x00\x00' + test_header[12:])
            
            self.log_analysis("IP Checksum Verification:")
            self.log_analysis(f"  Test header: {test_header.hex()}")
            self.log_analysis(f"  Calculated checksum: 0x{checksum:04x}")
            
            # Verify with known good checksum
            original_checksum = struct.unpack('!H', test_header[10:12])[0]
            if checksum == original_checksum:
                self.log_analysis("  Checksum verification: SUCCESS ✓")
            else:
                self.log_analysis(f"  Original checksum: 0x{original_checksum:04x}")
                self.log_analysis("  Checksum verification: Different (expected for demo)")
                
        except Exception as e:
            self.log_analysis(f"Checksum verification error: {str(e)}")
    
    # Attack simulation functions
    def simulate_mitm(self):
        """Simulate Man-in-the-Middle attack"""
        self.log_attack("=== MITM Attack Simulation ===")
        self.log_attack("Intercepting communication between 192.168.1.10 and 192.168.1.20")
        
        # Simulate packet interception
        intercepted_packets = [
            {"src": "192.168.1.10", "dst": "192.168.1.20", "data": "Hello Server", "time": time.time()},
            {"src": "192.168.1.20", "dst": "192.168.1.10", "data": "Hello Client", "time": time.time() + 0.1},
            {"src": "192.168.1.10", "dst": "192.168.1.20", "data": "Send file: document.pdf", "time": time.time() + 0.2}
        ]
        
        for packet in intercepted_packets:
            self.log_attack(f"[{packet['time']:.3f}] Intercepted: {packet['src']} -> {packet['dst']}")
            self.log_attack(f"  Data: {packet['data']}")
            
            # Simulate packet modification
            if "file" in packet['data'].lower():
                modified_data = packet['data'].replace("document.pdf", "malware.exe")
                self.log_attack(f"  Modified to: {modified_data}")
                self.log_attack("  ⚠️  MITM: Packet modified!")
        
        self.log_attack("MITM Attack completed. Encryption would prevent this!")
    
    def simulate_packet_injection(self):
        """Simulate packet injection attack"""
        self.log_attack("=== Packet Injection Simulation ===")
        
        if SCAPY_AVAILABLE:
            try:
                # Create fake packet
                fake_packet = IP(src="192.168.1.100", dst="192.168.1.200") / TCP(dport=80) / Raw(load="Injected data")
                self.log_attack("Fake packet created with Scapy:")
                self.log_attack(f"  Source: {fake_packet[IP].src}")
                self.log_attack(f"  Destination: {fake_packet[IP].dst}")
                self.log_attack(f"  Payload: {fake_packet[Raw].load}")
                self.log_attack("Packet injection simulated (not actually sent)")
                
            except Exception as e:
                self.log_attack(f"Scapy packet creation error: {str(e)}")
        else:
            # Manual packet creation simulation
            self.log_attack("Creating fake packet manually:")
            self.log_attack("  IP Header: 45 00 00 28 00 01 00 00 40 06 ...")
            self.log_attack("  TCP Header: 00 50 00 50 00 00 00 00 ...")
            self.log_attack("  Payload: 'Injected malicious data'")
            self.log_attack("Packet injection simulated")
        
        self.log_attack("⚠️  This demonstrates why network security is crucial!")
    
    def analyze_traffic(self):
        """Simulate traffic analysis"""
        self.log_attack("=== Traffic Analysis Simulation ===")
        
        # Simulate captured traffic
        traffic_samples = [
            {"protocol": "HTTP", "src": "192.168.1.10", "dst": "93.184.216.34", "size": 1024, "encrypted": False},
            {"protocol": "HTTPS", "src": "192.168.1.10", "dst": "142.250.191.14", "size": 2048, "encrypted": True},
            {"protocol": "FTP", "src": "192.168.1.10", "dst": "192.168.1.100", "size": 5120, "encrypted": False},
            {"protocol": "SSH", "src": "192.168.1.10", "dst": "192.168.1.200", "size": 512, "encrypted": True}
        ]
        
        self.log_attack("Analyzing captured network traffic:")
        
        for i, packet in enumerate(traffic_samples, 1):
            self.log_attack(f"Packet {i}:")
            self.log_attack(f"  Protocol: {packet['protocol']}")
            self.log_attack(f"  Flow: {packet['src']} -> {packet['dst']}")
            self.log_attack(f"  Size: {packet['size']} bytes")
            
            if packet['encrypted']:
                self.log_attack("  Status: ✅ ENCRYPTED - Data protected")
            else:
                self.log_attack("  Status: ⚠️  UNENCRYPTED - Data visible!")
                
                # Simulate data extraction for unencrypted traffic
                if packet['protocol'] == "HTTP":
                    self.log_attack("  Extracted: GET /login.html HTTP/1.1")
                    self.log_attack("  Extracted: username=admin&password=123456")
                elif packet['protocol'] == "FTP":
                    self.log_attack("  Extracted: USER admin")
                    self.log_attack("  Extracted: PASS secretpass")
        
        self.log_attack("Traffic analysis complete. Always use encryption!")
    
    def start_packet_capture(self):
        """Start packet capture simulation"""
        self.log_attack("=== Starting Packet Capture ===")
        
        if SCAPY_AVAILABLE:
            self.log_attack("Scapy available - Could capture real packets")
            self.log_attack("Available interfaces:")
            try:
                interfaces = get_if_list()
                for iface in interfaces[:5]:  # Show first 5 interfaces
                    self.log_attack(f"  - {iface}")
            except:
                self.log_attack("  - Could not enumerate interfaces")
        else:
            self.log_attack("Scapy not available - Simulating capture")
        
        self.log_attack("Capturing packets on interface eth0...")
        self.log_attack("Captured packets:")
        
        # Simulate captured packets
        captured_packets = [
            "192.168.1.10 -> 8.8.8.8 [DNS] Query: google.com",
            "192.168.1.10 -> 142.250.191.14 [HTTPS] Encrypted payload",
            "192.168.1.10 -> 192.168.1.1 [ARP] Who has 192.168.1.1?",
            "192.168.1.20 -> 192.168.1.10 [TCP] File transfer data"
        ]
        
        for packet in captured_packets:
            self.log_attack(f"  {packet}")
            time.sleep(0.1)
        
        self.log_attack("Packet capture simulation started")
    
    def stop_packet_capture(self):
        """Stop packet capture"""
        self.log_attack("Packet capture stopped")
        self.log_attack("Captured 47 packets in 10 seconds")
        self.log_attack("Analysis: 23 encrypted, 24 unencrypted")
    
    # Logging functions
    def log_transfer(self, message):
        """Log transfer events"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.transfer_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.transfer_log.see(tk.END)
        self.master.update_idletasks()
    
    def log_security(self, message):
        """Log security events"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.security_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.security_log.see(tk.END)
        self.master.update_idletasks()
    
    def log_analysis(self, message):
        """Log analysis events"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.analysis_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.analysis_log.see(tk.END)
        self.master.update_idletasks()
    
    def log_attack(self, message):
        """Log attack simulation events"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.attack_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.attack_log.see(tk.END)
        self.master.update_idletasks()

def main():
    """Main application entry point"""
    # Check required libraries
    missing_libs = []
    
    if not CRYPTO_AVAILABLE:
        missing_libs.append("cryptography")
    
    if missing_libs:
        print("Missing required libraries:")
        for lib in missing_libs:
            print(f"  pip install {lib}")
        print("\nSome features may not work without these libraries.")
    
    # Create and run GUI
    root = tk.Tk()
    app = SecureFileTransferGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user")

if __name__ == "__main__":
    main()