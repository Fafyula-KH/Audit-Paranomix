🎯 AuditSysteme_Paranomix - Outil d'Audit Sécurité Windows 🛡️

📌 Présentation

AuditSysteme_Paranomix est un outil avancé d'audit de sécurité pour Windows.

Il analyse en profondeur votre système afin de détecter :

🦠 Signes de compromission
🧬 Présence potentielle de malwares
⚠️ Anomalies système
🔐 Mécanismes de persistance
🌐 Activités réseau suspectes

L'objectif est de fournir un diagnostic rapide, compréhensible et transparent pour aider l'utilisateur à identifier les éléments nécessitant une vérification.

⚠️ AuditSysteme_Paranomix ne remplace pas un antivirus ou un EDR professionnel.

Il s'agit d'un outil de triage sécurité permettant de détecter des indicateurs suspects et d'orienter une analyse plus approfondie.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔐 Vérification d'intégrité SHA-256

Avant d'exécuter le programme, vous pouvez vérifier son authenticité grâce à son empreinte SHA-256 :

A711182F99BEE6032270F1CAED7F817F0B497A0ED67A635F8C8FC065A910E34C

❌ Si le hash ne correspond pas :

🚫 Ne lancez pas le fichier.
📩 Signalez immédiatement le fichier concerné.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✨ Fonctionnalités principales

🌐 Connexions réseau
Détection d'IPs malveillantes, domaines suspects et reverse DNS.

🔄 Processus
Analyse des noms suspects, techniques de masquerade et anomalies parent-enfant.

🚪 Ports écoutés
Détection des ports suspects (4444, 6667, 31337, etc.).

📅 Tâches planifiées
Surveillance des nouvelles tâches, modifications et actions COM.

🌍 DNS
Détection des détournements de résolution DNS.

📁 Fichiers temporaires
Analyse des exécutables présents dans les dossiers TEMP.

📄 Fichier HOSTS
Détection des détournements de domaines.

🗄️ Registre Windows
Analyse des mécanismes de persistance :
Run, Winlogon, AppInit_DLLs, IFEO, Services.

🛡️ Antivirus / Pare-feu
Vérification de l'état de protection Windows et des solutions tierces.

🔏 Signatures numériques
Vérification des signatures des exécutables importants.

🧠 Analyse mémoire
Détection d'injection de code et de shellcode.

🔗 Abonnements WMI
Détection de persistance fileless.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Système de verdict

AuditSysteme_Paranomix utilise un système de score basé sur plusieurs indicateurs.

🔴 POTENTIELLEMENT INFECTÉ

Condition :

3+ alertes fortes détectées.

➡️ Plusieurs indicateurs sérieux ont été détectés et nécessitent une investigation approfondie.

🟠 SUSPECT

Condition :

1-2 alertes fortes détectées.

➡️ Des éléments inhabituels ont été détectés et doivent être vérifiés manuellement.

🟢 VISIBLEMENT SAIN

Conditions :

Score ≥ 3 sans alerte forte

ou

Score < 3

➡️ Aucun signe majeur de compromission détecté.

⚠️ Un verdict sain ne garantit jamais une absence totale de menace. Aucun outil automatisé ne peut remplacer une analyse complète.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 Utilisation

▶️ Audit normal :

AuditSysteme_Paranomix.exe

🔄 Mise à jour forcée de la base Threat Intelligence :

AuditSysteme_Paranomix.exe --update

🚫 Audit sans mise à jour réseau :

AuditSysteme_Paranomix.exe --no-update

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Rapport généré

Après l'analyse, AuditSysteme_Paranomix génère automatiquement un rapport détaillé sur votre Bureau :

Rapport d'audit N°X.txt

Le rapport peut contenir :

🌐 IP contactées
📦 Logiciels installés
🗂️ Informations registre
⏰ Tâches planifiées
🔍 Indicateurs détectés

⚠️ Avant de partager un rapport, pensez à masquer les informations sensibles.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌍 Base Threat Intelligence

AuditSysteme_Paranomix utilise plusieurs sources publiques de renseignement sur les menaces :

🦠 Feodo Tracker
Détection d'adresses IP liées aux botnets.

🚨 Spamhaus DROP / eDROP
Listes de plages IP associées à des infrastructures malveillantes.

🔗 URLhaus
Détection de domaines utilisés pour distribuer des malwares.

🔄 La base est mise à jour automatiquement toutes les 24 heures si une connexion Internet est disponible.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧠 Techniques de détection avancées

AuditSysteme_Paranomix utilise plusieurs techniques inspirées de MITRE ATT&CK :

🎭 Masquerade de processus
MITRE ATT&CK T1036.005

Détection des processus tentant d'imiter des composants Windows légitimes.

👨‍👦 Anomalies parent-enfant

Exemples :

Microsoft Office → PowerShell

Navigateur → Shell système

Détection des chaînes d'exécution inhabituelles.

🧬 Analyse mémoire ciblée

Recherche :

- Régions mémoire exécutables privées
- Injection de code
- Shellcode potentiel

🔗 Résolution COM

Analyse :

- Actions ComHandler
- Mécanismes COM suspects

👻 Persistance WMI Fileless

MITRE ATT&CK T1546.003

Détection des techniques de persistance sans fichier utilisant WMI.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔐 Sécurité et confidentialité

❓ Est-ce que mes données quittent ma machine ?

❌ Non.

AuditSysteme_Paranomix fonctionne principalement en local.

Le rapport généré reste enregistré sur votre ordinateur.

Les seules communications externes concernent la mise à jour des bases Threat Intelligence :

🦠 Feodo Tracker
🚨 Spamhaus
🔗 URLhaus

Aucune donnée personnelle n'est envoyée dans ces requêtes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️ Pourquoi Windows Defender peut-il réagir ?

Certains antivirus peuvent détecter un faux positif, notamment avec les exécutables générés avec :

PyInstaller

Cela peut être lié à la structure du programme compilé et non forcément à un comportement malveillant.

Si cela arrive :

✅ Vérifiez le SHA-256
✅ Consultez le code source
✅ Compilez votre propre version
✅ Signalez un faux positif

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

👨‍💻 Vérification du code source

Le projet reste transparent :

🐍 Python
💻 PowerShell

Les utilisateurs avancés peuvent :

✅ Lire le code source
✅ Vérifier le fonctionnement
✅ Compiler leur propre version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🖥️ Lancement recommandé

Pour un audit complet :

➡️ Clic droit sur AuditSysteme_Paranomix.exe
➡️ Sélectionner "Exécuter en tant qu'administrateur"

Sans privilèges administrateur, certaines informations peuvent être incomplètes :

⏰ Tâches planifiées
🗂️ Certaines clés registre
🛡️ Informations Defender
🔥 Configuration pare-feu

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Prérequis

💻 Systèmes compatibles : Windows

🔑 Droits :
Administrateur recommandé

💾 Espace disque :
Environ 50 MB

📦 Dépendances :
Intégrées dans l'exécutable

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

👨‍💻 Auteurs :

🐍 Moteur original Python :
Fafyula

💻 Portage PowerShell :
Fafyula

🔗 GitHub :
https://github.com/Fafyula-KH/Audit-Paranomix
