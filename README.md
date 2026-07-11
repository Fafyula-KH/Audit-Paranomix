🎯 AuditSysteme - Outil d'Audit Sécurité Windows
📌 Présentation
AuditSysteme est un outil d'audit de sécurité avancé pour Windows. Il analyse en profondeur votre système pour détecter des signes de compromission, des malwares ou des vulnérabilités, tout en restant accessible et rassurant pour l'utilisateur.

SHA256          3BDAFD79C5D482B95CFBD17DB6D4822A551FC0CEBA391121B46F70A95A480B58

✨ Fonctionnalités
Section	Description
🌐 Connexions réseau	Détection d'IPs malveillantes, domaines suspects, reverse DNS
🔄 Processus	Analyse des noms suspects, masquerade, anomalies parent-enfant
🚪 Ports écoutés	Détection des ports suspects (4444, 6667, 31337, etc.)
📅 Tâches planifiées	Surveillance des nouvelles tâches, modifications, actions COM
🌍 DNS	Détection de détournement de résolution DNS
📁 Fichiers temporaires	Analyse des exécutables dans TEMP
📄 Fichier hosts	Détection de détournements de domaine
🗄️ Registre	Persistance (Run, Winlogon, AppInit_DLLs, IFEO, Services)
🛡️ Antivirus / Pare-feu	État de protection, signatures, produits tiers
🔏 Signatures numériques	Vérification des binaires de démarrage
🧠 Analyse mémoire	Détection d'injection de code / shellcode
🔗 Abonnements WMI	Détection de persistance fileless
🎯 Verdict final
Condition	Verdict
3+ alertes fortes	🔴 Ce PC est INFECTÉ
1-2 alertes fortes	🟠 Ce PC est SUSPECT
Score ≥ 3 (sans alerte forte)	🟢 PC visiblement SAIN, points à vérifier
Score < 3	🟢 Ce PC est SAIN
🔧 Utilisation
bash
# Audit normal
AuditSysteme.exe

# Mise à jour de la base Threat Intel
AuditSysteme.exe --update

# Audit sans mise à jour
AuditSysteme.exe --no-update
L'audit génère un rapport détaillé sur votre Bureau : Rapport d'audit N°X.txt

🛡️ Base Threat Intel
Le logiciel utilise des listes de malwares à jour :

Feodo Tracker - IPs de botnets

Spamhaus DROP/eDROP - Plages IPs malveillantes

URLhaus - Domaines malveillants

Mise à jour automatique toutes les 24h (si connexion internet).

🧠 Techniques de détection avancées
Masquerade de processus (MITRE ATT&CK T1036.005)

Anomalies parent-enfant (ex: Office → shell)

Analyse mémoire ciblée (régions exécutables privées)

Résolution COM (actions ComHandler)

Persistance WMI fileless (MITRE T1546.003)

📋 Prérequis
Système : Windows 7 / 8 / 10 / 11

Droits : Administrateur recommandé

Espace : ~50 MB

Dépendances : Intégrées dans l'exécutable
