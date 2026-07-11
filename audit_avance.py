"""
AUDIT SYSTEME AVANCE - avec Threat Intel, diff Tâches Planifiées, AV/Pare-feu
Auteur : Fafyula
GitHub : https://github.com/Fafyula-KH
"""

import os
import sys
import re
import json
import hashlib
import ipaddress
import psutil
import subprocess
import socket
import datetime
import platform
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

AUTEUR = "Fafyula"
GITHUB_URL = "https://github.com/Fafyula-KH"
VERSION = "1.7 (ComHandler, WMI persistence, anomalies parent-enfant, analyse mémoire ciblée)"

# --- Résolution du dossier de base : à côté du .py OU du .exe compilé ---
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

REPORT = []
SCORE = 0
ALERTES = []
ALERTES_FORTES = []  # indicateurs forts de compromission
CHEMINS_SIGNATURE = []

SEUIL_CONNEXIONS_SUSPECTES = 15
PORTS_SUSPECTS = [4444, 6667, 31337, 5555, 12345, 1337]
PROCESSUS_SUSPECTS = ["mimikatz", "nc.exe", "plink.exe", "putty.exe",
                      "cobaltstrike", "beacon", "meterpreter", "empire"]

THREAT_INTEL_PATH = BASE_DIR / "threat_intel.json"
SEUIL_MAJ_HEURES = 24
TASKS_BASELINE_PATH = BASE_DIR / "taches_baseline.json"

# ==========================================
# THREAT INTEL - chargement, fusion manual/auto, mise à jour
# ==========================================

SOURCES_TI = {
    "feodotracker_ips": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "urlhaus_hosts": "https://urlhaus.abuse.ch/downloads/hostfile/",
}
HEADERS_TI = {"User-Agent": "Mozilla/5.0 (compatible; local-security-audit/1.0)"}

DEFAUT_TI = {
    "manual": {"malicious_ips": [], "malicious_ip_ranges": [], "malicious_domains": []},
    "auto": {"last_update": None, "sources": {}, "malicious_ips": [], "malicious_ip_ranges": [], "malicious_domains": []},
    "dynamic_dns_domains": [
        "duckdns.org", "no-ip.com", "no-ip.org", "noip.com", "ddns.net",
        "hopto.org", "zapto.org", "sytes.net", "changeip.com",
        "freedynamicdns.org", "myftp.org", "servebeer.com", "servehttp.com",
        "dynu.com", "dnsdynamic.org"
    ],
    "high_risk_tlds": [".zip", ".mov", ".top", ".xyz", ".club", ".work",
                       ".gq", ".tk", ".ml", ".cf", ".ga", ".icu", ".rest"],
    "suspicious_process_strings": [
        "-enc ", "-encodedcommand", "-e ", "iex(", "iex (",
        "downloadstring", "invoke-expression", "frombase64string",
        "mshta http", "rundll32.exe javascript", "certutil -urlcache",
        "certutil -decode", "bitsadmin /transfer"
    ],
    "suspicious_path_fragments": [
        "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\public\\",
        "\\users\\public\\", "\\windows\\temp\\"
    ],
    "chemins_fiables_ignores": [
        "\\programdata\\microsoft\\windows defender\\",
        "\\program files\\windows defender\\",
        "\\program files (x86)\\windows defender\\"
    ]
}


def _fetch_text(url, timeout=20):
    req = Request(url, headers=HEADERS_TI)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _parse_ip_list(text):
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        try:
            ipaddress.ip_address(line)
            ips.append(line)
        except ValueError:
            continue
    return ips


def _parse_cidr_list(text):
    ranges = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        cidr = line.split(";")[0].strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
            ranges.append(cidr)
        except ValueError:
            continue
    return ranges


def _parse_hostfile_domains(text):
    domains = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            d = parts[1].strip().lower()
            if d and d != "localhost":
                domains.append(d)
    return domains


def charger_threat_intel():
    if not THREAT_INTEL_PATH.exists():
        with open(THREAT_INTEL_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAUT_TI, f, indent=2, ensure_ascii=False)
        print(f"ℹ️  threat_intel.json créé avec les valeurs par défaut ({THREAT_INTEL_PATH}).")

    with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    for cle, val in DEFAUT_TI.items():
        data.setdefault(cle, val)

    data["suspicious_path_fragments"] = [
        p for p in data.get("suspicious_path_fragments", []) if p.lower() != "\\programdata\\"
    ]

    manual = data.get("manual", {})
    auto = data.get("auto", {})
    data["malicious_ips"] = list(set(manual.get("malicious_ips", []) + auto.get("malicious_ips", [])))
    data["malicious_ip_ranges"] = list(set(manual.get("malicious_ip_ranges", []) + auto.get("malicious_ip_ranges", [])))
    data["malicious_domains"] = list(set(manual.get("malicious_domains", []) + auto.get("malicious_domains", [])))

    last_update = auto.get("last_update")
    if not last_update:
        print("ℹ️  Base auto jamais mise à jour. Lance le programme avec l'option --update pour la remplir.")
    else:
        try:
            dt = datetime.datetime.fromisoformat(last_update)
            age_jours = (datetime.datetime.now() - dt).days
            if age_jours > 14:
                print(f"⚠️  Base threat intel auto vieille de {age_jours} jours — pense à lancer --update.")
        except ValueError:
            pass

    return data


def mettre_a_jour_threat_intel():
    if not THREAT_INTEL_PATH.exists():
        charger_threat_intel()
    with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("auto", dict(DEFAUT_TI["auto"]))

    tous_ips, tous_ranges, tous_domaines = set(), set(), set()
    resultats, erreurs = {}, []

    print("Mise à jour de la threat intel en cours...\n")

    try:
        ips = _parse_ip_list(_fetch_text(SOURCES_TI["feodotracker_ips"]))
        tous_ips.update(ips)
        resultats["feodotracker_ips"] = len(ips)
        print(f"  ✅ Feodo Tracker : {len(ips)} IP")
    except Exception as e:
        erreurs.append(f"feodotracker_ips: {e}")
        print(f"  ❌ Feodo Tracker : échec ({e})")

    for key in ("spamhaus_drop", "spamhaus_edrop"):
        try:
            ranges = _parse_cidr_list(_fetch_text(SOURCES_TI[key]))
            tous_ranges.update(ranges)
            resultats[key] = len(ranges)
            print(f"  ✅ {key} : {len(ranges)} ranges")
        except Exception as e:
            erreurs.append(f"{key}: {e}")
            print(f"  ❌ {key} : échec ({e})")

    try:
        domaines = _parse_hostfile_domains(_fetch_text(SOURCES_TI["urlhaus_hosts"]))
        tous_domaines.update(domaines)
        resultats["urlhaus_hosts"] = len(domaines)
        print(f"  ✅ URLhaus : {len(domaines)} domaines")
    except Exception as e:
        erreurs.append(f"urlhaus_hosts: {e}")
        print(f"  ❌ URLhaus : échec ({e})")

    if not resultats:
        print("\n⚠️ Aucune source contactable (pas de réseau ?). Base inchangée.")
        return False

    data["auto"]["malicious_ips"] = sorted(tous_ips)
    data["auto"]["malicious_ip_ranges"] = sorted(tous_ranges)
    data["auto"]["malicious_domains"] = sorted(tous_domaines)
    data["auto"]["last_update"] = datetime.datetime.now().isoformat(timespec="seconds")
    data["auto"]["sources"] = resultats
    if erreurs:
        data["auto"]["sources"]["_erreurs"] = erreurs

    with open(THREAT_INTEL_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    total = len(tous_ips) + len(tous_ranges) + len(tous_domaines)
    print(f"\n✅ Base mise à jour : {total} IOC au total.")
    if erreurs:
        print(f"⚠️ {len(erreurs)} source(s) en échec.")
    return True


TI = charger_threat_intel()


def verifier_connexion_internet(timeout=3):
    for hote in ("1.1.1.1", "8.8.8.8"):
        try:
            socket.create_connection((hote, 53), timeout=timeout)
            return True
        except Exception:
            continue
    return False


def verifier_et_maj_threat_intel_si_necessaire(no_update=False):
    global TI
    auto = TI.get("auto", {})
    last_update = auto.get("last_update")
    age_heures = None
    if last_update:
        try:
            dt = datetime.datetime.fromisoformat(last_update)
            age_heures = (datetime.datetime.now() - dt).total_seconds() / 3600
        except ValueError:
            pass

    if no_update:
        if age_heures is not None:
            return f"Mise à jour désactivée (--no-update). Base utilisée datée d'il y a {age_heures:.0f}h."
        return "Mise à jour désactivée (--no-update). Aucune base auto n'a jamais été téléchargée (0 IOC)."

    if age_heures is not None and age_heures < SEUIL_MAJ_HEURES:
        return f"Base threat intel à jour (dernière mise à jour il y a {age_heures:.0f}h, seuil {SEUIL_MAJ_HEURES}h) — pas de nouvelle tentative."

    print("Base threat intel périmée ou absente, tentative de mise à jour avant l'audit...")
    reference = f" (dernière base connue datée du {last_update})" if last_update else " (aucune base n'a jamais été téléchargée avec succès — 0 IOC)"

    if not verifier_connexion_internet():
        return (f"⚠️ AUDIT REALISE SANS CONNEXION INTERNET DETECTEE — la base threat intel n'a pas pu "
                f"être mise à jour.{reference}. Résultats basés sur cette base existante.")

    succes = mettre_a_jour_threat_intel()
    TI = charger_threat_intel()
    if succes:
        return "✅ Base threat intel mise à jour automatiquement avant cet audit."
    return (f"⚠️ Connexion internet détectée mais la mise à jour a échoué pour toutes les sources "
            f"(pare-feu/proxy bloquant abuse.ch ou spamhaus.org ?).{reference}. Résultats basés sur cette base existante.")

# ==========================================
# UTILITAIRES DE COMPARAISON
# ==========================================

def ip_dans_ranges(ip, ranges):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def domaine_suspect(domaine):
    if not domaine:
        return None
    d = domaine.lower()
    for m in TI.get("malicious_domains", []):
        if m.lower() in d:
            return f"domaine connu malveillant ({m})"
    for dd in TI.get("dynamic_dns_domains", []):
        if d.endswith(dd.lower()):
            return f"dynamic DNS souvent abusé pour C2 ({dd})"
    for tld in TI.get("high_risk_tlds", []):
        if d.endswith(tld.lower()):
            return f"TLD à risque élevé ({tld})"
    return None


def resoudre_reverse_dns(ip, timeout=0.8):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def contient_pattern_suspect(texte, patterns):
    if not texte:
        return None
    t = texte.lower()
    for p in patterns:
        if p.lower() in t:
            return p
    return None


def chemin_est_fiable(texte):
    if not texte:
        return False
    t = texte.lower()
    for frag in TI.get("chemins_fiables_ignores", []):
        if frag.lower() in t:
            return True
    return False


def nom_processus_suspect(nom_process):
    n = nom_process.lower()
    for suspect in PROCESSUS_SUSPECTS:
        s = suspect.lower()
        pattern = r'(?<![a-z0-9])' + re.escape(s) + r'(?![a-z0-9])'
        if re.search(pattern, n):
            return suspect
    return None


def nom_aleatoire(nom):
    base = Path(nom).stem
    if len(base) < 10:
        return False
    lettres = [c for c in base.lower() if c.isalpha()]
    if len(lettres) < 6:
        return False
    voyelles = sum(1 for c in lettres if c in "aeiouy")
    ratio = voyelles / len(lettres)
    a_chiffres = any(c.isdigit() for c in base)
    return ratio < 0.2 and (a_chiffres or len(base) > 16)


def get_powershell_json(cmd, timeout=15):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def extraire_chemin_exe(commande):
    if not commande:
        return None
    c = commande.strip()
    if c.startswith('"'):
        fin = c.find('"', 1)
        return c[1:fin] if fin != -1 else None
    m = re.match(r'(.+?\.(?:exe|dll|sys))(?:\s|$)', c, re.IGNORECASE)
    if m:
        return m.group(1)
    parts = c.split()
    return parts[0] if parts else None


def noter_chemin_pour_signature(commande):
    chemin = extraire_chemin_exe(commande)
    if chemin and chemin.lower().endswith((".exe", ".dll", ".sys")):
        CHEMINS_SIGNATURE.append(chemin)


def decoder_product_state(state):
    try:
        state = int(state)
    except (TypeError, ValueError):
        return None, None
    hex_state = format(state, "06x")
    milieu = hex_state[2:4]
    fin = hex_state[4:6]
    actif = milieu in ("11", "21", "01")
    a_jour = fin == "00"
    return actif, a_jour

# ==========================================
# TACHES PLANIFIEES - lecture directe + diff baseline
# ==========================================

def parse_task_xml(contenu):
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(contenu)
    except ET.ParseError:
        return {"author": None, "hidden": False, "runlevel": None, "commands": [], "com_class_ids": []}

    def strip_ns(tag):
        return tag.split("}")[-1] if "}" in tag else tag

    result = {"author": None, "hidden": False, "runlevel": None, "commands": [], "com_class_ids": []}
    for elem in root.iter():
        tag = strip_ns(elem.tag)
        if tag == "Author" and elem.text:
            result["author"] = elem.text.strip()
        elif tag == "Hidden" and elem.text:
            result["hidden"] = elem.text.strip().lower() == "true"
        elif tag == "RunLevel" and elem.text:
            result["runlevel"] = elem.text.strip()
        elif tag in ("Command", "Arguments") and elem.text:
            result["commands"].append(elem.text.strip())
        elif tag == "ClassId" and elem.text:
            result["com_class_ids"].append(elem.text.strip())
    return result


def scanner_taches_planifiees():
    tasks_dir = Path("C:/Windows/System32/Tasks")
    snapshot = {}
    if not tasks_dir.exists():
        return snapshot, 0
    erreurs_lecture = 0
    for root, _, files in os.walk(tasks_dir):
        for fname in files:
            fpath = Path(root) / fname
            try:
                rel = str(fpath.relative_to(tasks_dir))
            except ValueError:
                continue
            try:
                raw = fpath.read_bytes()
            except Exception:
                erreurs_lecture += 1
                continue
            h = hashlib.sha256(raw).hexdigest()
            try:
                mtime = fpath.stat().st_mtime
            except Exception:
                mtime = None
            infos = parse_task_xml(raw.decode("utf-8", errors="ignore"))
            snapshot[rel] = {
                "hash": h,
                "mtime": mtime,
                "author": infos.get("author"),
                "hidden": infos.get("hidden"),
                "runlevel": infos.get("runlevel"),
                "commands": infos.get("commands", []),
                "com_class_ids": infos.get("com_class_ids", []),
            }
    return snapshot, erreurs_lecture


_CACHE_PACKAGES_COM = None

def _lister_packages_com():
    global _CACHE_PACKAGES_COM
    if _CACHE_PACKAGES_COM is not None:
        return _CACHE_PACKAGES_COM
    packages = []
    try:
        import winreg
        key_base = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"PackagedCom\Package")
        i = 0
        while True:
            try:
                packages.append(winreg.EnumKey(key_base, i))
                i += 1
            except OSError:
                break
    except Exception:
        pass
    _CACHE_PACKAGES_COM = packages
    return packages


def resoudre_classid_com(class_id):
    if platform.system() != "Windows":
        return None
    try:
        import winreg
    except ImportError:
        return None

    cid = class_id.strip("{}")

    for sous_cle in ("InprocServer32", "LocalServer32"):
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{{{cid}}}\{sous_cle}")
            val, _ = winreg.QueryValueEx(key, "")
            if val:
                return {"type": "com_classique", "binaire": val, "package": None}
        except Exception:
            continue

    for nom_package in _lister_packages_com():
        try:
            winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"PackagedCom\Package\{nom_package}\Class\{{{cid}}}")
            return {"type": "packaged_com", "binaire": None, "package": nom_package}
        except Exception:
            continue

    return None


def charger_baseline_taches():
    if TASKS_BASELINE_PATH.exists():
        try:
            with open(TASKS_BASELINE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def sauver_baseline_taches(snapshot):
    try:
        with open(TASKS_BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

# ==========================================
# UTILITAIRES RAPPORT
# ==========================================

def ajouter_alerte(niveau, message, fort=False):
    global SCORE
    SCORE += {"CRITIQUE": 6, "ELEVE": 3, "MOYEN": 1, "INFO": 0}[niveau]
    ALERTES.append(f"[{niveau}] {message}")
    if fort and niveau == "CRITIQUE":
        ALERTES_FORTES.append(message)

def section(title):
    line = "=" * 60
    print("\n" + line)
    print(f" {title}")
    print(line)
    REPORT.append("\n" + line)
    REPORT.append(f" {title}")
    REPORT.append(line)

def add(text):
    print(text)
    REPORT.append(text)

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "Inconnu"

def verifier_ip_privee(ip):
    if ip.startswith(('127.', '0.', '::1', 'fe80::')):
        return True
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                      '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                      '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                      '172.29.', '172.30.', '172.31.')):
        return True
    return False

_WINDIR = os.environ.get("WINDIR", r"C:\Windows").lower().rstrip("\\")
_SYSTEM32 = _WINDIR + "\\system32"
_SYSWOW64 = _WINDIR + "\\syswow64"

PROCESSUS_SYSTEME_CHEMINS_LEGITIMES = {
    "svchost.exe": [_SYSTEM32, _SYSWOW64],
    "lsass.exe": [_SYSTEM32],
    "winlogon.exe": [_SYSTEM32],
    "services.exe": [_SYSTEM32],
    "csrss.exe": [_SYSTEM32],
    "wininit.exe": [_SYSTEM32],
    "smss.exe": [_SYSTEM32],
    "spoolsv.exe": [_SYSTEM32],
    "dwm.exe": [_SYSTEM32],
    "taskhostw.exe": [_SYSTEM32],
    "searchindexer.exe": [_SYSTEM32],
    "conhost.exe": [_SYSTEM32, _SYSWOW64],
    "explorer.exe": [_WINDIR],
    "lsm.exe": [_SYSTEM32],
    "sihost.exe": [_SYSTEM32],
    "fontdrvhost.exe": [_SYSTEM32],
}


def verifier_masquerade(nom_process, chemin_exe):
    nom_l = nom_process.lower()
    if nom_l not in PROCESSUS_SYSTEME_CHEMINS_LEGITIMES or not chemin_exe:
        return False
    chemin_l = chemin_exe.lower()
    dossiers_ok = PROCESSUS_SYSTEME_CHEMINS_LEGITIMES[nom_l]
    return not any(chemin_l.startswith(d) for d in dossiers_ok)


PARENT_ATTENDU = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SHELLS_SUSPECTS_ENFANTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                            "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"}


def verifier_anomalie_parent(nom_process, nom_parent):
    if not nom_parent:
        return False, None
    nom_l = nom_process.lower()
    parent_l = nom_parent.lower()

    attendus = PARENT_ATTENDU.get(nom_l)
    if attendus and parent_l not in attendus:
        return True, f"parent anormal '{nom_parent}' (attendu: {'/'.join(attendus)})"

    if nom_l in SHELLS_SUSPECTS_ENFANTS and parent_l in OFFICE_APPS:
        return True, f"lancé par '{nom_parent}' — pattern classique de macro malveillante"

    return False, None


PIDS_A_ANALYSER_MEMOIRE = set()


def scanner_regions_memoire_suspectes(pid, max_regions=50000):
    if platform.system() != "Windows":
        return {"regions_suspectes": 0, "erreur": "Windows uniquement"}
    try:
        import ctypes
        from ctypes import wintypes

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        MEM_COMMIT = 0x1000
        MEM_PRIVATE = 0x20000
        PROTECTIONS_EXECUTABLES = {0x10, 0x20, 0x40, 0x80}
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        kernel32 = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            return {"regions_suspectes": 0, "erreur": "accès refusé (processus protégé ou droits insuffisants)"}

        try:
            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            compte_regions = 0
            regions_suspectes = 0
            limite = 0x7FFFFFFF0000
            while address < limite and compte_regions < max_regions:
                taille = kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if taille == 0:
                    break
                if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                        and mbi.Protect in PROTECTIONS_EXECUTABLES):
                    regions_suspectes += 1
                address += mbi.RegionSize if mbi.RegionSize else 0x1000
                compte_regions += 1
            return {"regions_suspectes": regions_suspectes, "erreur": None}
        finally:
            kernel32.CloseHandle(h_process)
    except Exception as e:
        return {"regions_suspectes": 0, "erreur": str(e)}

# ==========================================
# AUDIT SYSTEME - PARTIE 1
# ==========================================

def audit_system(message_maj_threat_intel=None):
    print("=" * 70)
    print("  🔍 AUDIT SYSTEME AVANCÉ - Threat Intel / Tâches / AV-Pare-feu")
    print(f"  Auteur : {AUTEUR}")
    print(f"  GitHub : {GITHUB_URL}")
    print("=" * 70)
    ti_count = (len(TI.get("malicious_ips", [])) + len(TI.get("malicious_ip_ranges", []))
                + len(TI.get("malicious_domains", [])))
    print(f"Base threat intel chargée : {ti_count} IOC + "
          f"{len(TI.get('dynamic_dns_domains', []))} dynamic DNS connus\n")

    section("INFORMATIONS SYSTEME")
    for i in [
        f"Date : {datetime.datetime.now()}",
        f"Système : {platform.system()} {platform.release()}",
        f"Machine : {platform.node()}",
        f"Utilisateur : {os.getlogin()}",
        f"Auteur du script : {AUTEUR}",
        f"GitHub : {GITHUB_URL}",
        f"Version du script : {VERSION}",
    ]:
        add(i)
    if message_maj_threat_intel:
        add(f"Statut mise à jour threat intel : {message_maj_threat_intel}")

    # ======================================
    # 1 - Connexions réseau
    # ======================================
    section("[1] ANALYSE DES CONNEXIONS RESEAU")
    try:
        count = 0
        ip_publiques_vues = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                process = get_process_name(conn.pid)
                ip = conn.raddr.ip
                count += 1

                if verifier_ip_privee(ip):
                    add(f"{process:<25} PID:{conn.pid} | {conn.laddr} -> {conn.raddr}")
                    continue

                match_directe = ip in TI.get("malicious_ips", [])
                match_range = ip_dans_ranges(ip, TI.get("malicious_ip_ranges", []))

                if match_directe or match_range:
                    add(f"{process:<25} PID:{conn.pid} | {conn.laddr} -> {conn.raddr}  🚨 MATCH THREAT INTEL")
                    ajouter_alerte("CRITIQUE", f"Connexion vers IP présente dans threat_intel.json: {ip} (processus: {process})", fort=True)
                    continue

                rdns = resoudre_reverse_dns(ip)
                motif = domaine_suspect(rdns) if rdns else None
                if motif:
                    add(f"{process:<25} PID:{conn.pid} | {conn.laddr} -> {conn.raddr}  ({rdns}) ⚠️ {motif}")
                    ajouter_alerte("ELEVE", f"Connexion vers {ip} ({rdns}) — {motif} (processus: {process})")
                else:
                    label = f" ({rdns})" if rdns else ""
                    add(f"{process:<25} PID:{conn.pid} | {conn.laddr} -> {conn.raddr}{label}")

                ip_publiques_vues.add(ip)

        if len(ip_publiques_vues) >= SEUIL_CONNEXIONS_SUSPECTES:
            ajouter_alerte("INFO", f"{len(ip_publiques_vues)} IP publiques distinctes contactées (volume à vérifier, normal si beaucoup d'apps cloud/streaming actives)")

        add(f"\nTotal connexions actives : {count}")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 2 - Processus
    # ======================================
    section("[2] ANALYSE DES PROCESSUS")
    try:
        process_suspects = []
        for p in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
            try:
                name = p.info['name'].lower()
                mem = p.info['memory_percent']
                cpu = p.info['cpu_percent']

                try:
                    proc_complet = psutil.Process(p.info['pid'])
                    cmdline = " ".join(proc_complet.cmdline())
                    chemin_exe = proc_complet.exe()
                    try:
                        ppid = proc_complet.ppid()
                        nom_parent = psutil.Process(ppid).name() if ppid else None
                    except Exception:
                        nom_parent = None
                except Exception:
                    cmdline = ""
                    chemin_exe = None
                    nom_parent = None

                pid_deja_suspect = False

                motif_nom = nom_processus_suspect(name)
                if motif_nom:
                    process_suspects.append(name)
                    pid_deja_suspect = True
                    if chemin_exe:
                        noter_chemin_pour_signature(chemin_exe)
                    ajouter_alerte("CRITIQUE", f"Processus suspect: {name} (PID: {p.info['pid']}) — motif '{motif_nom}'", fort=True)

                if cpu > 50:
                    ajouter_alerte("ELEVE", f"Processus consommant beaucoup de CPU: {name} (CPU: {cpu:.1f}%)")
                if mem > 30:
                    ajouter_alerte("MOYEN", f"Processus consommant beaucoup de mémoire: {name} (MEM: {mem:.1f}%)")

                if verifier_masquerade(name, chemin_exe):
                    process_suspects.append(name)
                    pid_deja_suspect = True
                    noter_chemin_pour_signature(chemin_exe)
                    ajouter_alerte("CRITIQUE",
                        f"MASQUERADE: '{name}' (PID {p.info['pid']}) tourne depuis un emplacement anormal: "
                        f"{chemin_exe} — un vrai '{name}' ne devrait jamais se trouver là", fort=True)

                anomalie, raison_anomalie = verifier_anomalie_parent(name, nom_parent)
                if anomalie:
                    process_suspects.append(name)
                    pid_deja_suspect = True
                    if chemin_exe:
                        noter_chemin_pour_signature(chemin_exe)
                    ajouter_alerte("CRITIQUE",
                        f"ANOMALIE PARENT-ENFANT: '{name}' (PID {p.info['pid']}) — {raison_anomalie}", fort=True)

                motif = contient_pattern_suspect(cmdline, TI.get("suspicious_process_strings", []))
                if motif:
                    pid_deja_suspect = True
                    if chemin_exe:
                        noter_chemin_pour_signature(chemin_exe)
                    ajouter_alerte("CRITIQUE", f"Ligne de commande suspecte pour {name} (PID {p.info['pid']}): motif '{motif}'")

                if pid_deja_suspect:
                    PIDS_A_ANALYSER_MEMOIRE.add((p.info['pid'], name))
            except Exception:
                pass

        processes = []
        for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                processes.append((p.info['memory_percent'], p.info['pid'], p.info['name']))
            except Exception:
                pass
        processes.sort(reverse=True)
        for mem, pid, name in processes[:10]:
            add(f"{name:<30} PID:{pid:<7} MEM:{mem:.2f}%")

        if process_suspects:
            add(f"\n⚠️ {len(process_suspects)} processus suspect(s) détecté(s)")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 3 - Ports
    # ======================================
    section("[3] ANALYSE DES PORTS ECOUTES")
    try:
        ports_trouves = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                process = get_process_name(conn.pid)
                port = conn.laddr.port
                add(f"Port {port:<6} PID:{conn.pid:<7} {process}")
                if port in PORTS_SUSPECTS:
                    ports_trouves.append(port)
                    ajouter_alerte("ELEVE", f"Port suspect ouvert: {port} (processus: {process})")
        if ports_trouves:
            add(f"\n⚠️ {len(ports_trouves)} port(s) suspect(s) détecté(s)")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 4 - Taches planifiees : lecture directe + diff baseline
    # ======================================
    section("[4] ANALYSE DES TACHES PLANIFIEES (avec détection de modifications)")
    if platform.system() == "Windows":
        try:
            snapshot, erreurs_lecture = scanner_taches_planifiees()

            if not snapshot:
                add("Impossible de lire C:\\Windows\\System32\\Tasks (relance en Administrateur) — "
                    "fallback sur schtasks (moins précis).")
                result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"],
                                         capture_output=True, text=True, timeout=15)
                blocs = result.stdout.split("\n\n")
                n = 0
                for bloc in blocs:
                    if "TaskName" not in bloc:
                        continue
                    n += 1
                    motif = contient_pattern_suspect(bloc, TI.get("suspicious_process_strings", []))
                    if motif:
                        nom_ligne = next((l for l in bloc.splitlines() if "TaskName" in l), bloc[:60])
                        ajouter_alerte("CRITIQUE", f"Tâche avec commande suspecte ({motif}): {nom_ligne.strip()}")
                add(f"Nombre de tâches analysées (fallback) : {n}")
            else:
                add(f"{len(snapshot)} tâches lues" +
                    (f" ({erreurs_lecture} illisibles, ACL restreint)" if erreurs_lecture else ""))

                baseline = charger_baseline_taches()
                nouvelles, modifiees, supprimees = [], [], []

                if baseline is None:
                    add("Aucune baseline précédente : création de la référence pour les prochains audits.")
                else:
                    for rel, info in snapshot.items():
                        if rel not in baseline:
                            nouvelles.append(rel)
                        elif info["hash"] != baseline[rel].get("hash"):
                            modifiees.append(rel)
                    for rel in baseline:
                        if rel not in snapshot:
                            supprimees.append(rel)

                for rel, info in snapshot.items():
                    cmd_complet = " ".join(info.get("commands", []))
                    motif_cmd = contient_pattern_suspect(cmd_complet, TI.get("suspicious_process_strings", []))
                    motif_path = contient_pattern_suspect(cmd_complet, TI.get("suspicious_path_fragments", []))
                    est_nouvelle = rel in nouvelles
                    est_modifiee = rel in modifiees
                    suspect_nom = nom_aleatoire(Path(rel).name)

                    est_namespace_microsoft = rel.lower().startswith("microsoft\\windows\\")
                    hidden_est_signal = info.get("hidden") and not est_namespace_microsoft

                    com_suspect = False
                    com_details = []
                    for cid in info.get("com_class_ids", []):
                        if not (est_nouvelle or est_modifiee):
                            break
                        resolu = resoudre_classid_com(cid)
                        if resolu is None:
                            com_suspect = True
                            com_details.append(f"{cid} → introuvable dans le registre COM (orphelin ou fileless)")
                        elif resolu["type"] == "packaged_com":
                            pkg = resolu["package"]
                            if "microsoft" in pkg.lower():
                                com_details.append(f"{cid} → package Microsoft ({pkg})")
                            else:
                                com_suspect = True
                                com_details.append(f"{cid} → package NON-Microsoft ({pkg})")
                        else:
                            binaire = resolu["binaire"]
                            noter_chemin_pour_signature(binaire)
                            com_details.append(f"{cid} → {binaire} (vérifié en section [10])")

                    if (est_nouvelle or est_modifiee) and (motif_cmd or hidden_est_signal or motif_path or suspect_nom or com_suspect):
                        raisons = []
                        if motif_cmd: raisons.append(f"commande suspecte '{motif_cmd}'")
                        if motif_path: raisons.append(f"chemin à risque '{motif_path}'")
                        if hidden_est_signal: raisons.append("tâche cachée (Hidden=true)")
                        if suspect_nom: raisons.append("nom à consonance aléatoire")
                        if com_suspect: raisons.append("action ComHandler résolue vers un composant non-Microsoft ou introuvable")
                        niveau = "CRITIQUE" if (motif_cmd or com_suspect or (hidden_est_signal and motif_path)) else "ELEVE"
                        statut_maj = "NOUVELLE" if est_nouvelle else "MODIFIEE"
                        for c in info.get("commands", []):
                            noter_chemin_pour_signature(c)
                        ajouter_alerte(niveau, f"Tâche {statut_maj} suspecte: {rel} — {', '.join(raisons)}", fort=com_suspect)
                        add(f"  🚨 [{statut_maj}] {rel} — {', '.join(raisons)}")
                        for d in com_details:
                            add(f"      ↳ {d}")
                    elif est_nouvelle or est_modifiee:
                        statut_maj = "NOUVELLE" if est_nouvelle else "MODIFIEE"
                        add(f"  ℹ️ [{statut_maj}] {rel} (auteur: {info.get('author') or 'inconnu'})")
                        for d in com_details:
                            add(f"      ↳ {d}")

                if baseline is not None:
                    add(f"\nRésumé : {len(nouvelles)} nouvelle(s), {len(modifiees)} modifiée(s), "
                        f"{len(supprimees)} supprimée(s) depuis le dernier audit.")
                    if len(nouvelles) + len(modifiees) > 10:
                        ajouter_alerte("MOYEN", f"Volume élevé de changements dans les tâches planifiées "
                                                f"({len(nouvelles) + len(modifiees)}) depuis le dernier audit")
                    for rel in supprimees[:5]:
                        add(f"  🗑️ Supprimée: {rel}")

                sauver_baseline_taches(snapshot)
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # 5 - DNS
    # ======================================
    section("[5] TEST DNS")
    try:
        ip = socket.gethostbyname("google.com")
        add(f"google.com -> {ip}")
        if ip.startswith("127."):
            ajouter_alerte("CRITIQUE", "Détournement DNS détecté (google.com → 127.0.0.1)", fort=True)
        else:
            add("✅ Résolution DNS normale")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 6 - Fichiers temporaires
    # ======================================
    section("[6] ANALYSE DES FICHIERS TEMPORAIRES")
    try:
        temp = Path(os.environ.get("TEMP", "/tmp"))
        extensions = (".exe", ".bat", ".cmd", ".ps1", ".scr", ".vbs", ".js")
        files = [f.name for f in temp.iterdir() if f.suffix.lower() in extensions]
        for f in files[:10]:
            add(f)
        add(f"\nNombre trouvé : {len(files)}")
        if len(files) > 10:
            ajouter_alerte("INFO", f"Beaucoup de fichiers exécutables dans TEMP ({len(files)})")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 7 - Fichier hosts
    # ======================================
    section("[7] ANALYSE DU FICHIER HOSTS")
    try:
        hosts_path = Path("C:/Windows/System32/drivers/etc/hosts")
        if hosts_path.exists():
            with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            for ligne in content.splitlines():
                l = ligne.strip()
                if not l or l.startswith('#'):
                    continue
                parts = l.split()
                if len(parts) < 2:
                    continue
                ip_h, domaine_h = parts[0], parts[1]
                if 'localhost' in domaine_h.lower():
                    continue
                motif = domaine_suspect(domaine_h)
                match_ip = (ip_h in TI.get("malicious_ips", [])) or ip_dans_ranges(ip_h, TI.get("malicious_ip_ranges", []))
                if match_ip or motif:
                    add(f"  ⚠️ {l}")
                    raison = motif or "IP présente dans threat_intel.json"
                    ajouter_alerte("ELEVE" if not match_ip else "CRITIQUE", f"Entrée hosts suspecte: {l} — {raison}")
                elif ip_h in ('127.0.0.1', '0.0.0.0'):
                    add(f"  {l}")
        else:
            add("Fichier hosts non trouvé")
    except Exception as e:
        add(f"Erreur : {e}")

    # ======================================
    # 8 - Registre : persistance
    # ======================================
    section("[8] ANALYSE DES CLES DE REGISTRE (PERSISTANCE)")
    if platform.system() == "Windows":
        try:
            import winreg

            def scan_run_key(hive, hive_name, chemin):
                try:
                    key = winreg.OpenKey(hive, chemin)
                except Exception:
                    return
                i, found = 0, []
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        found.append((name, str(value)))
                        i += 1
                    except OSError:
                        break
                if found:
                    add(f"  {hive_name}\\{chemin}")
                    for name, value in found:
                        add(f"    {name} = {value[:80]}")
                        noter_chemin_pour_signature(value)
                        motif_cmd = contient_pattern_suspect(value, TI.get("suspicious_process_strings", []))
                        motif_path = None if chemin_est_fiable(value) else contient_pattern_suspect(value, TI.get("suspicious_path_fragments", []))
                        if motif_cmd:
                            ajouter_alerte("CRITIQUE", f"Clé de démarrage suspecte ({hive_name}\\{chemin}\\{name}): motif '{motif_cmd}'", fort=True)
                        elif motif_path:
                            ajouter_alerte("MOYEN", f"Clé de démarrage pointant vers un dossier à risque ({hive_name}\\{chemin}\\{name}): {motif_path}")
                    if len(found) > 15:
                        ajouter_alerte("INFO", f"Nombreuses entrées dans {hive_name}\\{chemin} ({len(found)}) — pas anormal en soi, juste à parcourir de temps en temps")

            run_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for chemin in run_paths:
                scan_run_key(winreg.HKEY_LOCAL_MACHINE, "HKLM", chemin)
                scan_run_key(winreg.HKEY_CURRENT_USER, "HKCU", chemin)

            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
                for val_name, defaut in [("Shell", "explorer.exe"), ("Userinit", r"c:\windows\system32\userinit.exe,")]:
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        add(f"  Winlogon\\{val_name} = {val}")
                        noter_chemin_pour_signature(val)
                        if defaut.lower() not in val.lower():
                            ajouter_alerte("CRITIQUE", f"Winlogon\\{val_name} modifié: {val}", fort=True)
                    except FileNotFoundError:
                        pass
            except Exception:
                pass

            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
                val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                if val and val.strip():
                    add(f"  AppInit_DLLs = {val}")
                    for dll in val.split():
                        noter_chemin_pour_signature(dll)
                    ajouter_alerte("ELEVE", f"AppInit_DLLs non vide: {val}")
            except Exception:
                pass

            try:
                base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
                i = 0
                while True:
                    try:
                        subname = winreg.EnumKey(key, i)
                        i += 1
                        try:
                            subkey = winreg.OpenKey(key, subname)
                            val, _ = winreg.QueryValueEx(subkey, "Debugger")
                            add(f"  IFEO\\{subname}\\Debugger = {val}")
                            noter_chemin_pour_signature(val)
                            ajouter_alerte("CRITIQUE", f"Debugger hijacking détecté sur {subname}: {val}", fort=True)
                        except FileNotFoundError:
                            pass
                    except OSError:
                        break
            except Exception:
                pass

            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
                i, services_suspects = 0, 0
                while True:
                    try:
                        subname = winreg.EnumKey(key, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        subkey = winreg.OpenKey(key, subname)
                        image_path, _ = winreg.QueryValueEx(subkey, "ImagePath")
                    except Exception:
                        continue
                    if chemin_est_fiable(image_path):
                        continue
                    motif_path = contient_pattern_suspect(image_path, TI.get("suspicious_path_fragments", []))
                    motif_cmd = contient_pattern_suspect(image_path, TI.get("suspicious_process_strings", []))
                    if motif_path or motif_cmd:
                        services_suspects += 1
                        noter_chemin_pour_signature(image_path)
                        ajouter_alerte("ELEVE", f"Service '{subname}' avec ImagePath suspect: {image_path[:100]}")
                if services_suspects:
                    add(f"  {services_suspects} service(s) avec ImagePath suspect détecté(s)")
            except Exception:
                pass
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # 9 - Antivirus et pare-feu
    # ======================================
    section("[9] ANTIVIRUS ET PARE-FEU")
    if platform.system() == "Windows":
        try:
            fw_data = get_powershell_json(
                "Get-NetFirewallProfile -All | Select-Object Name, Enabled | ConvertTo-Json")
            if fw_data:
                if isinstance(fw_data, dict):
                    fw_data = [fw_data]
                for profil in fw_data:
                    nom, actif = profil.get("Name"), profil.get("Enabled")
                    if actif:
                        add(f"  Pare-feu [{nom}] : ✅ activé")
                    else:
                        add(f"  Pare-feu [{nom}] : ❌ DÉSACTIVÉ")
                        ajouter_alerte("CRITIQUE", f"Pare-feu Windows désactivé sur le profil '{nom}'")
            else:
                add("  Impossible d'interroger le pare-feu (droits admin requis).")

            defender_data = get_powershell_json(
                "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, "
                "AntispywareEnabled, AntivirusSignatureAge | ConvertTo-Json")
            if defender_data:
                av_on = defender_data.get("AntivirusEnabled")
                rtp_on = defender_data.get("RealTimeProtectionEnabled")
                sig_age = defender_data.get("AntivirusSignatureAge")
                add(f"  Windows Defender - Antivirus actif : {'✅ oui' if av_on else '❌ NON'}")
                add(f"  Windows Defender - Protection temps réel : {'✅ oui' if rtp_on else '❌ NON'}")
                if sig_age is not None:
                    add(f"  Windows Defender - Âge des signatures : {sig_age} jour(s)")
                if not av_on:
                    ajouter_alerte("CRITIQUE", "Windows Defender désactivé")
                if av_on and not rtp_on:
                    ajouter_alerte("CRITIQUE", "Protection temps réel Windows Defender désactivée")
                if sig_age is not None and sig_age > 7:
                    ajouter_alerte("ELEVE", f"Signatures antivirus obsolètes ({sig_age} jours)")
            else:
                add("  Windows Defender non interrogeable (peut-être remplacé par un AV tiers).")

            sc_av = get_powershell_json(
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
                "| Select-Object displayName, productState | ConvertTo-Json")
            if sc_av:
                if isinstance(sc_av, dict):
                    sc_av = [sc_av]
                for prod in sc_av:
                    nom = prod.get("displayName", "Inconnu")
                    actif, a_jour = decoder_product_state(prod.get("productState", 0))
                    statut = "✅ activé" if actif else "❌ désactivé" if actif is False else "❓ indéterminé"
                    maj = "à jour" if a_jour else "⚠️ signatures potentiellement obsolètes" if a_jour is False else ""
                    add(f"  Antivirus déclaré (Security Center) : {nom} — {statut}, {maj}")
                    if actif is False:
                        ajouter_alerte("CRITIQUE", f"Antivirus '{nom}' déclaré désactivé auprès du Security Center")
            else:
                add("  Aucun antivirus tiers déclaré au Security Center.")

            sc_fw = get_powershell_json(
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct "
                "| Select-Object displayName, productState | ConvertTo-Json")
            if sc_fw:
                if isinstance(sc_fw, dict):
                    sc_fw = [sc_fw]
                for prod in sc_fw:
                    nom = prod.get("displayName", "Inconnu")
                    actif, _ = decoder_product_state(prod.get("productState", 0))
                    statut = "✅ activé" if actif else "❌ désactivé" if actif is False else "❓ indéterminé"
                    add(f"  Pare-feu tiers déclaré : {nom} — {statut}")
                    if actif is False:
                        ajouter_alerte("ELEVE", f"Pare-feu tiers '{nom}' déclaré désactivé")
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # 10 - Signatures numériques des binaires de persistance
    # ======================================
    section("[10] VERIFICATION DES SIGNATURES NUMERIQUES (logiciels sans signature)")
    if platform.system() == "Windows":
        try:
            chemins_dedup = sorted(set(CHEMINS_SIGNATURE))
            if not chemins_dedup:
                add("Aucun binaire de démarrage à vérifier.")
            else:
                add(f"{len(chemins_dedup)} binaire(s) de démarrage/persistance à vérifier...")
                json_paths = json.dumps(chemins_dedup)
                ps_cmd = (
                    "$paths = '" + json_paths.replace("'", "''") + "' | ConvertFrom-Json; "
                    "$paths | ForEach-Object { "
                    "$p = [Environment]::ExpandEnvironmentVariables($_); "
                    "if (Test-Path -LiteralPath $p) { "
                    "$sig = Get-AuthenticodeSignature -FilePath $p; "
                    "[PSCustomObject]@{Path=$p; Status=$sig.Status.ToString(); Signer=$sig.SignerCertificate.Subject} "
                    "} else { [PSCustomObject]@{Path=$p; Status='FileNotFound'; Signer=$null} } "
                    "} | ConvertTo-Json"
                )
                resultats = get_powershell_json(ps_cmd, timeout=45)

                if resultats is None:
                    add("Impossible de vérifier les signatures (PowerShell indisponible ou droits insuffisants).")
                else:
                    if isinstance(resultats, dict):
                        resultats = [resultats]
                    non_signes, introuvables, valides = 0, 0, 0
                    for r in resultats:
                        chemin = r.get("Path")
                        statut = r.get("Status")
                        signataire = r.get("Signer")
                        if statut == "Valid":
                            valides += 1
                            add(f"  ✅ {chemin} — signé ({signataire})")
                        elif statut == "FileNotFound":
                            introuvables += 1
                            add(f"  ❓ {chemin} — fichier introuvable (variable d'env non résolue ou déjà supprimé)")
                        elif statut in ("HashMismatch", "NotTrusted"):
                            non_signes += 1
                            add(f"  🚨 {chemin} — signature INVALIDE/ALTÉRÉE ({statut})")
                            ajouter_alerte("CRITIQUE", f"Signature numérique invalide/altérée sur un binaire de démarrage: {chemin} ({statut})", fort=True)
                        else:
                            non_signes += 1
                            add(f"  ⚠️ {chemin} — NON SIGNÉ ({statut})")
                            ajouter_alerte("MOYEN", f"Binaire de démarrage non signé: {chemin} — à vérifier manuellement")

                    add(f"\nRésumé : {valides} signé(s), {non_signes} non signé(s)/invalide(s), {introuvables} introuvable(s)")
                    add("Note : un logiciel non signé n'est pas forcément malveillant, mais mérite une vérification manuelle.")
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # 11 - Analyse mémoire des processus déjà suspects
    # ======================================
    section("[11] ANALYSE MEMOIRE (régions exécutables non adossées à un fichier)")
    if platform.system() == "Windows":
        try:
            if not PIDS_A_ANALYSER_MEMOIRE:
                add("Aucun processus signalé par ailleurs — pas d'analyse mémoire nécessaire.")
            else:
                add(f"{len(PIDS_A_ANALYSER_MEMOIRE)} processus déjà suspect(s) — analyse de leur espace mémoire...")
                for pid, nom in PIDS_A_ANALYSER_MEMOIRE:
                    resultat = scanner_regions_memoire_suspectes(pid)
                    if resultat["erreur"]:
                        add(f"  {nom} (PID {pid}) — analyse impossible : {resultat['erreur']}")
                    elif resultat["regions_suspectes"] > 0:
                        add(f"  🚨 {nom} (PID {pid}) — {resultat['regions_suspectes']} région(s) mémoire "
                            f"exécutable(s) SANS fichier source (signature d'injection/shellcode)")
                        ajouter_alerte("CRITIQUE",
                            f"Régions mémoire exécutables non adossées à un fichier dans '{nom}' (PID {pid}): "
                            f"{resultat['regions_suspectes']} région(s) — forte suspicion d'injection de code", fort=True)
                    else:
                        add(f"  ✅ {nom} (PID {pid}) — aucune région mémoire suspecte détectée")
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # 12 - Abonnements WMI (persistance fileless)
    # ======================================
    section("[12] ABONNEMENTS WMI (persistance sans fichier)")
    if platform.system() == "Windows":
        try:
            filtres = get_powershell_json(
                "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue "
                "| Select-Object Name, Query | ConvertTo-Json -Compress")
            consommateurs = get_powershell_json(
                "$c = @(); "
                "$c += Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate; "
                "$c += Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, ScriptText; "
                "$c | ConvertTo-Json -Compress")
            liaisons = get_powershell_json(
                "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue "
                "| Select-Object Filter, Consumer | ConvertTo-Json -Compress")

            def normaliser(x):
                if x is None:
                    return []
                return [x] if isinstance(x, dict) else x

            filtres, consommateurs, liaisons = normaliser(filtres), normaliser(consommateurs), normaliser(liaisons)

            if not filtres and not consommateurs and not liaisons:
                add("✅ Aucun abonnement WMI permanent détecté.")
            else:
                add(f"⚠️ {len(filtres)} filtre(s), {len(consommateurs)} consommateur(s), {len(liaisons)} liaison(s) WMI détecté(s).")
                add("Note : certains outils de gestion d'entreprise légitimes utilisent ce mécanisme.")
                for f in filtres:
                    add(f"  Filtre: {f.get('Name')} — requête: {str(f.get('Query'))[:150]}")
                for c in consommateurs:
                    detail = c.get("CommandLineTemplate") or c.get("ScriptText") or ""
                    add(f"  Consommateur: {c.get('Name')} — action: {str(detail)[:150]}")
                for b in liaisons:
                    add(f"  Liaison: {b.get('Filter')} -> {b.get('Consumer')}")
                ajouter_alerte("ELEVE", f"{len(filtres)} abonnement(s) WMI permanent(s) détecté(s) — persistance "
                                        f"fileless possible, à vérifier manuellement")
        except Exception as e:
            add(f"Erreur : {e}")
    else:
        add("Fonction Windows uniquement")

    # ======================================
    # VERDICT FINAL AVEC SEUILS RESSERRÉS
    # ======================================
    section("📊 DIAGNOSTIC FINAL")
    add(f"Score de risque: {SCORE}")

    # 4 niveaux de verdict avec des seuils stricts
    if len(ALERTES_FORTES) >= 3:  # Au moins 3 indicateurs forts = compromission probable
        niveau_final = "ROUGE"
        statut = "🔴 Ce PC est INFECTÉ"
        description = (f"{len(ALERTES_FORTES)} indicateur(s) fort(s) corroboré(s) détecté(s) — "
                       "Une compromission est très probable. Une analyse approfondie est URGENTE.")
    elif ALERTES_FORTES:  # 1 ou 2 indicateurs forts = suspect
        niveau_final = "ORANGE"
        statut = "🟠 Ce PC est SUSPECT"
        description = (f"{len(ALERTES_FORTES)} indicateur(s) fort(s) détecté(s) — "
                       "Des éléments sérieux méritent une vérification approfondie.")
        elif SCORE >= 3:  # Des alertes existent mais pas d'indicateur fort = points à vérifier
        niveau_final = "VERT"
        statut = "✅ Ce PC est visiblement SAIN, mais quelques points à vérifier"
        description = "Aucun indicateur fort, mais des anomalies mineures ont été relevées. Consultez le rapport."
    else:
        niveau_final = "VERT"
        statut = "✅ Ce PC est SAIN"
        description = "Aucun élément suspect détecté lors de cet audit."

    add(f"\n{statut}")
    add(f"  {description}")

    if ALERTES:
        add(f"\n{len(ALERTES)} alerte(s) détectée(s) :")
        for alerte in ALERTES[:15]:
            add(f"  {alerte}")
        if len(ALERTES) > 15:
            add(f"  ... et {len(ALERTES)-15} autres alertes")

    afficher_rectangle_verdict(niveau_final, statut, description)
    save_report(statut)


def activer_ansi_console():
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def afficher_rectangle_verdict(niveau, titre, sous_texte):
    activer_ansi_console()
    couleurs = {
        "VERT": ("42", "30"),
        "ORANGE": ("48;5;208", "30"),
        "ROUGE": ("41", "97"),
    }
    bg, fg = couleurs.get(niveau, ("40", "97"))
    lignes = [titre, sous_texte]
    largeur = max(len(l) for l in lignes) + 6
    vide = " " * largeur

    print()
    print(f"\033[{bg}m\033[{fg}m{vide}\033[0m")
    for l in lignes:
        centre = l.center(largeur - 4)
        print(f"\033[{bg}m\033[{fg}m  {centre}  \033[0m")
    print(f"\033[{bg}m\033[{fg}m{vide}\033[0m")
    print()


def get_desktop_dir():
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        desktop = Path(userprofile) / "Desktop"
        if desktop.exists():
            return desktop
    desktop_home = Path.home() / "Desktop"
    if desktop_home.exists():
        return desktop_home
    return BASE_DIR


def prochain_numero_rapport(dossier):
    pattern = re.compile(r"Rapport d'audit N°(\d+)\.txt$", re.IGNORECASE)
    max_n = 0
    try:
        for f in dossier.glob("Rapport d'audit N°*.txt"):
            m = pattern.match(f.name)
            if m:
                max_n = max(max_n, int(m.group(1)))
    except Exception:
        pass
    return max_n + 1


def save_report(statut):
    dossier = get_desktop_dir()
    n = prochain_numero_rapport(dossier)
    filename = dossier / f"Rapport d'audit N°{n}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(REPORT))
    except Exception as e:
        filename = BASE_DIR / f"Rapport d'audit N°{n}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(REPORT))
        print(f"⚠️ Écriture sur le Bureau impossible ({e}), rapport sauvegardé à côté du programme à la place.")

    print("\n" + "=" * 70)
    print(f"  📄 RAPPORT SAUVEGARDE : {filename}")
    print("=" * 70)
    print(f"\n{statut}")
    print("\nAppuyez sur ENTRÉE pour fermer...")
    input()

if __name__ == "__main__":
    message_maj = None

    if "--update" in sys.argv:
        mettre_a_jour_threat_intel()
        TI = charger_threat_intel()
        message_maj = "Mise à jour forcée manuellement via --update juste avant cet audit."
        if len(sys.argv) == 2:
            input("\nAppuyez sur ENTRÉE pour fermer...")
            sys.exit(0)
    else:
        message_maj = verifier_et_maj_threat_intel_si_necessaire(no_update=("--no-update" in sys.argv))

    try:
        audit_system(message_maj_threat_intel=message_maj)
    except KeyboardInterrupt:
        print("\nAudit interrompu.")
        input("Appuyez sur ENTRÉE pour fermer...")
    except Exception as e:
        print(f"Erreur générale : {e}")
        input("Appuyez sur ENTRÉE pour fermer...")
