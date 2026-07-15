<#
.SYNOPSIS
    Audit systeme avance - Threat Intel / Taches / AV / Pare-feu
.AUTHOR
    Fafyula (traduction PowerShell)
.VERSION
    1.7
#>

# ==========================================
# CONFIGURATION
# ==========================================
$script:AUTEUR = "Fafyula (traduction PowerShell)"
$script:GITHUB_URL = "https://github.com/Fafyula-KH"
$script:VERSION = "1.8 (fix resolution binaires sans chemin, exemption WMI SCM Event Log)"

if ($MyInvocation.MyCommand.Path) {
    $script:BASE_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $script:BASE_DIR = $PWD.Path
}

$script:REPORT = @()
$script:SCORE = 0
$script:ALERTES = @()
$script:ALERTES_FORTES = @()
$script:CHEMINS_SIGNATURE = @()

$script:SEUIL_CONNEXIONS_SUSPECTES = 15
$script:PORTS_SUSPECTS = @(4444, 6667, 31337, 5555, 12345, 1337)
$script:PROCESSUS_SUSPECTS = @("mimikatz", "nc.exe", "plink.exe", "putty.exe",
    "cobaltstrike", "beacon", "meterpreter", "empire")

$script:THREAT_INTEL_PATH = Join-Path $BASE_DIR "threat_intel.json"
$script:SEUIL_MAJ_HEURES = 24
$script:TASKS_BASELINE_PATH = Join-Path $BASE_DIR "taches_baseline.json"

$script:WINDIR = $env:WINDIR
$script:SYSTEM32 = Join-Path $WINDIR "System32"
$script:SYSWOW64 = Join-Path $WINDIR "SysWOW64"

# ==========================================
# DEFAUT TI
# ==========================================
$script:DEFAUT_TI = @{
    "manual" = @{
        "malicious_ips" = @()
        "malicious_ip_ranges" = @()
        "malicious_domains" = @()
    }
    "auto" = @{
        "last_update" = $null
        "sources" = @{}
        "malicious_ips" = @()
        "malicious_ip_ranges" = @()
        "malicious_domains" = @()
    }
    "dynamic_dns_domains" = @(
        "duckdns.org", "no-ip.com", "no-ip.org", "noip.com", "ddns.net",
        "hopto.org", "zapto.org", "sytes.net", "changeip.com",
        "freedynamicdns.org", "myftp.org", "servebeer.com", "servehttp.com",
        "dynu.com", "dnsdynamic.org"
    )
    "high_risk_tlds" = @(".zip", ".mov", ".top", ".xyz", ".club", ".work",
        ".gq", ".tk", ".ml", ".cf", ".ga", ".icu", ".rest")
    "suspicious_process_strings" = @(
        "-enc ", "-encodedcommand", "-e ", "iex(", "iex (",
        "downloadstring", "invoke-expression", "frombase64string",
        "mshta http", "rundll32.exe javascript", "certutil -urlcache",
        "certutil -decode", "bitsadmin /transfer"
    )
    "suspicious_path_fragments" = @(
        "\appdata\local\temp\", "\appdata\roaming\", "\public\",
        "\users\public\", "\windows\temp\"
    )
    "chemins_fiables_ignores" = @(
        "\programdata\microsoft\windows defender\",
        "\program files\windows defender\",
        "\program files (x86)\windows defender\"
    )
}

$script:TI = $null
$script:PIDS_A_ANALYSER_MEMOIRE = @{}

# ==========================================
# FONCTIONS UTILITAIRES
# ==========================================

function Ajouter-Alerte {
    param($niveau, $message, [switch]$fort)
    $scoreMap = @{
        "CRITIQUE" = 10
        "ELEVE" = 5
        "MOYEN" = 2
        "INFO" = 1
    }
    $script:SCORE += $scoreMap[$niveau]
    $script:ALERTES += "[$niveau] $message"
    if ($fort -and $niveau -eq "CRITIQUE") {
        $script:ALERTES_FORTES += $message
    }
}

function Section {
    param($title)
    $line = "=" * 60
    Write-Host "`n$line"
    Write-Host " $title"
    Write-Host $line
    $script:REPORT += "`n$line"
    $script:REPORT += " $title"
    $script:REPORT += $line
}

function Add-Report {
    param($text)
    Write-Host $text
    $script:REPORT += $text
}

function Get-ProcessName {
    param($procId)
    try {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) { return $p.Name }
        return "Inconnu"
    } catch {
        return "Inconnu"
    }
}

function Test-PrivateIP {
    param($ip)
    if ($ip -match '^(127\.|0\.|::1|fe80::)') { return $true }
    if ($ip -match '^(10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)') { return $true }
    return $false
}

function Test-NomAleatoire {
    param($nom)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($nom)
    if ($base.Length -lt 10) { return $false }
    $lettres = ($base -replace '[^a-zA-Z]', '').ToCharArray()
    if ($lettres.Count -lt 6) { return $false }
    $voyelles = ($lettres | Where-Object { $_ -in @('a','e','i','o','u','y','A','E','I','O','U','Y') }).Count
    $ratio = $voyelles / $lettres.Count
    $aChiffres = $base -match '\d'
    return $ratio -lt 0.2 -and ($aChiffres -or $base.Length -gt 16)
}

function Resoudre-ReverseDNS {
    param($ip, $timeout = 0.8)
    try {
        $ipObj = [System.Net.IPAddress]::Parse($ip)
        $hostEntry = [System.Net.Dns]::GetHostEntry($ipObj)
        return $hostEntry.HostName
    } catch {
        return $null
    }
}

function Test-DomaineSuspect {
    param($domaine)
    if (-not $domaine) { return $null }
    $d = $domaine.ToLower()
    foreach ($m in $script:TI.malicious_domains) {
        if ($d -match [regex]::Escape($m.ToLower())) {
            return "domaine connu malveillant ($m)"
        }
    }
    foreach ($dd in $script:TI.dynamic_dns_domains) {
        if ($d -match [regex]::Escape($dd.ToLower()) + '$') {
            return "dynamic DNS souvent abuse pour C2 ($dd)"
        }
    }
    foreach ($tld in $script:TI.high_risk_tlds) {
        if ($d -match [regex]::Escape($tld.ToLower()) + '$') {
            return "TLD a risque eleve ($tld)"
        }
    }
    return $null
}

function ConvertTo-UInt32IP {
    # Convertit une IPv4 en entier 32 bits pour comparaison bitwise. Retourne $null
    # pour l'IPv6 (les flux Spamhaus/Feodo utilisés ici sont exclusivement IPv4).
    param([string]$ip)
    try {
        $addr = [System.Net.IPAddress]::Parse($ip)
        if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return $null
        }
        $bytes = $addr.GetAddressBytes()
        [Array]::Reverse($bytes)
        return [BitConverter]::ToUInt32($bytes, 0)
    } catch {
        return $null
    }
}

function Test-IPDansRanges {
    # Implémentation bitwise manuelle, compatible Windows PowerShell 5.1 ET PowerShell 7+
    # (System.Net.IPNetwork est une API .NET 8, absente de la majorité des postes Windows).
    param($ip, $ranges)
    $ipInt = ConvertTo-UInt32IP -ip $ip
    if ($null -eq $ipInt) { return $false }

    foreach ($cidr in $ranges) {
        try {
            $parts = $cidr -split '/'
            if ($parts.Count -ne 2) { continue }
            $reseauInt = ConvertTo-UInt32IP -ip $parts[0]
            if ($null -eq $reseauInt) { continue }
            $prefixLen = [int]$parts[1]
            if ($prefixLen -lt 0 -or $prefixLen -gt 32) { continue }

            if ($prefixLen -eq 0) { return $true }

            $masque = [uint32]([uint32]::MaxValue -shl (32 - $prefixLen))
            if (($ipInt -band $masque) -eq ($reseauInt -band $masque)) {
                return $true
            }
        } catch {
            continue
        }
    }
    return $false
}

function Test-ContientPattern {
    param($texte, $patterns)
    if (-not $texte) { return $null }
    $t = $texte.ToLower()
    foreach ($p in $patterns) {
        if ($t -match [regex]::Escape($p.ToLower())) {
            return $p
        }
    }
    return $null
}

function Test-CheminFiable {
    param($texte)
    if (-not $texte) { return $false }
    $t = $texte.ToLower()
    foreach ($frag in $script:TI.chemins_fiables_ignores) {
        if ($t -match [regex]::Escape($frag.ToLower())) {
            return $true
        }
    }
    return $false
}

function Test-NomProcessusSuspect {
    param($nomProcess)
    $n = $nomProcess.ToLower()
    foreach ($suspect in $script:PROCESSUS_SUSPECTS) {
        if ($n -match "(?<![a-z0-9])$([regex]::Escape($suspect.ToLower()))(?![a-z0-9])") {
            return $suspect
        }
    }
    return $null
}

function Extraire-CheminExe {
    param($commande)
    if (-not $commande) { return $null }
    $c = $commande.Trim()
    if ($c -match '^"([^"]+\.(?:exe|dll|sys))"') {
        return $Matches[1]
    }
    if ($c -match '^([^\s]+\.(?:exe|dll|sys))') {
        return $Matches[1]
    }
    $parts = $c -split '\s+'
    return $parts[0]
}

function Noter-CheminSignature {
    param($commande)
    $chemin = Extraire-CheminExe $commande
    if ($chemin -and $chemin -match '\.(exe|dll|sys)$') {
        $script:CHEMINS_SIGNATURE += $chemin
    }
}

function Decoder-ProductState {
    param($state)
    if (-not $state) { return $null, $null }
    try {
        $hex = ([int]$state).ToString("X6")
        $milieu = $hex.Substring(2, 2)
        $fin = $hex.Substring(4, 2)
        $actif = $milieu -in @("11", "21", "01")
        $aJour = $fin -eq "00"
        return $actif, $aJour
    } catch {
        return $null, $null
    }
}

# ==========================================
# ==========================================
# AFFICHER RECTANGLE SIMPLE (sans codes ANSI)
# ==========================================
function Afficher-RectangleVerdict {
    param($niveau, $titre, $sous_texte)

    $lignes = @($titre, $sous_texte)
    $largeur = ($lignes | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 6
    if ($largeur -lt 50) { $largeur = 50 }
    $vide = " " * $largeur
    $bordure = "+" + ("-" * ($largeur - 2)) + "+"

    Write-Host ""
    Write-Host $bordure -ForegroundColor Cyan
    Write-Host "|" $vide "|" -ForegroundColor Cyan
    foreach ($l in $lignes) {
        $espaceGauche = [math]::Floor(($largeur - 4 - $l.Length) / 2)
        $espaceDroite = [math]::Ceiling(($largeur - 4 - $l.Length) / 2)
        $centre = (" " * $espaceGauche) + $l + (" " * $espaceDroite)
        Write-Host "|  $centre  |" -ForegroundColor Cyan
    }
    Write-Host "|" $vide "|" -ForegroundColor Cyan
    Write-Host $bordure -ForegroundColor Cyan
    Write-Host ""
}

# ==========================================
# THREAT INTEL
# ==========================================

function Charger-ThreatIntel {
    if (-not (Test-Path $script:THREAT_INTEL_PATH)) {
        $script:DEFAUT_TI | ConvertTo-Json -Depth 10 | Set-Content -Path $script:THREAT_INTEL_PATH -Encoding UTF8
        Write-Host "INFO: threat_intel.json cree avec les valeurs par defaut ($script:THREAT_INTEL_PATH)."
    }
    try {
        $data = Get-Content -Path $script:THREAT_INTEL_PATH -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $data = $script:DEFAUT_TI | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    }
    foreach ($cle in $script:DEFAUT_TI.Keys) {
        if (-not $data.PSObject.Properties.Name -contains $cle) {
            $data | Add-Member -MemberType NoteProperty -Name $cle -Value $script:DEFAUT_TI[$cle] -Force
        }
    }
    $data | Add-Member -MemberType NoteProperty -Name "malicious_ips" -Value (@($data.manual.malicious_ips) + @($data.auto.malicious_ips) | Select-Object -Unique) -Force
    $data | Add-Member -MemberType NoteProperty -Name "malicious_ip_ranges" -Value (@($data.manual.malicious_ip_ranges) + @($data.auto.malicious_ip_ranges) | Select-Object -Unique) -Force
    $data | Add-Member -MemberType NoteProperty -Name "malicious_domains" -Value (@($data.manual.malicious_domains) + @($data.auto.malicious_domains) | Select-Object -Unique) -Force
    return $data
}

function MettreAJour-ThreatIntel {
    Write-Host "Mise a jour de la threat intel en cours..."
    $tousIPS = @()
    $tousRanges = @()
    $tousDomaines = @()
    $resultats = @{}
    $erreurs = @()

    try {
        $url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        $tousIPS += ($response.Content -split "`n") | Where-Object { $_ -and $_ -notmatch '^[;#]' -and $_ -match '^\d+\.\d+\.\d+\.\d+$' }
        $resultats["feodotracker_ips"] = $tousIPS.Count
        Write-Host "  OK Feodo Tracker : $($tousIPS.Count) IP"
    } catch {
        $erreurs += "feodotracker_ips: $_"
        Write-Host "  ECHEC Feodo Tracker : ($_)"
    }

    foreach ($key in @("spamhaus_drop", "spamhaus_edrop")) {
        try {
            $url = if ($key -eq "spamhaus_drop") { "https://www.spamhaus.org/drop/drop.txt" } else { "https://www.spamhaus.org/drop/edrop.txt" }
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
            $ranges = ($response.Content -split "`n") | Where-Object { $_ -and $_ -notmatch '^[;#]' } | ForEach-Object { ($_ -split ';')[0].Trim() }
            $tousRanges += $ranges
            $resultats[$key] = $ranges.Count
            Write-Host "  OK $key : $($ranges.Count) ranges"
        } catch {
            $erreurs += "$key : $_"
            Write-Host "  ECHEC $key : ($_)"
        }
    }

    try {
        $url = "https://urlhaus.abuse.ch/downloads/hostfile/"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        $lignes = $response.Content -split "`n"
        foreach ($ligne in $lignes) {
            $l = $ligne.Trim()
            if (-not $l -or $l -match '^#') { continue }
            $parts = $l -split '\s+'
            if ($parts.Count -ge 2) {
                $d = $parts[1].Trim().ToLower()
                if ($d -and $d -ne "localhost") { $tousDomaines += $d }
            }
        }
        $resultats["urlhaus_hosts"] = $tousDomaines.Count
        Write-Host "  OK URLhaus : $($tousDomaines.Count) domaines"
    } catch {
        $erreurs += "urlhaus_hosts: $_"
        Write-Host "  ECHEC URLhaus : ($_)"
    }

    if ($resultats.Keys.Count -eq 0) {
        Write-Host "ATTENTION: Aucune source contactable (pas de reseau ?). Base inchangee."
        return $false
    }

    $data = Charger-ThreatIntel
    $data.auto.malicious_ips = $tousIPS | Select-Object -Unique | Sort-Object
    $data.auto.malicious_ip_ranges = $tousRanges | Select-Object -Unique | Sort-Object
    $data.auto.malicious_domains = $tousDomaines | Select-Object -Unique | Sort-Object
    $data.auto.last_update = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $data.auto.sources = $resultats
    if ($erreurs.Count -gt 0) {
        $data.auto.sources | Add-Member -MemberType NoteProperty -Name "_erreurs" -Value ($erreurs -join "; ") -Force
    }

    $data | ConvertTo-Json -Depth 10 | Set-Content -Path $script:THREAT_INTEL_PATH -Encoding UTF8
    $total = $tousIPS.Count + $tousRanges.Count + $tousDomaines.Count
    Write-Host "Base mise a jour : $total IOC au total."
    if ($erreurs.Count -gt 0) { Write-Host "ATTENTION: $($erreurs.Count) source(s) en echec." }
    return $true
}

function Test-ConnexionInternet {
    param($timeout = 3)
    foreach ($hote in @("1.1.1.1", "8.8.8.8")) {
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $socket.BeginConnect($hote, 53, $null, $null)
            if ($asyncResult.AsyncWaitHandle.WaitOne($timeout * 1000)) {
                $socket.EndConnect($asyncResult)
                $socket.Close()
                return $true
            }
        } catch { continue }
    }
    return $false
}

function VerifierEtMajThreatIntel {
    param([switch]$noUpdate)
    $data = Charger-ThreatIntel
    $script:TI = $data
    $lastUpdate = $data.auto.last_update
    $ageHeures = $null
    if ($lastUpdate) {
        try {
            $dt = [datetime]::ParseExact($lastUpdate, "yyyy-MM-dd HH:mm:ss", $null)
            $ageHeures = ((Get-Date) - $dt).TotalHours
        } catch { $ageHeures = $null }
    }

    if ($noUpdate) {
        if ($ageHeures -ne $null) {
            return "Mise a jour desactivee (-noUpdate). Base utilisee datee d'il y a $([math]::Round($ageHeures,0))h."
        }
        return "Mise a jour desactivee (-noUpdate). Aucune base auto n'a jamais ete telechargee (0 IOC)."
    }

    if ($ageHeures -ne $null -and $ageHeures -lt $script:SEUIL_MAJ_HEURES) {
        return "Base threat intel a jour (derniere mise a jour il y a $([math]::Round($ageHeures,0))h, seuil $($script:SEUIL_MAJ_HEURES)h)."
    }

    $ref = if ($lastUpdate) { " (derniere base connue datee du $lastUpdate)" } else { " (aucune base n'a jamais ete telechargee avec succes)" }
    Write-Host "Base threat intel perimee ou absente, tentative de mise a jour avant l'audit..."

    if (-not (Test-ConnexionInternet)) {
        return "ATTENTION: AUDIT REALISE SANS CONNEXION INTERNET DETECTEE. La base threat intel n'a pas pu etre mise a jour.$ref."
    }

    $succes = MettreAJour-ThreatIntel
    $script:TI = Charger-ThreatIntel
    if ($succes) {
        return "Base threat intel mise a jour automatiquement avant cet audit."
    }
    return "ATTENTION: Connexion internet detectee mais la mise a jour a echoue.$ref."
}

# ==========================================
# TACHES PLANIFIEES
# ==========================================

function Parse-TaskXML {
    param($contenu)
    $result = @{
        "author" = $null
        "hidden" = $false
        "runlevel" = $null
        "commands" = @()
        "com_class_ids" = @()
    }
    try {
        $xml = [xml]$contenu
        $task = $xml.Task
        if ($task.Principals.Principal.UserId) {
            $result.author = $task.Principals.Principal.UserId
        }
        if ($task.Settings.Hidden) {
            $result.hidden = $task.Settings.Hidden -eq 'true'
        }
        if ($task.Principals.Principal.RunLevel) {
            $result.runlevel = $task.Principals.Principal.RunLevel
        }
        if ($task.Actions) {
            foreach ($action in $task.Actions.ChildNodes) {
                if ($action.Command) { $result.commands += $action.Command }
                if ($action.Arguments) { $result.commands += $action.Arguments }
                if ($action.ClassId) { $result.com_class_ids += $action.ClassId }
            }
        }
    } catch {}
    return $result
}

function Scanner-TachesPlanifiees {
    $tasksDir = "C:\Windows\System32\Tasks"
    $snapshot = @{}
    $erreurs = 0
    if (-not (Test-Path $tasksDir)) { return $snapshot, $erreurs }
    Get-ChildItem -Path $tasksDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($tasksDir.Length + 1)
        try {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA256).Hash
            $mtime = $_.LastWriteTimeUtc.Ticks
            $content = [System.Text.Encoding]::UTF8.GetString($bytes)
            $infos = Parse-TaskXML $content
            $snapshot[$rel] = @{
                "hash" = $hash
                "mtime" = $mtime
                "author" = $infos.author
                "hidden" = $infos.hidden
                "runlevel" = $infos.runlevel
                "commands" = $infos.commands
                "com_class_ids" = $infos.com_class_ids
            }
        } catch {
            $erreurs++
        }
    }
    return $snapshot, $erreurs
}

function Resoudre-ClassIdCom {
    param($classId)
    $cid = $classId -replace '[{}]', ''
    try {
        $key = "HKLM:\SOFTWARE\Classes\CLSID\{$cid}\InprocServer32"
        if (Test-Path $key) {
            $val = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue)."(default)"
            if ($val) { return @{"type" = "com_classique"; "binaire" = $val; "package" = $null } }
        }
        $key = "HKLM:\SOFTWARE\Classes\CLSID\{$cid}\LocalServer32"
        if (Test-Path $key) {
            $val = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue)."(default)"
            if ($val) { return @{"type" = "com_classique"; "binaire" = $val; "package" = $null } }
        }
        $packages = Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\PackagedCom\Package" -ErrorAction SilentlyContinue
        foreach ($pkg in $packages) {
            $testKey = Join-Path $pkg.PSPath "Class\{$cid}"
            if (Test-Path $testKey) {
                return @{"type" = "packaged_com"; "binaire" = $null; "package" = $pkg.PSChildName }
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Charger-BaselineTaches {
    if (Test-Path $script:TASKS_BASELINE_PATH) {
        try {
            return Get-Content -Path $script:TASKS_BASELINE_PATH -Encoding UTF8 | ConvertFrom-Json
        } catch { return $null }
    }
    return $null
}

function Sauver-BaselineTaches {
    param($snapshot)
    try {
        $snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $script:TASKS_BASELINE_PATH -Encoding UTF8
    } catch {}
}

# ==========================================
# ANALYSE MEMOIRE
# ==========================================

if (-not ("Win32MemApi" -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32MemApi {
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
}

function Scanner-RegionsMemoireSuspectes {
    # Equivalent PowerShell du scanner ctypes Python : parcourt l'espace memoire du
    # processus et compte les regions MEM_PRIVATE (sans fichier source) ET executables
    # -- signature classique de shellcode / reflective DLL loading / process hollowing.
    # Reserve aux PID deja suspects par ailleurs (corroboration), jamais un scan aveugle.
    param($pid)
    try {
        $PROCESS_QUERY_INFORMATION = 0x0400
        $PROCESS_VM_READ = 0x0010
        $MEM_COMMIT = 0x1000
        $MEM_PRIVATE = 0x20000
        $protectionsExecutables = @(0x10, 0x20, 0x40, 0x80)  # EXECUTE / _READ / _READWRITE / _WRITECOPY

        $hProcess = [Win32MemApi]::OpenProcess($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ, $false, $pid)
        if ($hProcess -eq [IntPtr]::Zero) {
            return @{"regions_suspectes" = 0; "erreur" = "acces refuse (processus protege ou droits insuffisants)" }
        }

        try {
            $mbi = New-Object "Win32MemApi+MEMORY_BASIC_INFORMATION"
            $tailleStruct = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf([type]"Win32MemApi+MEMORY_BASIC_INFORMATION")
            $address = [Int64]0
            $limite = [Int64]0x7FFFFFFF0000
            $compteRegions = 0
            $maxRegions = 50000
            $regionsSuspectes = 0

            while ($address -lt $limite -and $compteRegions -lt $maxRegions) {
                $addrPtr = [IntPtr]$address
                $taille = [Win32MemApi]::VirtualQueryEx($hProcess, $addrPtr, [ref]$mbi, $tailleStruct)
                if ($taille -eq 0) { break }

                if ($mbi.State -eq $MEM_COMMIT -and $mbi.Type -eq $MEM_PRIVATE -and ($protectionsExecutables -contains $mbi.Protect)) {
                    $regionsSuspectes++
                }

                $regionSize = [Int64]$mbi.RegionSize
                if ($regionSize -le 0) { $regionSize = 0x1000 }
                $address += $regionSize
                $compteRegions++
            }
            return @{"regions_suspectes" = $regionsSuspectes; "erreur" = $null }
        } finally {
            [Win32MemApi]::CloseHandle($hProcess) | Out-Null
        }
    } catch {
        return @{"regions_suspectes" = 0; "erreur" = $_.Exception.Message }
    }
}

# ==========================================
# AUDIT SYSTEME
# ==========================================

function Audit-System {
    param($messageMajThreatIntel)

    Write-Host "=" * 70
    Write-Host "  AUDIT SYSTEME AVANCE - Threat Intel / Taches / AV / Pare-feu"
    Write-Host "  Auteur : $script:AUTEUR"
    Write-Host "  GitHub : $script:GITHUB_URL"
    Write-Host "=" * 70
    $tiCount = $script:TI.malicious_ips.Count + $script:TI.malicious_ip_ranges.Count + $script:TI.malicious_domains.Count
    Write-Host "Base threat intel chargee : $tiCount IOC + $($script:TI.dynamic_dns_domains.Count) dynamic DNS connus`n"

    Section "INFORMATIONS SYSTEME"
    Add-Report "Date : $(Get-Date)"
    Add-Report "Systeme : $env:COMPUTERNAME - $((Get-CimInstance Win32_OperatingSystem).Caption)"
    Add-Report "Machine : $env:COMPUTERNAME"
    Add-Report "Utilisateur : $env:USERNAME"
    Add-Report "Auteur du script : $script:AUTEUR"
    Add-Report "GitHub : $script:GITHUB_URL"
    Add-Report "Version du script : $script:VERSION"
    if ($messageMajThreatIntel) {
        Add-Report "Statut mise a jour threat intel : $messageMajThreatIntel"
    }

    # 1 - Connexions reseau
    Section "[1] ANALYSE DES CONNEXIONS RESEAU"
    try {
        $count = 0
        $ipPubliquesVues = @{}
        $netstat = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $netstat) {
            $process = Get-ProcessName -procId $conn.OwningProcess
            $ip = $conn.RemoteAddress
            $port = $conn.RemotePort
            $localAddr = "$($conn.LocalAddress):$($conn.LocalPort)"
            $remoteAddr = "$ip`:$port"
            $count++

            if (Test-PrivateIP $ip) {
                Add-Report "$($process.PadRight(25)) PID:$($conn.OwningProcess) | $localAddr -> $remoteAddr"
                continue
            }

            $matchDirecte = $script:TI.malicious_ips -contains $ip
            $matchRange = Test-IPDansRanges -ip $ip -ranges $script:TI.malicious_ip_ranges

            if ($matchDirecte -or $matchRange) {
                Add-Report "$($process.PadRight(25)) PID:$($conn.OwningProcess) | $localAddr -> $remoteAddr  MATCH THREAT INTEL"
                Ajouter-Alerte -niveau "CRITIQUE" -message "Connexion vers IP presente dans threat_intel.json: $ip (processus: $process)" -fort
                continue
            }

            $rdns = Resoudre-ReverseDNS -ip $ip
            if ($rdns) {
                $motif = Test-DomaineSuspect -domaine $rdns
                if ($motif) {
                    Add-Report "$($process.PadRight(25)) PID:$($conn.OwningProcess) | $localAddr -> $remoteAddr  ($rdns) ATTENTION: $motif"
                    Ajouter-Alerte -niveau "ELEVE" -message "Connexion vers $ip ($rdns) - $motif (processus: $process)"
                } else {
                    Add-Report "$($process.PadRight(25)) PID:$($conn.OwningProcess) | $localAddr -> $remoteAddr  ($rdns)"
                }
            } else {
                Add-Report "$($process.PadRight(25)) PID:$($conn.OwningProcess) | $localAddr -> $remoteAddr"
            }
            $ipPubliquesVues[$ip] = $true
        }

        if ($ipPubliquesVues.Count -ge $script:SEUIL_CONNEXIONS_SUSPECTES) {
            Ajouter-Alerte -niveau "INFO" -message "$($ipPubliquesVues.Count) IP publiques distinctes contactees (volume a verifier)"
        }
        Add-Report "`nTotal connexions actives : $count"
    } catch {
        Add-Report "Erreur : $_"
    }

    # 2 - Processus
    Section "[2] ANALYSE DES PROCESSUS"
    try {
        $processSuspects = @()
        $processes = Get-Process | Where-Object { $_.Id -ne 0 }
        $sorted = $processes | Sort-Object -Property WorkingSet -Descending | Select-Object -First 10
        foreach ($p in $sorted) {
            $memPercent = ($p.WorkingSet / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory) * 100
            Add-Report "$($p.Name.PadRight(30)) PID:$($p.Id.ToString().PadRight(7)) MEM:$([math]::Round($memPercent,2))%"
        }

        foreach ($p in $processes) {
            try {
                $nom = $p.Name
                $pid = $p.Id
                $cpu = $p.CPU
                $mem = $p.WorkingSet
                $cmdline = $p.CommandLine
                $cheminExe = $p.Path
                $ppid = $p.Parent.Id
                $nomParent = (Get-Process -Id $ppid -ErrorAction SilentlyContinue).Name
                $pidDejaSuspect = $false

                $motifNom = Test-NomProcessusSuspect -nomProcess $nom
                if ($motifNom) {
                    $processSuspects += $nom
                    $pidDejaSuspect = $true
                    if ($cheminExe) { Noter-CheminSignature -commande $cheminExe }
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Processus suspect: $nom (PID: $pid) - motif '$motifNom'" -fort
                }

                if ($cpu -gt 50) {
                    Ajouter-Alerte -niveau "ELEVE" -message "Processus consommant beaucoup de CPU: $nom (CPU: $([math]::Round($cpu,1))%)"
                }
                if (($mem / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory * 100) -gt 30) {
                    Ajouter-Alerte -niveau "MOYEN" -message "Processus consommant beaucoup de memoire: $nom (MEM: $([math]::Round($mem/1MB,1)) MB)"
                }

                # Masquerade
                $processusSysteme = @{
                    "svchost" = @($script:SYSTEM32, $script:SYSWOW64)
                    "lsass" = @($script:SYSTEM32)
                    "winlogon" = @($script:SYSTEM32)
                    "services" = @($script:SYSTEM32)
                    "csrss" = @($script:SYSTEM32)
                    "wininit" = @($script:SYSTEM32)
                    "smss" = @($script:SYSTEM32)
                    "spoolsv" = @($script:SYSTEM32)
                    "dwm" = @($script:SYSTEM32)
                    "explorer" = @($script:WINDIR)
                }
                if ($cheminExe -and $processusSysteme.ContainsKey($nom.ToLower())) {
                    $dossiersOk = $processusSysteme[$nom.ToLower()]
                    $cheminL = $cheminExe.ToLower()
                    $anormal = $true
                    foreach ($d in $dossiersOk) {
                        if ($cheminL.StartsWith($d.ToLower())) { $anormal = $false; break }
                    }
                    if ($anormal) {
                        $processSuspects += $nom
                        $pidDejaSuspect = $true
                        Noter-CheminSignature -commande $cheminExe
                        Ajouter-Alerte -niveau "CRITIQUE" -message "MASQUERADE: '$nom' (PID $pid) tourne depuis un emplacement anormal: $cheminExe" -fort
                    }
                }

                # Parent-enfant
                $parentsAttendus = @{
                    "svchost.exe" = @("services.exe")
                    "lsass.exe" = @("wininit.exe")
                    "services.exe" = @("wininit.exe")
                }
                $shellsSuspects = @("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
                $officeApps = @("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe")

                $nomL = $nom.ToLower()
                if ($parentsAttendus.ContainsKey($nomL) -and $nomParent) {
                    $attendus = $parentsAttendus[$nomL]
                    if ($nomParent.ToLower() -notin $attendus) {
                        $processSuspects += $nom
                        $pidDejaSuspect = $true
                        Noter-CheminSignature -commande $cheminExe
                        Ajouter-Alerte -niveau "CRITIQUE" -message "ANOMALIE PARENT-ENFANT: '$nom' (PID $pid) - parent anormal '$nomParent' (attendu: $($attendus -join '/'))" -fort
                    }
                }
                if ($nomL -in $shellsSuspects -and $nomParent -and $nomParent.ToLower() -in $officeApps) {
                    $processSuspects += $nom
                    $pidDejaSuspect = $true
                    Noter-CheminSignature -commande $cheminExe
                    Ajouter-Alerte -niveau "CRITIQUE" -message "ANOMALIE PARENT-ENFANT: '$nom' (PID $pid) - lance par '$nomParent' - pattern classique de macro malveillante" -fort
                }

                $motif = Test-ContientPattern -texte $cmdline -patterns $script:TI.suspicious_process_strings
                if ($motif) {
                    $pidDejaSuspect = $true
                    if ($cheminExe) { Noter-CheminSignature -commande $cheminExe }
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Ligne de commande suspecte pour $nom (PID $pid): motif '$motif'"
                }

                if ($pidDejaSuspect) {
                    $script:PIDS_A_ANALYSER_MEMOIRE[$pid] = $nom
                }
            } catch {}
        }

        if ($processSuspects) {
            Add-Report "`nATTENTION: $($processSuspects.Count) processus suspect(s) detecte(s)"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 3 - Ports
    Section "[3] ANALYSE DES PORTS ECOUTES"
    try {
        $portsTrouves = @()
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $listeners) {
            $process = Get-ProcessName -procId $conn.OwningProcess
            $port = $conn.LocalPort
            Add-Report "Port $($port.ToString().PadRight(6)) PID:$($conn.OwningProcess.ToString().PadRight(7)) $process"
            if ($port -in $script:PORTS_SUSPECTS) {
                $portsTrouves += $port
                Ajouter-Alerte -niveau "ELEVE" -message "Port suspect ouvert: $port (processus: $process)"
            }
        }
        if ($portsTrouves) {
            Add-Report "`nATTENTION: $($portsTrouves.Count) port(s) suspect(s) detecte(s)"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 4 - Taches planifiees
    Section "[4] ANALYSE DES TACHES PLANIFIEES (avec detection de modifications)"
    try {
        $snapshot, $erreurs = Scanner-TachesPlanifiees
        if ($snapshot.Count -eq 0) {
            Add-Report "Lecture C:\Windows\System32\Tasks impossible (droits admin requis)."
            $result = schtasks /query /fo LIST /v
            $blocs = $result -split "`n`n"
            $n = 0
            foreach ($bloc in $blocs) {
                if ($bloc -notmatch "TaskName") { continue }
                $n++
                $motif = Test-ContientPattern -texte $bloc -patterns $script:TI.suspicious_process_strings
                if ($motif) {
                    $nomLigne = ($bloc -split "`n" | Where-Object { $_ -match "TaskName" })[0]
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Tache avec commande suspecte ($motif): $nomLigne"
                }
            }
            Add-Report "Nombre de taches analysees (fallback) : $n"
        } else {
            Add-Report "$($snapshot.Count) taches lues" + $(if ($erreurs -gt 0) { " ($erreurs illisibles)" } else { "" })
            $baseline = Charger-BaselineTaches
            $nouvelles = @()
            $modifiees = @()
            $supprimees = @()

            if (-not $baseline) {
                Add-Report "Aucune baseline precedente : creation de la reference."
            } else {
                foreach ($rel in $snapshot.Keys) {
                    if (-not $baseline.PSObject.Properties.Name -contains $rel) {
                        $nouvelles += $rel
                    } elseif ($snapshot[$rel].hash -ne $baseline.$rel.hash) {
                        $modifiees += $rel
                    }
                }
                foreach ($rel in $baseline.PSObject.Properties.Name) {
                    if (-not $snapshot.ContainsKey($rel)) {
                        $supprimees += $rel
                    }
                }
            }

            foreach ($rel in $snapshot.Keys) {
                $info = $snapshot[$rel]
                $cmdComplet = $info.commands -join " "
                $motifCmd = Test-ContientPattern -texte $cmdComplet -patterns $script:TI.suspicious_process_strings
                $motifPath = Test-ContientPattern -texte $cmdComplet -patterns $script:TI.suspicious_path_fragments
                $estNouvelle = $rel -in $nouvelles
                $estModifiee = $rel -in $modifiees
                $suspectNom = Test-NomAleatoire -nom (Split-Path $rel -Leaf)
                $estNamespaceMicrosoft = $rel -match '^microsoft\\windows\\'

                if (($estNouvelle -or $estModifiee) -and ($motifCmd -or $info.hidden -or $motifPath -or $suspectNom)) {
                    $raisons = @()
                    if ($motifCmd) { $raisons += "commande suspecte '$motifCmd'" }
                    if ($motifPath) { $raisons += "chemin a risque '$motifPath'" }
                    if ($info.hidden -and -not $estNamespaceMicrosoft) { $raisons += "tache cachee (Hidden=true)" }
                    if ($suspectNom) { $raisons += "nom aleatoire" }
                    $niveau = if ($motifCmd) { "CRITIQUE" } else { "ELEVE" }
                    $statut = if ($estNouvelle) { "NOUVELLE" } else { "MODIFIEE" }
                    foreach ($c in $info.commands) { Noter-CheminSignature -commande $c }
                    Ajouter-Alerte -niveau $niveau -message "Tache $statut suspecte: $rel - $($raisons -join ', ')" -fort:($motifCmd -or $motifPath)
                    Add-Report "  ALERTE [$statut] $rel - $($raisons -join ', ')"
                } elseif ($estNouvelle -or $estModifiee) {
                    $statut = if ($estNouvelle) { "NOUVELLE" } else { "MODIFIEE" }
                    $nomAuteur = if ($info.author) { $info.author } else { 'inconnu' }
                    Add-Report "  INFO [$statut] $rel (auteur: $nomAuteur)"
                }
            }

            if ($baseline) {
                Add-Report "`nResume : $($nouvelles.Count) nouvelle(s), $($modifiees.Count) modifiee(s), $($supprimees.Count) supprimee(s)."
                if ($nouvelles.Count + $modifiees.Count -gt 10) {
                    Ajouter-Alerte -niveau "MOYEN" -message "Volume eleve de changements dans les taches ($($nouvelles.Count + $modifiees.Count))"
                }
                foreach ($rel in $supprimees | Select-Object -First 5) {
                    Add-Report "  SUPPRIMEE: $rel"
                }
            }
            Sauver-BaselineTaches -snapshot $snapshot
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 5 - DNS
    Section "[5] TEST DNS"
    try {
        $ip = [System.Net.Dns]::GetHostEntry("google.com").AddressList[0].IPAddressToString
        Add-Report "google.com -> $ip"
        if ($ip -eq "127.0.0.1") {
            Ajouter-Alerte -niveau "CRITIQUE" -message "Detournement DNS detecte (google.com -> 127.0.0.1)" -fort
        } else {
            Add-Report "OK Resolution DNS normale"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 6 - Fichiers temporaires
    Section "[6] ANALYSE DES FICHIERS TEMPORAIRES"
    try {
        $temp = $env:TEMP
        $extensions = @(".exe", ".bat", ".cmd", ".ps1", ".scr", ".vbs", ".js")
        $files = @(Get-ChildItem -Path $temp -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in $extensions })
        foreach ($f in $files | Select-Object -First 10) {
            Add-Report $f.Name
        }
        Add-Report "`nNombre trouve : $($files.Count)"
        if ($files.Count -gt 10) {
            Ajouter-Alerte -niveau "INFO" -message "Beaucoup de fichiers executables dans TEMP ($($files.Count))"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 7 - Hosts
    Section "[7] ANALYSE DU FICHIER HOSTS"
    try {
        $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $content = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
            foreach ($ligne in $content) {
                $l = $ligne.Trim()
                if (-not $l -or $l.StartsWith('#')) { continue }
                $parts = $l -split '\s+'
                if ($parts.Count -lt 2) { continue }
                $ip_h = $parts[0]
                $domaine_h = $parts[1]
                if ($domaine_h -match 'localhost') { continue }
                $motif = Test-DomaineSuspect -domaine $domaine_h
                $matchIP = ($script:TI.malicious_ips -contains $ip_h) -or (Test-IPDansRanges -ip $ip_h -ranges $script:TI.malicious_ip_ranges)
                if ($matchIP -or $motif) {
                    Add-Report "  ALERTE: $l"
                    $raison = if ($motif) { $motif } else { "IP presente dans threat_intel.json" }
                    Ajouter-Alerte -niveau $(if ($matchIP) { "CRITIQUE" } else { "ELEVE" }) -message "Entree hosts suspecte: $l - $raison"
                } elseif ($ip_h -in @('127.0.0.1', '0.0.0.0')) {
                    Add-Report "  $l"
                }
            }
        } else {
            Add-Report "Fichier hosts non trouve"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 8 - Registre
    Section "[8] ANALYSE DES CLES DE REGISTRE (PERSISTANCE)"
    try {
        function Scan-RunKey {
            param($hive, $hiveName, $chemin)
            try {
                $key = Get-Item -Path "${hive}:\$chemin" -ErrorAction SilentlyContinue
                if (-not $key) { return }
                $found = @()
                foreach ($val in $key.Property) {
                    $value = (Get-ItemProperty -Path "${hive}:\$chemin" -Name $val -ErrorAction SilentlyContinue).$val
                    $found += @{Name = $val; Value = $value}
                }
                if ($found.Count -gt 0) {
                    Add-Report "  $hiveName\$chemin"
                    foreach ($item in $found) {
                        Add-Report "    $($item.Name) = $($item.Value.Substring(0, [Math]::Min(80, $item.Value.Length)))"
                        Noter-CheminSignature -commande $item.Value
                        $motifCmd = Test-ContientPattern -texte $item.Value -patterns $script:TI.suspicious_process_strings
                        $motifPath = if (-not (Test-CheminFiable -texte $item.Value)) { Test-ContientPattern -texte $item.Value -patterns $script:TI.suspicious_path_fragments } else { $null }
                        if ($motifCmd) {
                            Ajouter-Alerte -niveau "CRITIQUE" -message "Cle de demarrage suspecte ($hiveName\$chemin\$($item.Name)): motif '$motifCmd'" -fort
                        } elseif ($motifPath) {
                            Ajouter-Alerte -niveau "MOYEN" -message "Cle de demarrage pointant vers un dossier a risque ($hiveName\$chemin\$($item.Name)): $motifPath"
                        }
                    }
                    if ($found.Count -gt 15) {
                        Ajouter-Alerte -niveau "INFO" -message "Nombreuses entrees dans $hiveName\$chemin ($($found.Count))"
                    }
                }
            } catch {}
        }

        $runPaths = @(
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )

        foreach ($chemin in $runPaths) {
            Scan-RunKey -hive "HKLM" -hiveName "HKLM" -chemin $chemin
            Scan-RunKey -hive "HKCU" -hiveName "HKCU" -chemin $chemin
        }

        try {
            $key = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
            if ($key) {
                foreach ($valName in @("Shell", "Userinit")) {
                    $val = (Get-ItemProperty -Path $key.PSPath -Name $valName -ErrorAction SilentlyContinue).$valName
                    if ($val) {
                        Add-Report "  Winlogon\$valName = $val"
                        Noter-CheminSignature -commande $val
                        if ($valName -eq "Shell" -and $val -ne "explorer.exe") {
                            Ajouter-Alerte -niveau "CRITIQUE" -message "Winlogon\Shell modifie: $val" -fort
                        }
                        if ($valName -eq "Userinit" -and $val -ne "C:\Windows\system32\userinit.exe,") {
                            Ajouter-Alerte -niveau "CRITIQUE" -message "Winlogon\Userinit modifie: $val" -fort
                        }
                    }
                }
            }
        } catch {}

        try {
            $key = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue
            if ($key) {
                $val = (Get-ItemProperty -Path $key.PSPath -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs
                if ($val -and $val.Trim()) {
                    Add-Report "  AppInit_DLLs = $val"
                    foreach ($dll in $val -split ' ') { Noter-CheminSignature -commande $dll }
                    Ajouter-Alerte -niveau "ELEVE" -message "AppInit_DLLs non vide: $val"
                }
            }
        } catch {}

        try {
            $base = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            $items = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $debugger = (Get-ItemProperty -Path $item.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                if ($debugger) {
                    Add-Report "  IFEO\$($item.PSChildName)\Debugger = $debugger"
                    Noter-CheminSignature -commande $debugger
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Debugger hijacking detecte sur $($item.PSChildName): $debugger" -fort
                }
            }
        } catch {}

        try {
            $servicesSuspects = 0
            $services = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
            foreach ($svc in $services) {
                $imagePath = (Get-ItemProperty -Path $svc.PSPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath
                if (-not $imagePath) { continue }
                if (Test-CheminFiable -texte $imagePath) { continue }
                $motifPath = Test-ContientPattern -texte $imagePath -patterns $script:TI.suspicious_path_fragments
                $motifCmd = Test-ContientPattern -texte $imagePath -patterns $script:TI.suspicious_process_strings
                if ($motifPath -or $motifCmd) {
                    $servicesSuspects++
                    Noter-CheminSignature -commande $imagePath
                    Ajouter-Alerte -niveau "ELEVE" -message "Service '$($svc.PSChildName)' avec ImagePath suspect: $($imagePath.Substring(0, [Math]::Min(100, $imagePath.Length)))"
                }
            }
            if ($servicesSuspects -gt 0) {
                Add-Report "  $servicesSuspects service(s) avec ImagePath suspect detecte(s)"
            }
        } catch {}
    } catch {
        Add-Report "Erreur : $_"
    }

    # 9 - Antivirus/Pare-feu
    Section "[9] ANTIVIRUS ET PARE-FEU"
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($fwProfiles) {
            foreach ($p in $fwProfiles) {
                $status = if ($p.Enabled) { "ACTIVE" } else { "DESACTIVEE" }
                Add-Report "  Pare-feu [$($p.Name)] : $status"
                if (-not $p.Enabled) {
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Pare-feu Windows desactive sur le profil '$($p.Name)'"
                }
            }
        } else {
            Add-Report "  Interrogation pare-feu impossible (droits admin requis)."
        }

        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $avOn = $defender.AntivirusEnabled
            $rtpOn = $defender.RealTimeProtectionEnabled
            $sigAge = $defender.AntivirusSignatureAge
            Add-Report "  Windows Defender - Antivirus actif : $(if ($avOn) { 'OUI' } else { 'NON' })"
            Add-Report "  Windows Defender - Protection temps reel : $(if ($rtpOn) { 'OUI' } else { 'NON' })"
            if ($sigAge -ne $null) { Add-Report "  Windows Defender - Age des signatures : $sigAge jour(s)" }
            if (-not $avOn) { Ajouter-Alerte -niveau "CRITIQUE" -message "Windows Defender desactive" }
            if ($avOn -and -not $rtpOn) { Ajouter-Alerte -niveau "CRITIQUE" -message "Protection temps reel Windows Defender desactivee" }
            if ($sigAge -gt 7) { Ajouter-Alerte -niveau "ELEVE" -message "Signatures antivirus obsoletes ($sigAge jours)" }
        } else {
            Add-Report "  Windows Defender non interrogeable."
        }

        $scAv = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($scAv) {
            foreach ($prod in $scAv) {
                $nom = $prod.displayName
                $actif, $aJour = Decoder-ProductState -state $prod.productState
                $statut = if ($actif) { "ACTIVE" } else { "DESACTIVE" }
                $maj = if ($aJour) { "a jour" } else { "signatures potentiellement obsoletes" }
                Add-Report "  Antivirus declare (Security Center) : $nom - $statut, $maj"
                if ($actif -eq $false) {
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Antivirus '$nom' declare desactive"
                }
            }
        } else {
            Add-Report "  Aucun antivirus tiers declare au Security Center."
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 10 - Signatures
    Section "[10] VERIFICATION DES SIGNATURES NUMERIQUES"
    try {
        $cheminsDedup = @($script:CHEMINS_SIGNATURE | Select-Object -Unique)
        if ($cheminsDedup.Count -eq 0) {
            Add-Report "Aucun binaire de demarrage a verifier."
        } else {
            Add-Report "$($cheminsDedup.Count) binaire(s) de demarrage/persistance a verifier..."
            $nonSignes = 0
            $introuvables = 0
            $valides = 0
            foreach ($chemin in $cheminsDedup) {
                $cheminExp = [System.Environment]::ExpandEnvironmentVariables($chemin)
                if ($cheminExp -notmatch '[\\/]') {
                    # Nom de fichier seul, sans dossier (ex: Winlogon\Shell = explorer.exe) :
                    # on tente System32/SysWOW64/Windows avant d'abandonner en INTROUVABLE.
                    $candidats = @(
                        (Join-Path $env:WINDIR "System32\$cheminExp"),
                        (Join-Path $env:WINDIR "SysWOW64\$cheminExp"),
                        (Join-Path $env:WINDIR $cheminExp)
                    )
                    $trouve = $candidats | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
                    if ($trouve) { $cheminExp = $trouve }
                }
                if (-not (Test-Path $cheminExp)) {
                    $introuvables++
                    Add-Report "  INTROUVABLE: $cheminExp"
                    continue
                }
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $cheminExp -ErrorAction SilentlyContinue
                    if ($sig.Status -eq "Valid") {
                        $valides++
                        Add-Report "  OK $cheminExp - signe"
                    } elseif ($sig.Status -in @("HashMismatch", "NotTrusted")) {
                        $nonSignes++
                        Add-Report "  ALERTE: $cheminExp - signature INVALIDE/ALTEREE ($($sig.Status))"
                        Ajouter-Alerte -niveau "CRITIQUE" -message "Signature invalide sur $cheminExp ($($sig.Status))" -fort
                    } else {
                        $nonSignes++
                        Add-Report "  ATTENTION: $cheminExp - NON SIGNE ($($sig.Status))"
                        Ajouter-Alerte -niveau "MOYEN" -message "Binaire non signe: $cheminExp"
                    }
                } catch {
                    $nonSignes++
                    Add-Report "  ATTENTION: $cheminExp - NON SIGNE (erreur)"
                }
            }
            Add-Report "`nResume : $valides signe(s), $nonSignes non signe(s), $introuvables introuvable(s)"
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 11 - Analyse memoire
    Section "[11] ANALYSE MEMOIRE"
    try {
        if ($script:PIDS_A_ANALYSER_MEMOIRE.Count -eq 0) {
            Add-Report "Aucun processus signale - pas d'analyse memoire."
        } else {
            Add-Report "$($script:PIDS_A_ANALYSER_MEMOIRE.Count) processus suspects - analyse memoire..."
            foreach ($pid in $script:PIDS_A_ANALYSER_MEMOIRE.Keys) {
                $nom = $script:PIDS_A_ANALYSER_MEMOIRE[$pid]
                $resultat = Scanner-RegionsMemoireSuspectes -pid $pid
                if ($resultat.erreur) {
                    Add-Report "  $nom (PID $pid) - analyse impossible : $($resultat.erreur)"
                } elseif ($resultat.regions_suspectes -gt 0) {
                    Add-Report "  ALERTE: $nom (PID $pid) - $($resultat.regions_suspectes) region(s) memoire executable(s) sans fichier"
                    Ajouter-Alerte -niveau "CRITIQUE" -message "Regions memoire executables dans '$nom' (PID $pid)" -fort
                } else {
                    Add-Report "  OK $nom (PID $pid) - aucune region suspecte"
                }
            }
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # 12 - WMI
    Section "[12] ABONNEMENTS WMI"
    try {
        $filtres = @(Get-CimInstance -Namespace "root/subscription" -ClassName __EventFilter -ErrorAction SilentlyContinue)
        $consommateurs = @()
        $consommateurs += Get-CimInstance -Namespace "root/subscription" -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
        $consommateurs += Get-CimInstance -Namespace "root/subscription" -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        $liaisons = @(Get-CimInstance -Namespace "root/subscription" -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)

        # "SCM Event Log Filter/Consumer" est natif Windows, present par defaut sur la
        # quasi-totalite des installations. Sans exemption, l'alerte se declencherait sur
        # toutes les machines, tout le temps - aligne sur le .py de reference.
        $nomsWmiFiables = @("scm event log filter", "scm event log consumer")
        $estFiableWmi = { param($nom) $nom -and ($nomsWmiFiables -contains $nom.Trim().ToLower()) }

        $filtresSuspects = @($filtres | Where-Object { -not (& $estFiableWmi $_.Name) })
        $consommateursSuspects = @($consommateurs | Where-Object { -not (& $estFiableWmi $_.Name) })

        if ($filtres.Count -eq 0 -and $consommateurs.Count -eq 0 -and $liaisons.Count -eq 0) {
            Add-Report "Aucun abonnement WMI permanent detecte."
        } elseif ($filtresSuspects.Count -eq 0 -and $consommateursSuspects.Count -eq 0) {
            Add-Report "OK Seul le composant natif Windows 'SCM Event Log' detecte - normal et attendu, aucune alerte."
            foreach ($f in $filtres) {
                Add-Report "  Filtre (natif Windows): $($f.Name) - requete: $($f.Query)"
            }
        } else {
            Add-Report "ATTENTION: $($filtresSuspects.Count) filtre(s), $($consommateursSuspects.Count) consommateur(s) non reconnu(s) comme natifs, sur $($filtres.Count) filtre(s)/$($liaisons.Count) liaison(s) au total."
            foreach ($f in $filtres) {
                $tag = if (& $estFiableWmi $f.Name) { " (natif Windows, RAS)" } else { "" }
                Add-Report "  Filtre: $($f.Name)$tag - requete: $($f.Query)"
            }
            foreach ($c in $consommateurs) {
                $detail = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { $c.ScriptText }
                $tag = if (& $estFiableWmi $c.Name) { " (natif Windows, RAS)" } else { "" }
                Add-Report "  Consommateur: $($c.Name)$tag - action: $($detail)"
            }
            foreach ($b in $liaisons) {
                Add-Report "  Liaison: $($b.Filter) -> $($b.Consumer)"
            }
            if ($filtresSuspects.Count -gt 0 -or $consommateursSuspects.Count -gt 0) {
                Ajouter-Alerte -niveau "ELEVE" -message "$($filtresSuspects.Count) filtre(s)/$($consommateursSuspects.Count) consommateur(s) WMI non reconnu(s) comme natifs - a verifier manuellement"
            }
        }
    } catch {
        Add-Report "Erreur : $_"
    }

    # ==========================================
    # VERDICT FINAL AVEC RECTANGLE COLORÉ
    # ==========================================
    Section "DIAGNOSTIC FINAL"
    Add-Report "Score de risque: $script:SCORE"

    if ($script:ALERTES_FORTES.Count -ge 3) {
        $niveauCouleur = "ROUGE"
        $statut = "Ce PC est INFECTE"
        $desc = "$($script:ALERTES_FORTES.Count) indicateur(s) fort(s) - Une compromission est tres probable."
    } elseif ($script:ALERTES_FORTES.Count -gt 0) {
        $niveauCouleur = "ORANGE"
        $statut = "Ce PC est SUSPECT"
        $desc = "$($script:ALERTES_FORTES.Count) indicateur(s) fort(s) - Des elements serieux meritent une verification."
    } elseif ($script:SCORE -ge 3) {
        $niveauCouleur = "VERT"
        $statut = "PC visiblement SAIN, mais quelques points a verifier"
        $desc = "Aucun indicateur fort, mais des anomalies mineures."
    } else {
        $niveauCouleur = "VERT"
        $statut = "Ce PC est SAIN"
        $desc = "Aucun element suspect detecte."
    }

   
    # Afficher le rectangle coloré
    Afficher-RectangleVerdict -niveau $niveauCouleur -titre $statut -sous_texte $desc

    if ($script:ALERTES.Count -gt 0) {
        Add-Report "`n$($script:ALERTES.Count) alerte(s) detectee(s) :"
        foreach ($alerte in $script:ALERTES | Select-Object -First 15) {
            Add-Report "  $alerte"
        }
        if ($script:ALERTES.Count -gt 15) {
            Add-Report "  ... et $($script:ALERTES.Count - 15) autres alertes"
        }
    }

    # Sauvegarde
    try {
        $desktop = [Environment]::GetFolderPath("Desktop")
        $n = 1
        while (Test-Path "$desktop\Rapport d'audit N°$n.txt") { $n++ }
        $reportFile = "$desktop\Rapport d'audit N°$n.txt"
        $script:REPORT | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Host "`nRAPPORT SAUVEGARDE : $reportFile"
    } catch {
        $reportFile = Join-Path $script:BASE_DIR "Rapport d'audit.txt"
        $script:REPORT | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Host "`nRAPPORT SAUVEGARDE (local) : $reportFile"
    }
}

# ==========================================
# POINT D'ENTREE
# ==========================================

$noUpdate = $false
$update = $false

foreach ($arg in $args) {
    if ($arg -eq "-noUpdate" -or $arg -eq "--no-update") { $noUpdate = $true }
    if ($arg -eq "-update" -or $arg -eq "--update") { $update = $true }
}

if ($update) {
    MettreAJour-ThreatIntel
    $script:TI = Charger-ThreatIntel
    $messageMaj = "Mise a jour forcee manuellement via --update."
    if ($args.Count -eq 1) {
        Write-Host "`nAppuyez sur ENTER pour fermer..."
        Read-Host
        exit
    }
} else {
    $messageMaj = VerifierEtMajThreatIntel -noUpdate:$noUpdate
}

try {
    Audit-System -messageMajThreatIntel $messageMaj
} catch {
    Write-Host "Erreur generale : $_"
} finally {
    Write-Host "`nAppuyez sur ENTER pour fermer..."
    Read-Host
}