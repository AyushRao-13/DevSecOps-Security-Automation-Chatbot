<#
    capture.ps1
    Universal Windows Forensic Collection Script
    Supports: PowerShell 2.0 → 7.x, Win7 → Win11, Server 2008 → 2025
#>

#------------------ SETUP ------------------#
$BaseDrive = "E:"
$Base = Join-Path $BaseDrive "forensics"
$Dirs = "$Base","$Base\winevt","$Base\registry","$Base\memory","$Base\network","$Base\artifacts"
$LogFile = Join-Path $Base "forensics_run.log"
$CsvFile = Join-Path $Base "forensics_hashes.csv"
$StartTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$NetshTraceFile = Join-Path $Base "network_trace.etl"
$StopNetshTraceAfterSeconds = 0

$WinPmemExe = "winpmem.exe"
$DumpItExe  = "DumpIt.exe"

#------------------ FUNCTIONS ------------------#

function Write-Log {
    param([string]$Msg,[string]$Level="INFO")
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$t [$Level] $Msg" | Tee-Object -Append -FilePath $LogFile
}

function Ensure-Dirs {
    foreach ($d in $Dirs) {
        if (-not (Test-Path $d)) { New-Item -Force -ItemType Directory -Path $d | Out-Null }
    }
}

function Safe-Run {
    param([string]$Cmd,[string]$Out)
    try {
        Write-Log "Running: $Cmd"
        if ($Cmd -match "\|") {
            powershell -NoProfile -Command $Cmd | Out-File -FilePath $Out -Force -Encoding UTF8
        } else {
            cmd /c "$Cmd" > $Out 2>&1
        }
        Write-Log "Saved output to $Out"
    } catch { Write-Log "Error: $_" "ERROR" }
}

function Add-Hash {
    param([string]$File)
    if (-not (Test-Path $File)) { return }
    try {
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $File).Hash
        } else {
            $out = (& certutil -hashfile "$File" SHA256) 2>$null
            $hash = ($out | Select-String -Pattern "^[0-9A-F]{64}$").Line
        }
        "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),$File,$hash" |
            Out-File -Append -FilePath $CsvFile -Encoding ASCII
    } catch { Write-Log "Hash fail: $_" "WARN" }
}

#------------------ START ------------------#

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544)) {
    Write-Host "Run PowerShell as Administrator!" ; exit
}

Ensure-Dirs
"Timestamp,File,SHA256" | Out-File -FilePath $CsvFile -Encoding ascii -Force
Write-Log "=== Forensic Capture Started $StartTime ==="

#------------------ SYSTEM INFO ------------------#

Safe-Run "tasklist /v" "$Base\tasklist.txt"
Safe-Run "query user" "$Base\users.txt"

try {
    Get-Process | Select-Object Id,ProcessName,StartTime |
        Export-Csv "$Base\processes.txt" -NoTypeInformation
} catch {
    Safe-Run "wmic process get ProcessId,Name,CreationDate" "$Base\processes.txt"
}

Safe-Run "whoami /all" "$Base\whoami.txt"

#------------------ NETWORK INFO ------------------#
Safe-Run "netstat -ano" "$Base\netstat.txt"
Safe-Run "arp -a" "$Base\arp.txt"
Safe-Run "route print" "$Base\route.txt"
Safe-Run "ipconfig /displaydns" "$Base\dns_cache.txt"

#------------------ MEMORY CAPTURE ------------------#

$memOutput = "$Base\memory\memory.raw"

$WinPmemCmd = Get-Command $WinPmemExe -ErrorAction SilentlyContinue
$DumpItCmd  = Get-Command $DumpItExe  -ErrorAction SilentlyContinue

if ($WinPmemCmd) {
    Write-Log "Running winpmem..."
    & $WinPmemCmd.Source --format raw --output $memOutput |
        Out-File "$Base\memory\winpmem_log.txt"
}
elseif ($DumpItCmd) {
    Write-Log "Running DumpIt..."
    & $DumpItCmd.Source /OUTPUTPATH=$Base\memory |
        Out-File "$Base\memory\dumpit_log.txt"
}
else {
    Write-Log "Memory acquisition tools missing." "WARN"
}

#------------------ PACKET TRACE (OPTIONAL) ------------------#

if (Get-Command netsh -ErrorAction SilentlyContinue) {
    Safe-Run "netsh trace start capture=yes tracefile=`"$NetshTraceFile`"" "$Base\network\netsh_start.txt"

    if ($StopNetshTraceAfterSeconds -gt 0) {
        Start-Sleep -Seconds $StopNetshTraceAfterSeconds
        Safe-Run "netsh trace stop" "$Base\network\netsh_stop.txt"
    }
}

#------------------ EVENT LOGS (EXPORT ALL) ------------------#

Write-Log "Exporting ALL Windows Event Logs..."
$w = "$Base\winevt"

$AllLogs = wevtutil el
$AllLogs | Out-File "$w\wevt_list.txt"

foreach ($log in $AllLogs) {
    $safe = $log -replace '[\\/:\*\?"<>\|]', '_'     # filename-safe
    $evtx = Join-Path $w "$safe.evtx"
    $txt  = Join-Path $w "export_$safe.txt"

    Write-Log "Exporting event log: $log"
    try {
        wevtutil epl "$log" "$evtx" 2>&1 | Out-File $txt -Force
    }
    catch {
        Write-Log "EVTX export failed for $log : $_" "ERROR"
    }
}

#------------------ REGISTRY HIVES ------------------#

$reg = "$Base\registry"

Safe-Run "reg save HKLM\SYSTEM `"$reg\SYSTEM.hiv`"" "$reg\regsave_system.txt"
Safe-Run "reg save HKLM\SOFTWARE `"$reg\SOFTWARE.hiv`"" "$reg\regsave_soft.txt"
Safe-Run "reg save HKLM\SAM `"$reg\SAM.hiv`"" "$reg\regsave_sam.txt"
Safe-Run "reg save HKLM\SECURITY `"$reg\SECURITY.hiv`"" "$reg\regsave_sec.txt"

if (Test-Path "$env:USERPROFILE\NTUSER.DAT") {
    Copy-Item "$env:USERPROFILE\NTUSER.DAT" "$reg\$env:USERNAME`_NTUSER.DAT" -Force
}

#------------------ SHELLBAGS / ARTIFACTS ------------------#

foreach ($loc in "C:\hellbags","$env:ProgramData\hellbags","$env:USERPROFILE\hellbags") {
    if (Test-Path $loc) {
        Copy-Item $loc "$Base\artifacts\hellbags" -Recurse -Force
        Write-Log "Copied shellbags from $loc"
        break
    }
}

#------------------ HASH ALL COLLECTED FILES ------------------#

Get-ChildItem -Path $Base -Recurse -File | ForEach-Object {
    Add-Hash $_.FullName
}

#------------------ END ------------------#

$EndTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
Write-Log "=== Capture Complete $EndTime ==="
Write-Log "Hash log saved: $CsvFile"
Write-Log "Run log saved: $LogFile"

Write-Host "`nForensic Collection Complete."
Write-Host "Output saved to: $Base"
