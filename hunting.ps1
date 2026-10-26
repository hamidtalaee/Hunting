# ==========================================
# Windows Threat Hunting - Read Only
# ==========================================

$Time = Get-Date -Format "yyyyMMdd_HHmmss"
$Out = "$env:USERPROFILE\Desktop\ThreatHunt_$Time"

New-Item -ItemType Directory -Path $Out -Force | Out-Null

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " WINDOWS THREAT HUNTING" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------
# 1. Running Processes
# ------------------------------------------

Write-Host "[+] Checking running processes..." -ForegroundColor Yellow

$Processes = Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine

$Processes |
Export-Csv "$Out\Processes.csv" -NoTypeInformation -Encoding UTF8

# Suspicious process locations
$SuspiciousProcesses = $Processes | Where-Object {
$_.ExecutablePath -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\"
}

$SuspiciousProcesses |
Export-Csv "$Out\Suspicious_Processes.csv" -NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 2. PowerShell / CMD / WMI Hunting
# ------------------------------------------

Write-Host "[+] Hunting suspicious command lines..." -ForegroundColor Yellow

$Keywords = @(
"-enc",
"-encodedcommand",
"FromBase64String",
"DownloadString",
"DownloadFile",
"Invoke-WebRequest",
"IEX",
"Invoke-Expression",
"Start-BitsTransfer",
"certutil",
"bitsadmin",
"mshta",
"regsvr32",
"rundll32",
"wmic",
"powershell",
"cmd.exe /c",
"vssadmin",
"wevtutil",
"net user",
"net group",
"whoami",
"nltest",
"quser"
)

$SuspiciousCommands = foreach ($p in $Processes) {

if ($p.CommandLine) {

foreach ($k in $Keywords) {

if ($p.CommandLine -match [regex]::Escape($k)) {

[PSCustomObject]@{
ProcessId = $p.ProcessId
ParentPID = $p.ParentProcessId
Process = $p.Name
Path = $p.ExecutablePath
Command = $p.CommandLine
Indicator = $k
}

break
}
}
}
}

$SuspiciousCommands |
Export-Csv "$Out\Suspicious_CommandLines.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 3. Network Connections
# ------------------------------------------

Write-Host "[+] Checking active network connections..." -ForegroundColor Yellow

$Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

$NetworkResults = foreach ($c in $Connections) {

$p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue

[PSCustomObject]@{
LocalIP = $c.LocalAddress
LocalPort = $c.LocalPort
RemoteIP = $c.RemoteAddress
RemotePort = $c.RemotePort
PID = $c.OwningProcess
Process = $p.ProcessName
}
}

$NetworkResults |
Export-Csv "$Out\Network_Connections.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 4. Scheduled Tasks
# ------------------------------------------

Write-Host "[+] Checking scheduled tasks..." -ForegroundColor Yellow

$Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
ForEach-Object {

$Task = $_

try {

$Info = Get-ScheduledTaskInfo `
-TaskName $Task.TaskName `
-TaskPath $Task.TaskPath `
-ErrorAction SilentlyContinue

[PSCustomObject]@{
TaskName = $Task.TaskName
Path = $Task.TaskPath
State = $Task.State
LastRun = $Info.LastRunTime
NextRun = $Info.NextRunTime
}
}
catch {}
}

$Tasks |
Export-Csv "$Out\Scheduled_Tasks.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 5. Services
# ------------------------------------------

Write-Host "[+] Checking services..." -ForegroundColor Yellow

Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
Export-Csv "$Out\Services.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 6. Startup
# ------------------------------------------

Write-Host "[+] Checking startup entries..." -ForegroundColor Yellow

$Startup = Get-CimInstance Win32_StartupCommand |
Select-Object Name,Command,Location,User

$Startup |
Export-Csv "$Out\Startup.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 7. Local Users
# ------------------------------------------

Write-Host "[+] Checking local users..." -ForegroundColor Yellow

Get-LocalUser |
Select-Object Name,Enabled,LastLogon,PasswordLastSet |
Export-Csv "$Out\Local_Users.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 8. Windows Defender
# ------------------------------------------

Write-Host "[+] Checking Defender detections..." -ForegroundColor Yellow

Get-MpThreatDetection -ErrorAction SilentlyContinue |
Select-Object DetectionID,ThreatID,InitialDetectionTime,
ThreatStatus,Resources |
Export-Csv "$Out\Defender_Detections.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 9. PowerShell Event Logs
# ------------------------------------------

Write-Host "[+] Checking PowerShell logs..." -ForegroundColor Yellow

Get-WinEvent `
-FilterHashtable @{
LogName='Microsoft-Windows-PowerShell/Operational'
StartTime=(Get-Date).AddDays(-7)
} `
-ErrorAction SilentlyContinue |
Select-Object TimeCreated,Id,LevelDisplayName,Message |
Export-Csv "$Out\PowerShell_Events.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 10. Security Events
# ------------------------------------------

Write-Host "[+] Checking Security events..." -ForegroundColor Yellow

$EventIDs = 4624,4625,4672,4688,4697,4698,7045

Get-WinEvent `
-FilterHashtable @{
LogName='Security'
Id=$EventIDs
StartTime=(Get-Date).AddDays(-3)
} `
-ErrorAction SilentlyContinue |
Select-Object TimeCreated,Id,ProviderName,Message |
Export-Csv "$Out\Security_Events.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 11. Recent Files in suspicious locations
# ------------------------------------------

Write-Host "[+] Checking recent files..." -ForegroundColor Yellow

$Locations = @(
"$env:TEMP",
"$env:LOCALAPPDATA\Temp",
"$env:PUBLIC\Downloads"
)

$RecentFiles = foreach ($Path in $Locations) {

if (Test-Path $Path) {

Get-ChildItem $Path -File -Recurse `
-ErrorAction SilentlyContinue |
Where-Object {
$_.LastWriteTime -gt (Get-Date).AddDays(-3)
} |
Select-Object FullName,Length,CreationTime,LastWriteTime
}
}

$RecentFiles |
Export-Csv "$Out\Recent_Files.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# 12. Hash suspicious executables
# ------------------------------------------

Write-Host "[+] Hashing suspicious executables..." -ForegroundColor Yellow

$Hashes = foreach ($file in $RecentFiles) {

if ($file.FullName -match "\.(exe|dll|ps1|bat|cmd|vbs|js)$") {

try {

$hash = Get-FileHash `
-Path $file.FullName `
-Algorithm SHA256 `
-ErrorAction Stop

[PSCustomObject]@{
File = $file.FullName
SHA256 = $hash.Hash
}
}
catch {}
}
}

$Hashes |
Export-Csv "$Out\File_Hashes.csv" `
-NoTypeInformation -Encoding UTF8


# ------------------------------------------
# Summary
# ------------------------------------------

$Summary = @"

WINDOWS THREAT HUNTING REPORT
==============================

Computer : $env:COMPUTERNAME
User : $env:USERNAME
Time : $(Get-Date)

Suspicious Processes : $($SuspiciousProcesses.Count)
Suspicious Commands : $($SuspiciousCommands.Count)
Network Connections : $($NetworkResults.Count)
Recent Files : $($RecentFiles.Count)
File Hashes : $($Hashes.Count)

Output:
$Out

IMPORTANT:
This is a hunting/collection report.
Findings require analyst validation.
"@

$Summary | Out-File "$Out\SUMMARY.txt" -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "HUNTING COMPLETED" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Report: $Out" -ForegroundColor Yellow
Write-Host ""