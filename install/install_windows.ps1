# Palisade agent installer for Windows. Run in an elevated PowerShell:
#   .\install_windows.ps1 -Server http://YOUR-SERVER:8787
param([Parameter(Mandatory=$true)][string]$Server)
$ErrorActionPreference = "Stop"
$dir = "C:\Program Files\Palisade"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item "$PSScriptRoot\..\agent\palisade_agent.py" "$dir\palisade_agent.py" -Force
# requires Python 3 on PATH
python -m pip install --quiet psutil
$py = (Get-Command python).Source
$action  = New-ScheduledTaskAction -Execute $py `
  -Argument "`"$dir\palisade_agent.py`" --server $Server --state `"$dir\state.json`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$set     = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName "PalisadeAgent" -Action $action -Trigger $trigger `
  -Principal $princ -Settings $set -Force
Start-ScheduledTask -TaskName "PalisadeAgent"
Write-Host "Palisade agent installed and started as SYSTEM scheduled task 'PalisadeAgent'."
