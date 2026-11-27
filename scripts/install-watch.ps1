# Remplace la tache "ParsecDisplaySwitch Watch" par "C2C Watch" (c2c.exe watch --execute).
# Par defaut : AFFICHE seulement ce qui serait fait. -Apply pour appliquer, -Rollback pour revenir en arriere.
# Ne touche ni a "ParsecVDD Repair" ni a "ParsecVDisplay Autostart" (reparation/creation de l'ecran virtuel).
param([switch]$Apply, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$old  = 'ParsecDisplaySwitch Watch'
$new  = 'C2C Watch'
$dir  = (Join-Path $env:USERPROFILE 'C2C')
$exe  = Join-Path $dir 'c2c.exe'
$src  = Join-Path $PSScriptRoot '..\target\release\c2c.exe'

function Step($t) { Write-Host ("{0}{1}" -f $(if ($Apply -or $Rollback) { '' } else { '[simulation] ' }), $t) }
$do = $Apply -or $Rollback

if ($Rollback) {
    Step "arret et suppression de '$new'"
    if ($do) { Stop-ScheduledTask -TaskName $new -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $new -Confirm:$false -ErrorAction SilentlyContinue }
    Step "reactivation et demarrage de '$old'"
    if ($do) { Enable-ScheduledTask -TaskName $old | Out-Null; Start-ScheduledTask -TaskName $old }
    return
}

if (-not (Test-Path -LiteralPath $src)) { throw "Binaire absent : cargo build --release d'abord ($src)" }
Step "copie de c2c.exe vers $dir"
Step "arret et DESACTIVATION de '$old' (jamais deux surveillances en meme temps)"
Step "creation de '$new' : a l'ouverture de session, c2c.exe watch --execute, utilisateur courant, sans elevation"
if (-not $Apply) { return }

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Stop-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'display\.ps1' -and $_.CommandLine -match '-Mode\s+Watch' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Disable-ScheduledTask -TaskName $old | Out-Null
Copy-Item -LiteralPath $src -Destination $exe -Force
$action   = New-ScheduledTaskAction -Execute $exe -Argument 'watch --execute' -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $new -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited -Force | Out-Null
Start-ScheduledTask -TaskName $new
Write-Host "Fait. Retour arriere : .\install-watch.ps1 -Rollback"
