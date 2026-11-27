# Agent C2C permanent : tache planifiee « C2C Agent » (c2c.exe agent-serve) lancee a l'ouverture de session de l'utilisateur.
# L'agent lit sa cle dans 1Password au demarrage : l'application 1Password doit etre deverrouillee (et l'integration CLI active) ;
# a defaut il s'arrete et la tache le relance toutes les 2 minutes (jusqu'a 99 fois). La premiere lecture peut afficher une
# fenetre d'autorisation 1Password sur le PC fixe : l'accepter.
# Ecoute sur l'IP Tailscale du PC fixe UNIQUEMENT (voir [agent] bind dans c2c.toml) ; regle pare-feu : scripts\agent-pare-feu.ps1.
# Par defaut : simulation. -Apply : cree et demarre la tache. -Rollback : arrete et supprime la tache et l'agent.
# Sans elevation (comme C2C Watch) ; ne touche ni au Watch, ni a Sunshine, ni a l'affichage.
param([switch]$Apply, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$name = 'C2C Agent'
$dir  = (Join-Path $env:USERPROFILE 'C2C')
$exe  = Join-Path $dir 'c2c.exe'
$conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'

function Stop-Agent {
    Get-CimInstance Win32_Process -Filter "Name='c2c.exe'" | Where-Object { $_.CommandLine -match 'agent-serve' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
}

if (-not ($Apply -or $Rollback)) {
    Write-Host "SIMULATION (rien n'est modifie). Utiliser -Apply ou -Rollback."
    Write-Host "c2c.exe present : $(Test-Path $exe) ; tache '$name' presente : $([bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue))"
    Write-Host "-Apply    : tache '$name' a l'ouverture de session (delai 45 s), sans fenetre, utilisateur courant, relance en cas d'echec."
    Write-Host "-Rollback : arrete l'agent et supprime la tache."
    return
}
if ($Rollback) {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Stop-Agent
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Tache '$name' supprimee, agent arrete."
    return
}
if (-not (Test-Path $exe)) { throw "c2c.exe introuvable : $exe" }
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw "La tache '$name' existe deja ; lancer -Rollback d'abord." }
Select-String -Path (Join-Path $dir 'c2c.toml') -Pattern '^\[agent\]' -Quiet | ForEach-Object { if (-not $_) { throw "Section [agent] absente de c2c.toml." } }

$action   = New-ScheduledTaskAction -Execute $conhost -Argument "--headless `"$exe`" agent-serve" -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$trigger.Delay = 'PT45S'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited -Description 'C2C : agent (ping/status) joignable depuis le tailnet. Cle lue dans 1Password.' | Out-Null
Start-ScheduledTask -TaskName $name
Write-Host "Tache '$name' creee et demarree. Accepter l'eventuelle fenetre 1Password. Retour arriere : .\install-agent.ps1 -Rollback"
