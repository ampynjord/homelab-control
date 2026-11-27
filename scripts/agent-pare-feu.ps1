# Pare-feu de l'agent C2C : autorise c2c.exe en entrant sur TCP 7443 UNIQUEMENT depuis le tailnet (100.64.0.0/10).
# Par defaut : simulation. -Apply : cree la regle 'C2C Agent (tailnet)'. -Rollback : la supprime.
# A lancer dans un PowerShell administrateur sur le PC fixe. Ne coupe aucun flux (Sunshine/RDP inchanges).
param([switch]$Apply, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$exe  = (Join-Path $env:USERPROFILE 'C2C\c2c.exe')
$rule = 'C2C Agent (tailnet)'

$exists = [bool](Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)
if (-not ($Apply -or $Rollback)) {
    Write-Host "SIMULATION (rien n'est modifie). Utiliser -Apply ou -Rollback."
    Write-Host "c2c.exe present : $(Test-Path $exe) ; regle '$rule' presente : $exists"
    Write-Host "-Apply    : entrant, TCP 7443, programme $exe, distant 100.64.0.0/10, tous profils."
    Write-Host "-Rollback : supprime la regle '$rule'."
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ce script doit etre lance dans un PowerShell administrateur."
}
if ($Rollback) {
    Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "Regle '$rule' supprimee."
}
else {
    if (-not (Test-Path $exe)) { throw "c2c.exe introuvable : $exe" }
    if ($exists) { throw "La regle '$rule' existe deja ; lancer -Rollback d'abord." }
    New-NetFirewallRule -DisplayName $rule -Description 'C2C : agent joignable uniquement depuis le tailnet.' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 7443 -Program $exe -RemoteAddress '100.64.0.0/10' -Profile Any | Out-Null
    Write-Host "Regle '$rule' creee."
}
