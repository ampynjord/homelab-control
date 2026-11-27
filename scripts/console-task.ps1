# Tache planifiee SYSTEM « C2C ramener console » : lance `tscon 1 /dest:console` pour ramener la session de l'utilisateur
# sur la console quand elle est restee « deconnectee » (fin d'un RDP). C2C Watch la declenche (schtasks /run) ; sans elle,
# le deverrouillage depuis Moonlight reconnecte la session et fait redemarrer Sunshine (flux coupe).
# Par defaut : simulation. -Apply : cree la tache (aucun declencheur, lancement a la demande seulement). -Rollback : la supprime.
# A lancer dans un PowerShell administrateur. Aucun fichier modifiable par l'utilisateur n'est execute par la tache.
param([switch]$Apply, [switch]$Rollback, [string]$runner = $env:USERNAME)
$ErrorActionPreference = 'Stop'
$name = 'C2C ramener console'
$tscon = Join-Path $env:SystemRoot 'System32\tscon.exe'

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not ($Apply -or $Rollback)) {
    Write-Host "SIMULATION (rien n'est modifie). Utiliser -Apply ou -Rollback."
    Write-Host "tscon present : $(Test-Path $tscon) ; tache existante : $([bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue))"
    Write-Host "-Apply    : cree '$name' (SYSTEM, a la demande) = tscon de la session deconnectee de $runner vers la console"
    Write-Host "-Rollback : supprime '$name'."
    return
}
if (-not (Test-Admin)) { throw "Ce script doit etre lance dans un PowerShell administrateur." }

if ($Apply) {
    if (-not (Test-Path $tscon)) { throw "tscon.exe introuvable : $tscon" }
    # Idempotent : recree la tache si elle existe deja.
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
    # L'ID de session change apres un redemarrage : la commande (fixe, SYSTEM seul peut la modifier) retrouve la session
    # de l'utilisateur dans `quser`, uniquement si elle est deconnectee (colonne SESSION vide : le 2e champ est alors l'ID).
    $cmd = '$u = ''' + $runner + '''; foreach ($l in (quser 2>$null)) { $t = $l.TrimStart(''> '') -split ''\s+''; if ($t[0] -ieq $u -and $t[1] -match ''^\d+$'') { & (Join-Path $env:SystemRoot ''System32\tscon.exe'') $t[1] /dest:console } }'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -NonInteractive -EncodedCommand $enc"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Description 'C2C : ramene la session 1 sur la console (declenchee par C2C Watch).' | Out-Null
    # Droit de lecture + lancement pour l'utilisateur (sinon `schtasks /run` depuis C2C Watch, non eleve, est refuse).
    $sid = (New-Object Security.Principal.NTAccount($runner)).Translate([Security.Principal.SecurityIdentifier]).Value
    $svc = New-Object -ComObject Schedule.Service; $svc.Connect()
    $task = $svc.GetFolder('\').GetTask($name)
    $sddl = $task.GetSecurityDescriptor(4)
    $task.SetSecurityDescriptor($sddl + "(A;;FRFX;;;$sid)", 0)
    Write-Host "Tache '$name' creee (a la demande uniquement) ; lancement autorise pour $runner."
}
else {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
    Write-Host "Tache '$name' supprimee."
}
