# Met a jour c2c.exe (PC fixe) depuis une release GitHub construite par la CI, apres verification du SHA-256 publie.
# Par defaut : simulation (affiche la release trouvee, ne telecharge rien et ne modifie rien).
# -Apply : telecharge, verifie l'empreinte, arrete C2C Watch, remplace c2c.exe (ancien en .bak), relance C2C Watch.
# Necessite `gh` connecte. Ne touche ni a Sunshine, ni a l'affichage, ni a la session en cours. A lancer en PowerShell NORMAL.
param([switch]$Apply, [string]$Tag = '', [string]$Repo = 'ampynjord/homelab-control', [string]$Dest = (Join-Path $env:USERPROFILE 'C2C'))
$ErrorActionPreference = 'Stop'
$exe = Join-Path $Dest 'c2c.exe'

if (-not $Tag) { $Tag = (gh release view --repo $Repo --json tagName --jq .tagName) }
if (-not $Tag) { throw "Aucune release trouvee sur $Repo." }
Write-Host "Release : $Tag ($Repo)"
if (-not $Apply) {
    Write-Host "SIMULATION (rien n'est modifie). -Apply : telecharge, verifie le SHA-256, remplace $exe et relance C2C Watch."
    Write-Host "c2c.exe actuel : $(if (Test-Path $exe) { (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() } else { 'absent' })"
    return
}
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("c2c-maj-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    gh release download $Tag --repo $Repo --dir $tmp --pattern 'c2c.exe' --pattern 'c2c.exe.sha256'
    $attendu = ((Get-Content (Join-Path $tmp 'c2c.exe.sha256') -Raw).Trim() -split '\s+')[0].ToLower()
    $reel = (Get-FileHash (Join-Path $tmp 'c2c.exe') -Algorithm SHA256).Hash.ToLower()
    if ($attendu -notmatch '^[0-9a-f]{64}$' -or $reel -ne $attendu) { throw "SHA-256 inattendu (attendu $attendu, obtenu $reel) : rien n'a ete modifie." }
    Write-Host "SHA-256 conforme : $reel"
    Stop-ScheduledTask -TaskName 'C2C Watch' -ErrorAction SilentlyContinue
    Get-Process c2c -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 2
    if (Test-Path $exe) { Copy-Item $exe "$exe.bak" -Force }
    Copy-Item (Join-Path $tmp 'c2c.exe') $exe -Force
    Start-ScheduledTask -TaskName 'C2C Watch'
    # L'arret de c2c.exe coupe aussi l'agent (si installe) : on le relance (1Password peut redemander une autorisation).
    if (Get-ScheduledTask -TaskName 'C2C Agent' -ErrorAction SilentlyContinue) { Start-ScheduledTask -TaskName 'C2C Agent' }
    Start-Sleep 6
    Write-Host "C2C Watch : $((Get-ScheduledTask -TaskName 'C2C Watch').State) ; $Tag installe dans $exe."
}
finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
