<#
.SYNOPSIS
  php-safepatch Windows test. Downloads an old official PHP build, then checks scan,
  apply (same-branch update and mitigation), idempotency and rollback.
  Needs internet access. Does not touch IIS or Apache (-NoRestart, no web server users).

  powershell -ExecutionPolicy Bypass -File tests\windows\run.ps1 [-OldVersion 8.3.35] [-Build nts-Win32-vs16-x64]

  SPDX-License-Identifier: MIT
#>
param(
    [string]$OldVersion = '8.3.35',
    [string]$Build = 'nts-Win32-vs16-x64',
    [string]$WorkDir = (Join-Path $env:TEMP 'php-safepatch-wintest')
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
$Script = Join-Path $Repo 'windows\php-safepatch.ps1'
$Adv = Join-Path $Repo 'advisories\php2shell.conf'
$Pass = 0; $Fail = 0
function Pass($m) { $script:Pass++; Write-Host "PASS  $m" }
function Fail($m) { $script:Fail++; Write-Host "FAIL  $m" }
function Check($m, [bool]$ok) { if ($ok) { Pass $m } else { Fail $m } }
function Section($m) { Write-Host "`n== $m" }
function Invoke-Safepatch([string[]]$A) {
    $env:PHP_SAFEPATCH_TEST_NONROOT = '1'
    # PowerShell 5.1 turns native stderr lines into errors under "Stop"; warnings are normal here.
    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $Script @A 2>&1 | Out-String
    $code = $LASTEXITCODE
    Add-Content -LiteralPath (Join-Path $WorkDir 'safepatch.out') -Value $out
    return $code
}
function Get-PhpValue([string]$Code) { return (& "$PhpDir\php.exe" -r $Code) }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$PhpDir = Join-Path $WorkDir 'php'
$State = Join-Path $WorkDir 'state'
$Zip = Join-Path $WorkDir "php-$OldVersion-$Build.zip"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
if (Test-Path -LiteralPath $State) { Remove-Item -LiteralPath ('\\?\' + $State) -Recurse -Force }
if (Test-Path -LiteralPath $PhpDir) { Remove-Item -LiteralPath $PhpDir -Recurse -Force }

Section "Fixture: PHP $OldVersion ($Build)"
$url = "https://downloads.php.net/~windows/releases/archives/php-$OldVersion-$Build.zip"
# The fixture comes from the official archive over HTTPS. The archive has no checksum list,
# so only the update zip (from releases.json) is checked by SHA-256, inside php-safepatch.
if (-not (Test-Path -LiteralPath $Zip)) { Write-Host "Downloading $url"; Invoke-WebRequest -Uri $url -OutFile $Zip -UseBasicParsing }
Remove-Item -LiteralPath (Join-Path $WorkDir 'safepatch.out') -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $Zip -DestinationPath $PhpDir -Force
# php.ini with extensions and a [PATH=] section at the end: values after it apply only to that path.
Set-Content -LiteralPath "$PhpDir\php.ini" -Encoding ASCII -Value "[PHP]`nextension_dir = `"ext`"`nextension=mbstring`nextension=openssl`n[PATH=C:/nowhere]`nshort_open_tag = On"
$IniBefore = Get-Content -LiteralPath "$PhpDir\php.ini" -Raw
$ModsBefore = @(& "$PhpDir\php.exe" -m | Where-Object { $_ -and $_ -notmatch '^\[' } | Sort-Object -Unique)
$Branch = ($OldVersion -replace '^(\d+\.\d+).*', '$1')

Section 'scan'
$rc = Invoke-Safepatch @('scan', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', $Adv, '-NoIoc', '-Quiet', '-Json', "$WorkDir\scan.json")
$scan = Get-Content -LiteralPath "$WorkDir\scan.json" -Raw | ConvertFrom-Json
Check 'scan exit code is 1 (vulnerable)' ($rc -eq 1)
Check "scan reports VULNERABLE for $OldVersion" ($scan.runtimes[0].status -eq 'VULNERABLE')
Check 'scan detects the build type' ($scan.runtimes[0].build -match '^(nts|ts)-vs1[67]-x(64|86)$')

Section 'apply: same-branch update, mitigation, opt-in'
$rc = Invoke-Safepatch @('apply', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', $Adv, '-NoIoc', '-Yes', '-NoRestart', '-Mitigate', 'always', '-IncludeOptIn', '-Quiet', '-Json', "$WorkDir\apply.json")
$ap = Get-Content -LiteralPath "$WorkDir\apply.json" -Raw | ConvertFrom-Json
$newVer = Get-PhpValue 'echo PHP_VERSION;'
Check 'apply exit code is 0' ($rc -eq 0)
Check "branch stays $Branch (now $newVer)" ($newVer -like "$Branch.*")
Check 'version is higher than the fixture' ([version]$newVer -gt [version]$OldVersion)
Check 'status is PATCHED' ($ap.runtimes[0].status -eq 'PATCHED')
$ModsAfter = @(& "$PhpDir\php.exe" -m | Where-Object { $_ -and $_ -notmatch '^\[' } | Sort-Object -Unique)
Check 'no extension lost' (@($ModsBefore | Where-Object { $ModsAfter -notcontains $_ }).Count -eq 0)
Check 'session.upload_progress.enabled is 0 (block placed before [PATH=])' ((Get-PhpValue 'echo ini_get(''session.upload_progress.enabled'');') -eq '0')
Check 'memory_limit is -1 with -IncludeOptIn' ((Get-PhpValue 'echo ini_get(''memory_limit'');') -eq '-1')
$ini = Get-Content -LiteralPath "$PhpDir\php.ini"
$iBlock = [array]::IndexOf($ini, '; >>> php-safepatch PHP2Shell mitigation >>>')
$iPath = [array]::IndexOf($ini, '[PATH=C:/nowhere]')
Check 'mitigation block is before the [PATH=] section' ($iBlock -ge 0 -and $iBlock -lt $iPath)

Section 'idempotency'
$iniAfter1 = Get-Content -LiteralPath "$PhpDir\php.ini" -Raw
$rc = Invoke-Safepatch @('apply', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', $Adv, '-NoIoc', '-Yes', '-NoRestart', '-Mitigate', 'always', '-IncludeOptIn', '-Quiet', '-Json', "$WorkDir\apply2.json")
$ap2 = Get-Content -LiteralPath "$WorkDir\apply2.json" -Raw | ConvertFrom-Json
Check 'second apply exit code is 0' ($rc -eq 0)
Check 'second apply changes nothing' (@($ap2.changes).Count -eq 0 -and (Get-Content -LiteralPath "$PhpDir\php.ini" -Raw) -eq $iniAfter1)

Section 'rollback'
$runId = Split-Path -Leaf $ap.run_dir
$rc = Invoke-Safepatch @('rollback', '-RunId', $runId, '-StateDir', $State, '-Yes', '-NoRestart', '-Quiet')
Check 'rollback exit code is 0' ($rc -eq 0)
Check "version back to $OldVersion" ((Get-PhpValue 'echo PHP_VERSION;') -eq $OldVersion)
Check 'php.ini back to the original' ((Get-Content -LiteralPath "$PhpDir\php.ini" -Raw) -eq $IniBefore)

Write-Host ("`nResult: {0} passed, {1} failed" -f $Pass, $Fail)
if ($Fail -gt 0) { exit 1 } else { exit 0 }
