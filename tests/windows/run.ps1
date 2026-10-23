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

Section 'Function checks (no PHP needed): functions are taken from the script by its syntax tree'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
$want = 'Compare-Ver', 'Get-Branch', 'Get-FixedFor', 'Get-LowestFixedBranch', 'Set-Assessment', 'ConvertTo-IniNorm', 'Split-Args', 'Test-HealthAfter'
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($want -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
$Adv = [ordered]@{ id = 'PHP2Shell'; fixed = '8.2.35 8.3.36 8.4.27 8.5.12'; eol_backport = '7.4 8.0 8.1' }
function Get-Status([string]$V) { $rt = @{ version = $V; branch = (Get-Branch $V); build = 'nts-vs16-x64'; status = ''; installed = ''; reason = ''; action = '' }; Set-Assessment $rt; return $rt.status }
Check '8.3.36 is PATCHED' ((Get-Status '8.3.36') -eq 'PATCHED')
Check '8.3.35 is VULNERABLE' ((Get-Status '8.3.35') -eq 'VULNERABLE')
Check '8.6.0 (branch not in the advisory) is UNKNOWN, not PATCHED' ((Get-Status '8.6.0') -eq 'UNKNOWN')
Check '8.5.12RC1 (pre-release of the fix) is VULNERABLE' ((Get-Status '8.5.12RC1') -eq 'VULNERABLE')
Check '8.5.13-dev (pre-release after the fix) is UNKNOWN' ((Get-Status '8.5.13-dev') -eq 'UNKNOWN')
Check '8.0.30 is VULNERABLE_EOL' ((Get-Status '8.0.30') -eq 'VULNERABLE_EOL')
Check '7.3.33 is VULNERABLE_NOFIX' ((Get-Status '7.3.33') -eq 'VULNERABLE_NOFIX')
Check 'ini values: Off = 0, On = 1' ((ConvertTo-IniNorm 'Off') -eq '0' -and (ConvertTo-IniNorm 'On') -eq '1' -and (ConvertTo-IniNorm '-1') -eq '-1')
Check 'IIS arguments are split with quotes' ((@(Split-Args '-c "C:\My PHP\php.ini" -d x=1') -join '|') -eq '-c|C:\My PHP\php.ini|-d|x=1')
# Health: a URL must give the same status code before and after the change.
function Info($m) { } ; function Warn($m) { } ; function Err($m) { }
function Start-Sleep { }
$HealthUrl = @('http://app.test/health')
$script:codes = @(404); function Get-HttpCode($u) { $c = $script:codes[0]; if ($script:codes.Count -gt 1) { $script:codes = $script:codes[1..($script:codes.Count - 1)] }; return $c }
Check 'health 200 -> 404 fails' (-not (Test-HealthAfter @{ 'http://app.test/health' = 200 }))
$script:codes = @(200)
Check 'health 200 -> 200 passes' (Test-HealthAfter @{ 'http://app.test/health' = 200 })
# Service recovery: the second Apache service fails to stop. The first one must start again.
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($fn.Name -in 'Stop-PhpUsers', 'Start-PhpUsers', 'Invoke-WithStoppedUsers', 'Update-State') { . ([scriptblock]::Create($fn.Extent.Text)) }
}
$script:started = @()
function Get-ApacheServices { return @([pscustomobject]@{ Name = 'ApacheA' }, [pscustomobject]@{ Name = 'ApacheB' }) }
function Get-DirProcesses($d) { return @() }
function Stop-Service { param($Name, [switch]$Force, $ErrorAction) if ($Name -eq 'ApacheB') { throw 'access denied' } }
function Start-Service { param($Name, $ErrorAction) $script:started += $Name }
$r = Invoke-WithStoppedUsers 'C:\php' @('apache') { return $true }
Check 'a failed stop of ApacheB returns $false' ($r -eq $false)
Check 'ApacheA, already stopped, is started again' ($script:started -contains 'ApacheA')
$script:started = @()
function Stop-Service { param($Name, [switch]$Force, $ErrorAction) }
$r = Invoke-WithStoppedUsers 'C:\php' @('apache') { throw 'copy failed' }
Check 'an exception in the body returns $false' ($r -eq $false)
Check 'both services are started again after the exception' (($script:started -contains 'ApacheA') -and ($script:started -contains 'ApacheB'))
# After a restore, the report must show the version on disk, not the version before the restore.
function Get-PhpInfo($d) { return @{ Version = '8.3.35'; Build = 'nts-vs16-x64' } }
function Set-Running($rt) { }
function Set-MitigationState($rt) { }
$rt = @{ path = 'C:\php'; version = '8.3.36'; branch = '8.3'; build = 'nts-vs16-x64'; status = 'PATCHED'; installed = 'PATCHED'; reason = ''; action = '' }
Update-State $rt
Check 'Update-State reads the version again (8.3.36 -> 8.3.35 after a restore)' ($rt.version -eq '8.3.35' -and $rt.status -eq 'VULNERABLE')
Remove-Item Function:\Start-Sleep, Function:\Info, Function:\Warn, Function:\Err, Function:\Stop-Service, Function:\Start-Service, `
    Function:\Get-ApacheServices, Function:\Get-DirProcesses, Function:\Get-PhpInfo, Function:\Set-Running, Function:\Set-MitigationState
$Adv = Join-Path $Repo 'advisories\php2shell.conf'

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
Check 'the CLI reads the block (mitigation=effective)' ($ap2.runtimes[0].mitigation -eq 'effective')
Check 'the report lists the php.ini of each configuration' (@($ap2.runtimes[0].configs).Count -ge 1 -and $ap2.runtimes[0].configs[0].php_ini -like '*php.ini')

Section 'patched installation: auto mode removes the old mitigation'
$rc = Invoke-Safepatch @('apply', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', $Adv, '-NoIoc', '-Yes', '-NoRestart', '-Quiet', '-Json', "$WorkDir\clean.json")
$cl = Get-Content -LiteralPath "$WorkDir\clean.json" -Raw | ConvertFrom-Json
Check 'cleanup apply exit code is 0' ($rc -eq 0)
Check 'mitigation block removed from php.ini' (@(Get-Content -LiteralPath "$PhpDir\php.ini") -notcontains '; >>> php-safepatch PHP2Shell mitigation >>>')
Check 'memory_limit is no longer -1' ((Get-PhpValue 'echo ini_get(''memory_limit'');') -ne '-1')
Check 'mitigation=none after cleanup' ($cl.runtimes[0].mitigation -eq 'none')

Section 'advisory files start empty and are validated'
Set-Content -LiteralPath "$WorkDir\other.conf" -Encoding ASCII -Value "id=OTHER-TEST`ncves=CVE-2099-0001`nfixed=8.6.1"
$iniNow = Get-Content -LiteralPath "$PhpDir\php.ini" -Raw
$rc = Invoke-Safepatch @('apply', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', "$WorkDir\other.conf", '-NoIoc', '-Yes', '-NoRestart', '-NoPatch', '-Mitigate', 'always', '-IncludeOptIn', '-Quiet')
Check 'no PHP2Shell rule is inherited (php.ini unchanged)' ((Get-Content -LiteralPath "$PhpDir\php.ini" -Raw) -eq $iniNow)
Set-Content -LiteralPath "$WorkDir\bad.conf" -Encoding ASCII -Value "id=BAD`ncves=CVE-2099-0002`nfixed=8.2`nmitigate=memory_limit"
$rc = Invoke-Safepatch @('scan', '-Php', $PhpDir, '-StateDir', $State, '-Advisory', "$WorkDir\bad.conf", '-NoIoc', '-Quiet')
Check 'invalid advisory: exit code 2' ($rc -eq 2)

Section 'rollback'
$runId = Split-Path -Leaf $ap.run_dir
$rc = Invoke-Safepatch @('rollback', '-RunId', $runId, '-StateDir', $State, '-Yes', '-NoRestart', '-Quiet')
Check 'rollback exit code is 0' ($rc -eq 0)
Check "version back to $OldVersion" ((Get-PhpValue 'echo PHP_VERSION;') -eq $OldVersion)
Check 'php.ini back to the original' ((Get-Content -LiteralPath "$PhpDir\php.ini" -Raw) -eq $IniBefore)

Write-Host ("`nResult: {0} passed, {1} failed" -f $Pass, $Fail)
if ($Fail -gt 0) { exit 1 } else { exit 0 }
