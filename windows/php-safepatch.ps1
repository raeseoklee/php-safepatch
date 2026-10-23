<#
.SYNOPSIS
  php-safepatch for Windows. Finds PHP installations, checks them against an advisory
  (default: PHP2Shell, CVE-2026-109618 / CVE-2026-109619), and fixes them without
  changing the PHP minor branch.

.DESCRIPTION
  scan     Find PHP installations and report their status. Makes no changes.
  apply    Scan, then install the fixed patch release of the same branch and build
           (TS/NTS, compiler, architecture) from windows.php.net, and apply mitigations.
  rollback Restore the directories and files that a previous run changed.

  Exit codes: 0 = no vulnerable runtime and no indicator, 1 = vulnerable runtime or
  indicator found, 2 = error.

  SPDX-License-Identifier: MIT
  Copyright (c) 2026 php-safepatch contributors
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('scan', 'apply', 'rollback', 'version')]
    [string]$Command = 'scan',
    [string]$Json,
    [switch]$Yes,
    [ValidateSet('auto', 'always', 'never')]
    [string]$Mitigate = 'auto',
    [switch]$IncludeOptIn,
    [switch]$NoPatch,
    [switch]$NoRestart,
    [switch]$NoIoc,
    [string[]]$HealthUrl = @(),
    [string[]]$Php = @(),
    [string[]]$WebRoot = @(),
    [string]$Advisory,
    [string]$StateDir = (Join-Path $env:ProgramData 'php-safepatch'),
    [string]$RunId,
    [string]$ReleasesUrl = 'https://downloads.php.net/~windows/releases/releases.json',
    [string]$DownloadBase = 'https://downloads.php.net/~windows/releases/',
    [string]$ZipDir,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$SafepatchVersion = '0.1.0'

# ---------------------------------------------------------------------------
# Advisory defaults (override with -Advisory FILE)
# ---------------------------------------------------------------------------
$Adv = [ordered]@{
    id             = 'PHP2Shell'
    cves           = 'CVE-2026-109618 CVE-2026-109619'
    fixed          = '8.2.35 8.3.36 8.4.27 8.5.12'
    eol_backport   = '7.4 8.0 8.1'
    ioc_since      = '2026-10-17'
    mitigate       = @('session.upload_progress.enabled=0', 'fatal_error_backtraces=0@8.5')
    mitigate_optin = @('memory_limit=-1')
    ioc_log        = @(
        "pre-script memory exhaustion errors ('in Unknown on line 0')|Allowed memory size of [0-9]+ bytes exhausted.* in Unknown on line 0",
        'worker segmentation faults|Segmentation fault|SIGSEGV|exited on signal 11|Access violation|0xc0000005'
    )
}

$Script:Runtimes = New-Object System.Collections.ArrayList
$Script:Indicators = New-Object System.Collections.ArrayList
$Script:Changes = New-Object System.Collections.ArrayList
$Script:Errors = New-Object System.Collections.ArrayList
$Script:RunDir = $null
$Script:LogFile = $null

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Log([string]$Level, [string]$Msg) {
    if ($Script:LogFile) {
        Add-Content -LiteralPath $Script:LogFile -Value ('{0} {1} {2}' -f (Get-Date -Format s), $Level, $Msg) -Encoding UTF8
    }
}
function Info([string]$Msg) { Write-Log 'INFO' $Msg; if (-not $Quiet) { [Console]::Error.WriteLine("[php-safepatch] $Msg") } }
function Warn([string]$Msg) { Write-Log 'WARN' $Msg; [Console]::Error.WriteLine("[php-safepatch] WARNING: $Msg") }
function Err([string]$Msg) { Write-Log 'ERROR' $Msg; [void]$Script:Errors.Add($Msg); [Console]::Error.WriteLine("[php-safepatch] ERROR: $Msg") }
function Die([string]$Msg) { Err $Msg; exit 2 }

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
function Compare-Ver([string]$A, [string]$B) {
    $pa = $A.Split('.'); $pb = $B.Split('.')
    for ($i = 0; $i -lt 4; $i++) {
        $x = 0; $y = 0
        if ($i -lt $pa.Count) { [void][int]::TryParse(($pa[$i] -replace '[^0-9].*$', ''), [ref]$x) }
        if ($i -lt $pb.Count) { [void][int]::TryParse(($pb[$i] -replace '[^0-9].*$', ''), [ref]$y) }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}
function Get-Branch([string]$V) { if ($V -match '^(\d+\.\d+)') { return $Matches[1] } return '' }
function Get-FixedFor([string]$Branch) {
    foreach ($f in ($Adv.fixed -split '\s+')) { if ((Get-Branch $f) -eq $Branch) { return $f } }
    return $null
}
function Get-LowestFixedBranch {
    $low = $null
    foreach ($f in ($Adv.fixed -split '\s+')) {
        $b = Get-Branch $f
        if (-not $low -or (Compare-Ver $b $low) -lt 0) { $low = $b }
    }
    return $low
}
function Get-Slug { return (($Adv.id.ToLower()) -replace '[^a-z0-9._-]', '-') }
function Get-ShortHash([string]$S) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($S.ToLowerInvariant()))
    return (($h[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Import-Advisory([string]$File) {
    # An external advisory starts empty: nothing is inherited from the built-in PHP2Shell data.
    if (-not (Test-Path -LiteralPath $File)) { Die "Cannot read advisory file: $File" }
    foreach ($k in 'id', 'cves', 'fixed', 'eol_backport', 'ioc_since') { $Adv[$k] = '' }
    foreach ($k in 'mitigate', 'mitigate_optin', 'ioc_log') { $Adv[$k] = @() }
    $bad = $false; $n = 0
    foreach ($raw in Get-Content -LiteralPath $File) {
        $n++
        $line = $raw.TrimEnd("`r")
        if (-not $line.Trim() -or $line.TrimStart().StartsWith('#')) { continue }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { Err "${File}:${n}: not key=value"; $bad = $true; continue }
        $k = $line.Substring(0, $eq).Trim(); $v = $line.Substring($eq + 1)
        if ($k -in 'id', 'cves', 'fixed', 'eol_backport', 'ioc_since') { $Adv[$k] = $v }
        elseif ($k -in 'mitigate', 'mitigate_optin', 'ioc_log') { $Adv[$k] = @($Adv[$k]) + $v }
        else { Err "${File}:${n}: unknown key '$k'"; $bad = $true }
    }
    # A wrong advisory must stop the run, not change servers in an unexpected way.
    if ($Adv.id -notmatch '^[A-Za-z0-9._-]+$') { Err "${File}: 'id' is missing or has characters other than A-Z a-z 0-9 . _ -"; $bad = $true }
    if (-not $Adv.cves.Trim()) { Err "${File}: 'cves' is missing"; $bad = $true }
    if (-not $Adv.fixed.Trim()) { Err "${File}: 'fixed' is missing"; $bad = $true }
    foreach ($x in ($Adv.fixed -split '\s+' | Where-Object { $_ })) { if ($x -notmatch '^\d+\.\d+\.\d+$') { Err "${File}: 'fixed' value '$x' is not X.Y.Z"; $bad = $true } }
    foreach ($x in ($Adv.eol_backport -split '\s+' | Where-Object { $_ })) { if ($x -notmatch '^\d+\.\d+$') { Err "${File}: 'eol_backport' value '$x' is not X.Y"; $bad = $true } }
    if ($Adv.ioc_since -and $Adv.ioc_since -notmatch '^\d{4}-\d{2}-\d{2}$') { Err "${File}: 'ioc_since' is not YYYY-MM-DD"; $bad = $true }
    foreach ($x in @($Adv.mitigate) + @($Adv.mitigate_optin)) { if ($x -notmatch '^[A-Za-z0-9_.]+=[^@]*(@\d+\.\d+)?$') { Err "${File}: mitigation rule '$x' is not KEY=VALUE[@X.Y]"; $bad = $true } }
    foreach ($x in @($Adv.ioc_log)) { if ($x -notmatch '^.+\|.+$') { Err "${File}: ioc_log '$x' is not LABEL|REGEX"; $bad = $true } }
    if ($bad) { Die "Advisory file $File is not valid. No change was made." }
}

# Returns @(@{Key; Value}) for the rules that apply to a branch.
function Get-MitigationRules([string]$Branch) {
    $rules = @($Adv.mitigate)
    if ($IncludeOptIn) { $rules += @($Adv.mitigate_optin) }
    $out = @()
    foreach ($r in $rules) {
        if (-not $r) { continue }
        $kv = $r; $minb = $null
        $at = $r.LastIndexOf('@')
        if ($at -gt 0) { $kv = $r.Substring(0, $at); $minb = $r.Substring($at + 1) }
        if ($minb -and (Compare-Ver $Branch $minb) -lt 0) { continue }
        $eq = $kv.IndexOf('=')
        $out += , @{ Key = $kv.Substring(0, $eq); Value = $kv.Substring($eq + 1) }
    }
    return , $out
}

function Invoke-Php([string]$Exe, [string[]]$PhpArgs, [int]$TimeoutSec = 20, [hashtable]$EnvVars = @{}) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($PhpArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Split-Path -Parent $Exe
    foreach ($k in $EnvVars.Keys) { $psi.EnvironmentVariables[$k] = [string]$EnvVars[$k] }
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $null = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; return '' }
        return $outTask.Result
    } catch { return '' }
}

function Initialize-RunDir([string]$Id) {
    $Script:RunDir = Join-Path $StateDir $Id
    try {
        New-Item -ItemType Directory -Force -Path (Join-Path $Script:RunDir 'backup') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $Script:RunDir 'modules') | Out-Null
    } catch { $Script:RunDir = $null; return $false }
    $Script:LogFile = Join-Path $Script:RunDir 'php-safepatch.log'
    Set-Content -LiteralPath (Join-Path $Script:RunDir 'command') -Value $Command -Encoding ASCII
    New-Item -ItemType File -Force -Path (Join-Path $Script:RunDir 'manifest') | Out-Null
    return $true
}

function Add-Manifest([string]$Line) { Add-Content -LiteralPath (Join-Path $Script:RunDir 'manifest') -Value $Line -Encoding UTF8 }

function Backup-File([string]$Path) {
    if (-not $Script:RunDir) { Die "No run directory. Refusing to change $Path without a backup." }
    $mf = @(Get-Content -LiteralPath (Join-Path $Script:RunDir 'manifest') -ErrorAction SilentlyContinue)
    foreach ($l in $mf) { $p = $l.Split("`t"); if ($p.Count -ge 2 -and $p[1] -eq $Path -and $p[0] -in 'FILE', 'CREATED') { return } }
    if (Test-Path -LiteralPath $Path) {
        # Short hash-based name: long source paths would pass the Windows path limit.
        $name = 'file_' + (Get-ShortHash $Path) + '.bak'
        Copy-Item -LiteralPath $Path -Destination (Join-Path $Script:RunDir "backup\$name") -Force
        Add-Manifest "FILE`t$Path`t$name"
    } else {
        Add-Manifest "CREATED`t$Path"
    }
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
function Get-IisPhpPaths {
    $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    $paths = @()
    if (Test-Path -LiteralPath $cfg) {
        try {
            [xml]$x = Get-Content -LiteralPath $cfg -Raw
            foreach ($a in $x.SelectNodes('//fastCgi/application')) { $paths += [Environment]::ExpandEnvironmentVariables($a.fullPath) }
            foreach ($h in $x.SelectNodes('//handlers/add[@scriptProcessor]')) {
                $sp = ($h.scriptProcessor -split '\|')[0]
                if ($sp -match 'php') { $paths += [Environment]::ExpandEnvironmentVariables($sp) }
            }
        } catch { Warn "Cannot parse $cfg : $($_.Exception.Message)" }
    }
    return $paths
}

function Get-IisSiteRoots {
    $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    $roots = @()
    if (Test-Path -LiteralPath $cfg) {
        try {
            [xml]$x = Get-Content -LiteralPath $cfg -Raw
            foreach ($v in $x.SelectNodes('//sites/site/application/virtualDirectory')) { $roots += [Environment]::ExpandEnvironmentVariables($v.physicalPath) }
        } catch { }
    }
    return $roots
}

function Get-ApacheConfs {
    $confs = @()
    $cands = @('C:\Apache24\conf\httpd.conf', 'C:\xampp\apache\conf\httpd.conf', 'C:\Program Files\Apache24\conf\httpd.conf',
               'C:\Program Files\Apache Software Foundation\Apache2.4\conf\httpd.conf')
    $cands += @(Get-ChildItem -Path 'C:\wamp64\bin\apache\*\conf\httpd.conf', 'C:\wamp\bin\apache\*\conf\httpd.conf',
                'C:\laragon\bin\apache\*\conf\httpd.conf' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'httpd\.exe' })) {
        if ($svc.PathName -match '^"?(.+?\\bin)\\httpd\.exe') { $cands += (Join-Path (Split-Path -Parent $Matches[1]) 'conf\httpd.conf') }
    }
    foreach ($c in ($cands | Select-Object -Unique)) { if (Test-Path -LiteralPath $c) { $confs += $c } }
    return $confs
}

function Get-ApachePhpDirs {
    $dirs = @()
    foreach ($c in Get-ApacheConfs) {
        foreach ($m in (Select-String -LiteralPath $c -Pattern '^\s*LoadModule\s+php\w*_module\s+"?([^"]+)"?' -ErrorAction SilentlyContinue)) {
            $dll = $m.Matches[0].Groups[1].Value.Trim().Replace('/', '\')
            $dirs += (Split-Path -Parent $dll)
        }
        foreach ($m in (Select-String -LiteralPath $c -Pattern '^\s*PHPIniDir\s+"?([^"]+)"?' -ErrorAction SilentlyContinue)) {
            $dirs += $m.Matches[0].Groups[1].Value.Trim().Replace('/', '\')
        }
    }
    return $dirs
}

function Find-PhpDirs {
    $dirs = New-Object System.Collections.ArrayList
    $add = {
        param($p)
        if (-not $p) { return }
        $p = $p.Trim('"')
        if (Test-Path -LiteralPath $p -PathType Leaf) { $p = Split-Path -Parent $p }
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { return }
        if (-not ((Test-Path -LiteralPath (Join-Path $p 'php.exe')) -or (Test-Path -LiteralPath (Join-Path $p 'php-cgi.exe')))) { return }
        $full = (Resolve-Path -LiteralPath $p).ProviderPath.TrimEnd('\')
        foreach ($d in $dirs) { if ($d -ieq $full) { return } }
        [void]$dirs.Add($full)
    }
    foreach ($p in $Php) { & $add $p }
    foreach ($c in @(Get-Command php.exe, php-cgi.exe -All -ErrorAction SilentlyContinue)) { & $add $c.Source }
    $globs = @('C:\php*', 'C:\tools\php*', "$env:ProgramFiles\PHP\*", "$env:ProgramFiles\PHP", 'C:\xampp\php',
               'C:\laragon\bin\php\*', 'C:\wamp64\bin\php\*', 'C:\wamp\bin\php\*', "$env:ProgramFiles\iis express\PHP\*")
    if (${env:ProgramFiles(x86)}) { $globs += "${env:ProgramFiles(x86)}\PHP\*" }
    foreach ($g in $globs) { foreach ($i in @(Get-Item -Path $g -ErrorAction SilentlyContinue)) { & $add $i.FullName } }
    foreach ($p in Get-IisPhpPaths) { & $add $p }
    foreach ($p in Get-ApachePhpDirs) { & $add $p }
    foreach ($proc in @(Get-Process -Name php, php-cgi -ErrorAction SilentlyContinue)) { try { & $add $proc.Path } catch { } }
    return $dirs
}

function Get-PhpInfo([string]$Dir) {
    $exe = Join-Path $Dir 'php.exe'
    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $Dir 'php-cgi.exe' }
    $out = Invoke-Php $exe @('-n', '-r', 'echo PHP_VERSION,"|",PHP_ZTS,"|",PHP_INT_SIZE*8,"\n";')
    $line = ($out -split "`n" | Where-Object { $_ -match '^\d+\.\d+\.\d+.*\|' } | Select-Object -First 1)
    $info = [ordered]@{ Exe = $exe; Version = ''; Ts = ''; Arch = ''; Compiler = ''; Build = ''; Ini = '' }
    if ($line) {
        $parts = $line.Trim().Split('|')
        # Keep a pre-release suffix (8.5.12RC1, 8.6.0-dev): such a build is not the fixed release.
        if ($parts[0] -match '^(\d+\.\d+\.\d+)(-?(alpha|beta|RC|dev)\d*)?') { $info.Version = $Matches[1] + $Matches[2] }
        $info.Ts = if ($parts[1] -eq '1') { 'ts' } else { 'nts' }
        $info.Arch = if ($parts[2] -eq '64') { 'x64' } else { 'x86' }
    }
    $phpi = Invoke-Php $exe @('-n', '-i')
    if ($phpi -match 'Compiler => (?:Visual C\+\+|MSVC)\s*(\d+)') {
        switch ($Matches[1]) { '2017' { $info.Compiler = 'vc15' } '15' { $info.Compiler = 'vc15' } '2019' { $info.Compiler = 'vs16' } '16' { $info.Compiler = 'vs16' } '2022' { $info.Compiler = 'vs17' } '17' { $info.Compiler = 'vs17' } }
    }
    if ($info.Compiler) { $info.Build = '{0}-{1}-{2}' -f $info.Ts, $info.Compiler, $info.Arch }
    return $info
}

function Get-DirUsers([string]$Dir) {
    # Which web servers load PHP from this directory.
    $users = @()
    foreach ($p in Get-IisPhpPaths) { if ($p -and ($p.Trim('"') -like "$Dir\*")) { $users += 'iis'; break } }
    foreach ($p in Get-ApachePhpDirs) { if ($p -and ($p.TrimEnd('\') -ieq $Dir)) { $users += 'apache'; break } }
    return ($users | Select-Object -Unique)
}

# Splits a command-line argument string (IIS "arguments") into an array.
function Split-Args([string]$S) {
    $out = @()
    foreach ($m in [regex]::Matches($S, '"([^"]*)"|(\S+)')) { if ($m.Groups[1].Success) { $out += $m.Groups[1].Value } else { $out += $m.Groups[2].Value } }
    return $out   # callers wrap the result in @()
}

# The configurations that really load PHP from this directory: the CLI, every IIS FastCGI
# application (its "arguments" and PHPRC), and Apache (PHPIniDir). Each gets the php.ini it reads.
function Get-RuntimeConfigs([string]$Dir, [string]$Exe) {
    $cfgs = New-Object System.Collections.ArrayList
    $resolve = {
        param([string[]]$PArgs, [hashtable]$PEnv)
        $cli = Join-Path $Dir 'php.exe'
        $loaded = ''
        if (Test-Path -LiteralPath $cli) {
            $loaded = (Invoke-Php $cli (@($PArgs) + @('-r', 'echo php_ini_loaded_file();')) 20 $PEnv).Trim()
        } else {
            $html = Invoke-Php $Exe (@($PArgs) + @('-i')) 20 $PEnv
            if ($html -match 'Loaded Configuration File\s*(?:</td><td class="v">|=>)\s*([^<\r\n]+)') { $loaded = $Matches[1].Trim() }
        }
        if (-not $loaded -or $loaded -eq '(none)') { $loaded = Join-Path $Dir 'php.ini' }   # PHP reads it once it exists
        return $loaded
    }
    [void]$cfgs.Add(@{ Source = 'cli'; Args = @(); Env = @{}; Ini = (& $resolve @() @{}) })
    $hostCfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $hostCfg) {
        try {
            [xml]$x = Get-Content -LiteralPath $hostCfg -Raw
            foreach ($a in $x.SelectNodes('//fastCgi/application')) {
                $full = [Environment]::ExpandEnvironmentVariables($a.fullPath)
                if ($full -notlike "$Dir\*") { continue }
                $pArgs = @(Split-Args ([string]$a.arguments)); $pEnv = @{}
                foreach ($e in $a.SelectNodes('environmentVariables/environmentVariable')) {
                    if ($e.name -in 'PHPRC', 'PHP_INI_SCAN_DIR') { $pEnv[$e.name] = [Environment]::ExpandEnvironmentVariables($e.value) }
                }
                [void]$cfgs.Add(@{ Source = "iis:$full $($a.arguments)".Trim(); Args = $pArgs; Env = $pEnv; Ini = (& $resolve $pArgs $pEnv) })
            }
        } catch { Warn "Cannot parse $hostCfg : $($_.Exception.Message)" }
    }
    foreach ($c in Get-ApacheConfs) {
        $usesDir = $false
        foreach ($m in (Select-String -LiteralPath $c -Pattern '^\s*LoadModule\s+php\w*_module\s+"?([^"]+)"?' -ErrorAction SilentlyContinue)) {
            if ((Split-Path -Parent $m.Matches[0].Groups[1].Value.Trim().Replace('/', '\')).TrimEnd('\') -ieq $Dir) { $usesDir = $true }
        }
        if (-not $usesDir) { continue }
        $iniDir = $Dir
        foreach ($m in (Select-String -LiteralPath $c -Pattern '^\s*PHPIniDir\s+"?([^"]+)"?' -ErrorAction SilentlyContinue)) {
            $iniDir = $m.Matches[0].Groups[1].Value.Trim().Replace('/', '\')
        }
        $ini = Join-Path $iniDir 'php.ini'
        [void]$cfgs.Add(@{ Source = "apache:$c"; Args = @('-c', $ini); Env = @{}; Ini = $ini })
    }
    return , $cfgs
}

function Add-Runtime($Dir, $PhpInfo) {
    $configs = Get-RuntimeConfigs $Dir $PhpInfo.Exe
    $rt = [ordered]@{
        path = $Dir; exe = $PhpInfo.Exe; version = $PhpInfo.Version; branch = (Get-Branch $PhpInfo.Version)
        build = $PhpInfo.Build; used_by = @(Get-DirUsers $Dir)
        configs = $configs; inis = @($configs | ForEach-Object { $_.Ini } | Select-Object -Unique)
        status = ''; installed = ''; running = 'no'; mitigation = 'none'; mitigated = $false; reason = ''; action = ''
    }
    [void]$Script:Runtimes.Add($rt)
}

# ---------------------------------------------------------------------------
# Running processes and mitigation state
# ---------------------------------------------------------------------------
function Get-DirProcesses([string]$Dir) {
    return @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and $_.Path -like "$Dir\*" } catch { $false } })
}

function Set-Running($rt) {
    $rt.running = if (@(Get-DirProcesses $rt.path).Count -gt 0) { 'yes' } else { 'no' }
}

function ConvertTo-IniNorm([string]$V) {
    $v = "$V".Trim().ToLowerInvariant()
    if ($v -in 'on', '1', 'true', 'yes') { return '1' }
    if ($v -in 'off', '0', 'false', 'no', '') { return '0' }
    return $v
}

function Test-HasMitigationBlock([string]$Ini) {
    if (-not (Test-Path -LiteralPath $Ini)) { return $false }
    return (@(Get-Content -LiteralPath $Ini) -contains "; >>> php-safepatch $($Adv.id) mitigation >>>")
}

# none | effective | pending_restart | not_effective
function Set-MitigationState($rt) {
    $withBlock = @($rt.inis | Where-Object { Test-HasMitigationBlock $_ })
    if ($withBlock.Count -eq 0) { $rt.mitigation = 'none'; return }
    $rules = Get-MitigationRules $rt.branch
    $cli = Join-Path $rt.path 'php.exe'
    $bad = $false
    if ($rules.Count -gt 0 -and (Test-Path -LiteralPath $cli)) {
        foreach ($cfg in $rt.configs) {
            # Read each value the way this service reads php.ini.
            foreach ($r in $rules) {
                $code = 'echo ini_get(' + [char]39 + $r.Key + [char]39 + ');'
                $got = (Invoke-Php $cli (@($cfg.Args) + @('-r', $code)) 20 $cfg.Env).Trim()
                if ((ConvertTo-IniNorm $got) -ne (ConvertTo-IniNorm $r.Value)) { $bad = $true }
            }
        }
    }
    if ($bad) { $rt.mitigation = 'not_effective'; return }
    $newest = ($withBlock | ForEach-Object { (Get-Item -LiteralPath $_).LastWriteTime } | Sort-Object | Select-Object -Last 1)
    $old = @(Get-DirProcesses $rt.path | Where-Object { try { $_.StartTime -lt $newest } catch { $false } })
    if ($rt.used_by -contains 'apache') {
        $old += @(Get-Process -Name httpd -ErrorAction SilentlyContinue | Where-Object { try { $_.StartTime -lt $newest } catch { $false } })
    }
    $rt.mitigation = if ($old.Count -gt 0) { 'pending_restart' } else { 'effective' }
}

# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------
function Test-BadStatus([string]$S) { return ($S -ne 'PATCHED') }

function Set-Assessment($rt) {
    $v = $rt.version; $b = $rt.branch
    if (-not $v) { $rt.status = 'UNKNOWN'; $rt.installed = 'UNKNOWN'; $rt.reason = 'Version not readable'; $rt.action = 'Check this installation manually'; return }
    $base = ($v -replace '^(\d+\.\d+\.\d+).*$', '$1'); $pre = $v.Substring($base.Length)
    $fixed = Get-FixedFor $b
    $low = Get-LowestFixedBranch
    # Only a release that the advisory names as fixed counts as safe.
    if ($fixed -and -not $pre -and (Compare-Ver $base $fixed) -ge 0) { $rt.status = 'PATCHED'; $rt.reason = "Version $v >= $fixed" }
    elseif ($fixed -and $pre -and (Compare-Ver $base $fixed) -gt 0) { $rt.status = 'UNKNOWN'; $rt.reason = "Pre-release build $v after the fixed release $fixed; the advisory does not say it is fixed" }
    elseif ($fixed) { $rt.status = 'VULNERABLE'; $rt.reason = "Version $v is older than the fixed release $fixed" }
    elseif (($Adv.eol_backport -split '\s+') -contains $b) { $rt.status = 'VULNERABLE_EOL'; $rt.reason = "Branch $b is end-of-life; windows.php.net has no fixed build" }
    elseif ($low -and (Compare-Ver $b $low) -lt 0) { $rt.status = 'VULNERABLE_NOFIX'; $rt.reason = "Branch $b has no upstream fix" }
    else { $rt.status = 'UNKNOWN'; $rt.reason = "Branch $b is not covered by advisory $($Adv.id)" }
    $rt.installed = $rt.status
    switch ($rt.status) {
        'PATCHED' { $rt.action = 'None' }
        'UNKNOWN' { $rt.action = "Check the PHP advisories for $v manually" }
        'VULNERABLE' { $rt.action = "Install the fixed $b build ($($rt.build)) from windows.php.net; mitigate if that is not possible" }
        default { $rt.action = 'Mitigate now; plan a vendor build or an isolated upgrade with application tests' }
    }
}

# ---------------------------------------------------------------------------
# Indicators (read-only)
# ---------------------------------------------------------------------------
function Add-Indicator([string]$Msg) { [void]$Script:Indicators.Add($Msg); if (-not $Msg.StartsWith('info:')) { Warn "Indicator: $Msg" } }

function Test-Indicators {
    if ($NoIoc) { return }
    $logs = @()
    foreach ($rt in $Script:Runtimes) {
        $el = (Invoke-Php $rt.exe @('-r', 'echo ini_get("error_log");')).Trim()
        if ($el -and (Test-Path -LiteralPath $el)) { $logs += $el }
    }
    foreach ($c in Get-ApacheConfs) {
        $logs += @(Get-ChildItem -Path (Join-Path (Split-Path -Parent (Split-Path -Parent $c)) 'logs\error*.log') -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    foreach ($f in ($logs | Select-Object -Unique)) {
        foreach ($rule in $Adv.ioc_log) {
            $sep = $rule.IndexOf('|'); $label = $rule.Substring(0, $sep); $rx = $rule.Substring($sep + 1)
            $n = @(Select-String -LiteralPath $f -Pattern $rx -ErrorAction SilentlyContinue).Count
            if ($n -gt 0) { Add-Indicator "log ${f}: $n $label" }
        }
    }
    # Shells started by PHP or web workers.
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byId = @{}; foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
    foreach ($p in $procs) {
        if ($p.Name -notmatch '^(cmd|powershell|pwsh|wscript|cscript|mshta|certutil|bitsadmin|curl|wget|rundll32)\.exe$') { continue }
        $parent = $byId[[int]$p.ParentProcessId]
        if ($parent -and $parent.Name -match '^(php|php-cgi|httpd|w3wp)\.exe$') {
            Add-Indicator ("process {0} '{1}' started by {2} ({3})" -f $p.ProcessId, $p.CommandLine, $parent.Name, $parent.ProcessId)
        }
    }
    # PHP files changed after the reference date.
    if (-not $Adv.ioc_since) { return }   # the advisory gives no reference date for changed files
    $since = [datetime]::ParseExact($Adv.ioc_since, 'yyyy-MM-dd', $null)
    $roots = @('C:\inetpub\wwwroot', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\laragon\www') + (Get-IisSiteRoots) + $WebRoot
    $shellRx = 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|assert\s*\(\s*\$_|(system|passthru|shell_exec|proc_open|popen)\s*\(\s*\$_'
    foreach ($r in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $r -PathType Container)) { continue }
        $files = @(Get-ChildItem -LiteralPath $r -Recurse -File -Include '*.php', '*.phtml', '*.php?', '*.phar', '.user.ini' -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge $since } | Select-Object -First 2000)
        if ($files.Count -eq 0) { continue }
        foreach ($m in @($files | Select-String -Pattern $shellRx -List -ErrorAction SilentlyContinue | Select-Object -First 50)) {
            Add-Indicator "web shell pattern in $($m.Path)"
        }
        Add-Indicator "info: $($files.Count) PHP-related files in $r changed since $($Adv.ioc_since) (review them; list in log)"
        foreach ($f in $files) { Write-Log 'INFO' "changed: $($f.FullName)" }
    }
}

function Get-IndicatorCount { return @($Script:Indicators | Where-Object { -not $_.StartsWith('info:') }).Count }
function Get-BadCount { return @($Script:Runtimes | Where-Object { Test-BadStatus $_.status }).Count }

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
function Show-Report {
    $o = New-Object System.Text.StringBuilder
    [void]$o.AppendLine('')
    [void]$o.AppendLine(('php-safepatch {0}  advisory {1} ({2})  host {3}  os windows' -f $SafepatchVersion, $Adv.id, $Adv.cves, $env:COMPUTERNAME))
    [void]$o.AppendLine(('{0,-18} {1,-11} {2,-14} {3,-8} {4,-16} {5,-11} {6}' -f 'STATUS', 'VERSION', 'BUILD', 'RUNNING', 'MITIGATION', 'USED BY', 'PATH'))
    foreach ($rt in $Script:Runtimes) {
        $ver = if ($rt.version) { $rt.version } else { '-' }
        [void]$o.AppendLine(('{0,-18} {1,-11} {2,-14} {3,-8} {4,-16} {5,-11} {6}' -f $rt.status, $ver, $rt.build, $rt.running, $rt.mitigation, (($rt.used_by) -join ','), $rt.path))
        foreach ($c in $rt.configs) { [void]$o.AppendLine(('{0,-18}    php.ini {1}  ({2})' -f '', $c.Ini, $c.Source)) }
        if (Test-BadStatus $rt.status) { [void]$o.AppendLine(('{0,-18} -> {1}. {2}' -f '', $rt.reason, $rt.action)) }
    }
    if ($Script:Runtimes.Count -eq 0) { [void]$o.AppendLine('(no PHP installation found)') }
    if ($Script:Indicators.Count -gt 0) {
        [void]$o.AppendLine(''); [void]$o.AppendLine('Indicators (review; php-safepatch does not delete anything):')
        foreach ($i in $Script:Indicators) { [void]$o.AppendLine("  - $i") }
    }
    if ($Script:Changes.Count -gt 0) {
        [void]$o.AppendLine(''); [void]$o.AppendLine("Changes in this run ($($Script:RunDir)):")
        foreach ($c in $Script:Changes) { [void]$o.AppendLine("  - $c") }
    }
    if ((Get-BadCount) -gt 0 -or (Get-IndicatorCount) -gt 0) {
        [void]$o.AppendLine(''); [void]$o.AppendLine('Reminder: rotate DB passwords, API keys and admin passwords on hosts that were exposed before the fix.')
    }
    [Console]::Out.Write($o.ToString())
}

function Get-JsonReport {
    $rep = [ordered]@{
        tool = 'php-safepatch'; version = $SafepatchVersion
        advisory = [ordered]@{ id = $Adv.id; cves = $Adv.cves; fixed = $Adv.fixed }
        host = $env:COMPUTERNAME; os = [ordered]@{ id = 'windows'; family = 'windows' }
        time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); command = $Command; run_dir = $Script:RunDir
        runtimes = @($Script:Runtimes | ForEach-Object {
                [ordered]@{ path = $_.path; sapi = 'cli/cgi'; version = $_.version; branch = $_.branch; manager = 'windows-zip'; build = $_.build
                    used_by = @($_.used_by); status = $_.status; installed = $_.installed; running = $_.running; mitigation = $_.mitigation
                    configs = @($_.configs | ForEach-Object { [ordered]@{ source = $_.Source; php_ini = $_.Ini } })
                    reason = $_.reason; action = $_.action }
            })
        dockerfiles = @(); indicators = @($Script:Indicators); changes = @($Script:Changes); errors = @($Script:Errors)
        summary = [ordered]@{ runtimes = $Script:Runtimes.Count; not_patched = (Get-BadCount); indicators = (Get-IndicatorCount) }
    }
    return ($rep | ConvertTo-Json -Depth 6)
}

# ---------------------------------------------------------------------------
# Compatibility checks
# ---------------------------------------------------------------------------
function Get-Modules([string]$Exe) {
    return @((Invoke-Php $Exe @('-m')) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\[' } | Sort-Object -Unique)
}

function Get-HttpCode([string]$Url) {
    try {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 0 -ErrorAction Stop
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

function Test-HealthAfter($Before) {
    # A URL passes only if it gives the same status code as before the change.
    $ok = $true
    foreach ($u in $HealthUrl) {
        $b = $Before[$u]; $now = 0
        if ($b -eq 0 -or $b -ge 500) { Warn "Health URL $u already failed before the change ($b); it cannot verify this run"; continue }
        for ($t = 0; $t -lt 5; $t++) { $now = Get-HttpCode $u; if ($now -eq $b) { break }; Start-Sleep -Seconds 3 }
        Info "Health after: $u -> $now (before $b)"
        if ($now -ne $b) { Err "Health check failed: $u gave $b before the change and $now after it"; $ok = $false }
    }
    return $ok
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
function Get-ApacheServices { return @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'httpd\.exe' -and $_.State -eq 'Running' }) }

function Stop-PhpUsers([string]$Dir, $UsedBy) {
    $stopped = @()
    if ($UsedBy -contains 'iis') {
        Info 'Stopping IIS (iisreset /stop)'
        & "$env:windir\System32\iisreset.exe" /stop | Out-Null
        $stopped += 'iis'
    }
    if ($UsedBy -contains 'apache') {
        foreach ($s in Get-ApacheServices) { Info "Stopping service $($s.Name)"; Stop-Service -Name $s.Name -Force; $stopped += "svc:$($s.Name)" }
    }
    Start-Sleep -Seconds 2
    $left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and $_.Path -like "$Dir\*" } catch { $false } })
    if ($left.Count -gt 0) {
        Err ("Processes still use {0}: {1}. Stop them and run apply again." -f $Dir, (($left | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', '))
        Start-PhpUsers $stopped
        return $null
    }
    return , $stopped
}

function Start-PhpUsers($Stopped) {
    # Each start is tried on its own, so that one failure does not leave the other services stopped.
    foreach ($s in $Stopped) {
        try {
            if ($s -eq 'iis') {
                Info 'Starting IIS (iisreset /start)'
                & "$env:windir\System32\iisreset.exe" /start | Out-Null
                if ($LASTEXITCODE -ne 0) { Err "iisreset /start failed ($LASTEXITCODE). Start IIS manually." }
            } elseif ($s -like 'svc:*') { $n = $s.Substring(4); Info "Starting service $n"; Start-Service -Name $n -ErrorAction Stop }
        } catch { Err "Could not start $s : $($_.Exception.Message). Start it manually." }
    }
}

function Restart-PhpUsers($UsedBy) {
    if ($NoRestart) { Warn 'Restart skipped (-NoRestart). Restart IIS / Apache now to load the change.'; [void]$Script:Changes.Add('restart:skipped'); return }
    if ($UsedBy -contains 'iis') {
        $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
        if (Test-Path -LiteralPath $appcmd) {
            Info 'Recycling IIS application pools'
            foreach ($pool in @(& $appcmd list apppool /state:Started /text:name)) { & $appcmd recycle apppool /apppool.name:"$pool" | Out-Null }
        } else { & "$env:windir\System32\iisreset.exe" /restart | Out-Null }
        [void]$Script:Changes.Add('restart:iis')
    }
    if ($UsedBy -contains 'apache') {
        foreach ($s in Get-ApacheServices) { Info "Restarting service $($s.Name)"; Restart-Service -Name $s.Name -Force; [void]$Script:Changes.Add("restart:$($s.Name)") }
    }
}

# ---------------------------------------------------------------------------
# Patching: same branch, same build
# ---------------------------------------------------------------------------
$Script:Releases = $null
function Get-Releases {
    if ($Script:Releases) { return $Script:Releases }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Info "Reading $ReleasesUrl"
    $Script:Releases = Invoke-RestMethod -Uri $ReleasesUrl -UseBasicParsing -TimeoutSec 60
    return $Script:Releases
}

function Get-FixedZip($rt) {
    # Returns @{Version; File; Sha256} for the newest release of the same branch and build.
    if (-not $rt.build) { Err "Build type unknown for $($rt.path) (TS/NTS, compiler, arch). Cannot pick a zip."; return $null }
    $rel = Get-Releases
    $entry = $rel.($rt.branch)
    if (-not $entry) { Err "releases.json has no branch $($rt.branch)"; return $null }
    if ((Get-Branch $entry.version) -ne $rt.branch) { Err "releases.json branch mismatch: $($entry.version)"; return $null }
    $fixed = Get-FixedFor $rt.branch
    if ((Compare-Ver $entry.version $fixed) -lt 0) { Err "windows.php.net offers $($entry.version), lower than the fixed $fixed"; return $null }
    $b = $entry.($rt.build)
    if (-not $b -or -not $b.zip) { Err "No $($rt.build) zip for $($entry.version). Build types available: $((($entry.PSObject.Properties.Name) -match '-') -join ', ')"; return $null }
    return @{ Version = $entry.version; File = $b.zip.path; Sha256 = $b.zip.sha256 }
}

function Update-PhpDir($rt) {
    $z = Get-FixedZip $rt
    if (-not $z) { return $false }
    $dl = Join-Path $Script:RunDir 'downloads'; New-Item -ItemType Directory -Force -Path $dl | Out-Null
    $zipPath = Join-Path $dl $z.File
    if ($ZipDir -and (Test-Path -LiteralPath (Join-Path $ZipDir $z.File))) { Copy-Item -LiteralPath (Join-Path $ZipDir $z.File) -Destination $zipPath -Force }
    if (-not (Test-Path -LiteralPath $zipPath)) {
        $url = $DownloadBase + $z.File
        Info "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -TimeoutSec 600
    }
    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $z.Sha256.ToLower()) { Err "SHA-256 mismatch for $($z.File): $hash (expected $($z.Sha256))"; return $false }
    $ext = Join-Path $Script:RunDir ('extract\' + $z.Version + '-' + $rt.build)
    if (Test-Path -LiteralPath $ext) { Remove-Item -LiteralPath $ext -Recurse -Force }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $ext -Force
    if (-not (Test-Path -LiteralPath (Join-Path $ext 'php.exe'))) { Err "Zip $($z.File) has no php.exe"; return $false }

    $stopped = Stop-PhpUsers $rt.path $rt.used_by
    if ($null -eq $stopped) { return $false }
    # From here the web services are stopped. "finally" starts them again in every case,
    # also when an exception occurs; a partial copy is restored from the backup first.
    $bk = Join-Path $Script:RunDir ('backup\dir_' + (Get-ShortHash $rt.path))
    $copyStarted = $false; $ok = $false
    try {
        Info "Backing up $($rt.path) to $bk"
        & robocopy.exe $rt.path $bk /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Err "Backup failed (robocopy $LASTEXITCODE)"; return $false }
        Add-Manifest "DIR`t$($rt.path)`t$bk"
        # Copy the new files over the old ones. php.ini, third-party extensions and other local files stay.
        $copyStarted = $true
        & robocopy.exe $ext $rt.path /E /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Err "Copy failed (robocopy $LASTEXITCODE). Restoring $($rt.path)."; return $false }
        $ok = $true
    } catch {
        Err "Update of $($rt.path) failed: $($_.Exception.Message). Restoring."
        return $false
    } finally {
        if (-not $ok -and $copyStarted) {
            & robocopy.exe $bk $rt.path /MIR /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
            if ($LASTEXITCODE -ge 8) { Err "Restore of $($rt.path) failed (robocopy $LASTEXITCODE). Restore it from $bk manually." }
        }
        Start-PhpUsers $stopped
    }
    [void]$Script:Changes.Add("binaries:$($rt.path) $($rt.version) -> $($z.Version) ($($rt.build))")
    return $true
}

# ---------------------------------------------------------------------------
# Mitigation
# ---------------------------------------------------------------------------
function Set-IniMitigation($rt) {
    # Every php.ini that a service of this directory reads (CLI, IIS FastCGI, Apache PHPIniDir).
    $rules = Get-MitigationRules $rt.branch
    if ($rules.Count -eq 0) { Warn "Advisory $($Adv.id) has no mitigation rule for branch $($rt.branch). Nothing to mitigate."; return $false }
    $changed = $false
    foreach ($ini in $rt.inis) { if (Set-IniBlock $ini $rules) { $changed = $true } }
    return $changed
}

function Set-IniBlock([string]$Ini, $Rules) {
    $begin = "; >>> php-safepatch $($Adv.id) mitigation >>>"
    $end = "; <<< php-safepatch $($Adv.id) mitigation <<<"
    $ini = $Ini; $rules = $Rules
    $old = @()
    if (Test-Path -LiteralPath $ini) { $old = @(Get-Content -LiteralPath $ini) }
    $new = New-Object System.Collections.ArrayList
    $skip = $false
    foreach ($l in $old) {
        if ($l -eq $begin) { $skip = $true; continue }
        if ($l -eq $end) { $skip = $false; continue }
        if (-not $skip) { [void]$new.Add($l) }
    }
    # Values after a [PATH=] or [HOST=] section apply only to that path or host, and a later [PHP]
    # header does not end such a section. So the block goes before the first one (tested on PHP 8.3).
    $block = @($begin, "; Interim mitigation for $($Adv.id) ($($Adv.cves)). Remove after the runtime is patched.")
    foreach ($r in $rules) { $block += "$($r.Key) = $($r.Value)" }
    $block += $end
    $pos = $new.Count
    for ($i = 0; $i -lt $new.Count; $i++) { if ($new[$i] -match '^\s*\[(PATH|HOST)\s*=') { $pos = $i; break } }
    $new.InsertRange($pos, [string[]]$block)
    if (($old -join "`n") -eq ($new -join "`n")) { return $false }
    Backup-File $ini
    [IO.File]::WriteAllLines($ini, [string[]]$new.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
    [void]$Script:Changes.Add("ini:$ini")
    Info "Mitigation block in $ini"
    return $true
}

function Remove-IniMitigation($rt) {
    $changed = $false
    foreach ($ini in $rt.inis) { if (Remove-IniBlock $ini) { $changed = $true } }
    return $changed
}

function Remove-IniBlock([string]$Ini) {
    $begin = "; >>> php-safepatch $($Adv.id) mitigation >>>"
    $ini = $Ini
    if (-not (Test-Path -LiteralPath $ini)) { return $false }
    $old = @(Get-Content -LiteralPath $ini)
    if ($old -notcontains $begin) { return $false }
    $end = "; <<< php-safepatch $($Adv.id) mitigation <<<"
    $new = New-Object System.Collections.ArrayList; $skip = $false
    foreach ($l in $old) { if ($l -eq $begin) { $skip = $true; continue }; if ($l -eq $end) { $skip = $false; continue }; if (-not $skip) { [void]$new.Add($l) } }
    Backup-File $ini
    [IO.File]::WriteAllLines($ini, [string[]]$new.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
    [void]$Script:Changes.Add("removed-mitigation:$ini")
    return $true
}

function Restore-Run([string]$Rd) {
    $mf = Join-Path $Rd 'manifest'
    if (-not (Test-Path -LiteralPath $mf)) { return }
    $lines = @(Get-Content -LiteralPath $mf); [array]::Reverse($lines)
    foreach ($l in $lines) {
        $p = $l.Split("`t")
        switch ($p[0]) {
            'FILE' { Copy-Item -LiteralPath (Join-Path $Rd ('backup\' + $p[2])) -Destination $p[1] -Force; Info "Restored $($p[1])" }
            'CREATED' { if (Test-Path -LiteralPath $p[1]) { Remove-Item -LiteralPath $p[1] -Force; Info "Removed $($p[1])" } }
            'DIR' {
                $users = @(Get-DirUsers $p[1])
                $stopped = Stop-PhpUsers $p[1] $users
                if ($null -eq $stopped) { Err "Cannot restore $($p[1]) while processes use it"; continue }
                & robocopy.exe $p[2] $p[1] /MIR /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
                if ($LASTEXITCODE -ge 8) { Err "Restore of $($p[1]) failed (robocopy $LASTEXITCODE)" } else { Info "Restored directory $($p[1])" }
                Start-PhpUsers $stopped
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
function Invoke-Scan {
    foreach ($d in Find-PhpDirs) { Add-Runtime $d (Get-PhpInfo $d) }
    foreach ($rt in $Script:Runtimes) { Update-State $rt }
    Test-Indicators
}

function Update-State($rt) {
    Set-Running $rt
    Set-Assessment $rt
    Set-MitigationState $rt
}

function Confirm-Action([string]$Question) {
    if ($Yes) { return $true }
    if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $a = Read-Host "$Question [y/N]"
        return ($a -match '^[Yy]')
    }
    Err 'No console for confirmation. Use -Yes to apply without a prompt.'
    return $false
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Apply {
    if (-not (Test-Admin) -and $env:PHP_SAFEPATCH_TEST_NONROOT -ne '1') { Die 'apply must run as Administrator' }
    $todo = @($Script:Runtimes | Where-Object { $_.version -and ((Test-BadStatus $_.status) -or $Mitigate -eq 'always') })
    # Patched installations that still carry an old mitigation (for example memory_limit=-1):
    # remove it in auto mode.
    $cleanup = @()
    if ($Mitigate -eq 'auto') { $cleanup = @($Script:Runtimes | Where-Object { $_.status -eq 'PATCHED' -and $_.mitigation -ne 'none' }) }
    if ($todo.Count -eq 0 -and $cleanup.Count -eq 0) { Info 'Nothing to apply on this host.'; return }
    Show-Report
    $patchText = if ($NoPatch) { 'no' } else { 'same branch and build only' }
    $optText = if ($IncludeOptIn) { ' +opt-in rules' } else { '' }
    $rsText = if ($NoRestart) { 'no' } else { 'yes' }
    [Console]::Out.WriteLine(("`nPlanned: {0} installation(s). Patch: {1}. Mitigate: {2}{3}. Restart: {4}." -f $todo.Count, $patchText, $Mitigate, $optText, $rsText))
    if (-not (Confirm-Action "Apply these changes on $($env:COMPUTERNAME)?")) { Info 'Cancelled.'; return }

    $before = @{}
    foreach ($u in $HealthUrl) { $before[$u] = Get-HttpCode $u; Info "Health before: $u -> $($before[$u])" }

    foreach ($rt in $todo) {
        $mods = Get-Modules $rt.exe
        $patched = $false
        if (-not $NoPatch -and $rt.status -eq 'VULNERABLE') {
            $patched = Update-PhpDir $rt
            if ($patched) {
                $info = Get-PhpInfo $rt.path
                if ((Get-Branch $info.Version) -ne $rt.branch) { Err "Branch changed for $($rt.path): $($rt.branch) -> $($info.Version). Restoring."; Restore-Run $Script:RunDir; continue }
                $rt.version = $info.Version
                Set-Assessment $rt
                $after = Get-Modules $rt.exe
                $missing = @($mods | Where-Object { $after -notcontains $_ })
                if ($missing.Count -gt 0) {
                    Err "Extensions missing after update in $($rt.path): $($missing -join ', '). Restoring."
                    Restore-Run $Script:RunDir; $rt.version = (Get-PhpInfo $rt.path).Version; Set-Assessment $rt; continue
                }
            }
        }
        $rt.mitigated = $false
        if ($Mitigate -ne 'never') {
            if ((Test-BadStatus $rt.status) -or $Mitigate -eq 'always') {
                if (Set-IniMitigation $rt) { Restart-PhpUsers $rt.used_by }
                $rt.mitigated = ((Get-MitigationRules $rt.branch).Count -gt 0)
            } elseif ($patched) {
                if (Remove-IniMitigation $rt) { Restart-PhpUsers $rt.used_by }
            }
        }
        if ($patched -and $NoRestart) { Warn "IIS / Apache were restarted during the binary update of $($rt.path)." }
    }
    foreach ($rt in $cleanup) { if (Remove-IniMitigation $rt) { Restart-PhpUsers $rt.used_by } }

    # Verify with the state after the change: processes, values that each service reads, health.
    foreach ($rt in $Script:Runtimes) { Update-State $rt }
    foreach ($rt in $todo) {
        if (-not $rt.mitigated) { continue }
        if ($rt.mitigation -eq 'not_effective') { Err "Mitigation is written but a service of $($rt.path) does not use it. Check its php.ini, PHPRC and -c settings." }
        elseif ($rt.mitigation -eq 'none') { Err "No mitigation block reaches $($rt.path)." }
    }
    if (-not (Test-HealthAfter $before)) {
        Err 'Verification failed. Restoring everything this run changed.'
        Restore-Run $Script:RunDir
        foreach ($rt in $Script:Runtimes) { Restart-PhpUsers $rt.used_by; Update-State $rt }
    }
}

function Invoke-Rollback {
    if (-not (Test-Admin) -and $env:PHP_SAFEPATCH_TEST_NONROOT -ne '1') { Die 'rollback must run as Administrator' }
    $rd = $null
    if ($RunId) { $rd = Join-Path $StateDir $RunId }
    else {
        $rd = Get-ChildItem -LiteralPath $StateDir -Directory -ErrorAction SilentlyContinue |
              Where-Object { (Test-Path (Join-Path $_.FullName 'command')) -and ((Get-Content (Join-Path $_.FullName 'command')) -eq 'apply') } |
              Sort-Object Name | Select-Object -Last 1 | ForEach-Object { $_.FullName }
    }
    if (-not $rd -or -not (Test-Path -LiteralPath $rd)) { Die "Run not found. Use -RunId (see $StateDir)." }
    Info "Rolling back $rd"
    Get-Content -LiteralPath (Join-Path $rd 'manifest') -ErrorAction SilentlyContinue | ForEach-Object { [Console]::Out.WriteLine($_) }
    if (-not (Confirm-Action 'Restore the items listed above?')) { Info 'Cancelled.'; return }
    Restore-Run $rd
    $all = @(); foreach ($d in Find-PhpDirs) { $all += Get-DirUsers $d }
    Restart-PhpUsers ($all | Select-Object -Unique)
    Info 'Rollback finished.'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if ($Command -eq 'version') { [Console]::Out.WriteLine("php-safepatch $SafepatchVersion"); exit 0 }
if ($Advisory) { Import-Advisory $Advisory }

try {
    switch ($Command) {
        'scan' {
            [void](Initialize-RunDir ('{0}-scan-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID))
            Invoke-Scan
        }
        'apply' {
            if (-not (Initialize-RunDir ('{0}-apply-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID))) { Die 'apply needs a writable -StateDir' }
            Invoke-Scan
            Invoke-Apply
        }
        'rollback' {
            Invoke-Rollback
            if ($Script:Errors.Count -gt 0) { exit 2 } else { exit 0 }
        }
    }
} catch {
    Err ("Unexpected failure: {0} at {1}" -f $_.Exception.Message, $_.InvocationInfo.PositionMessage)
}

Show-Report
$jsonText = Get-JsonReport
if ($Json) { if ($Json -eq '-') { [Console]::Out.WriteLine($jsonText) } else { [IO.File]::WriteAllText($Json, $jsonText, (New-Object System.Text.UTF8Encoding($false))) } }
if ($Script:RunDir) { [IO.File]::WriteAllText((Join-Path $Script:RunDir 'report.json'), $jsonText, (New-Object System.Text.UTF8Encoding($false))) }

if ($Script:Errors.Count -gt 0) { exit 2 }
if ((Get-BadCount) -gt 0 -or (Get-IndicatorCount) -gt 0) { exit 1 }
exit 0
