# ============================================================================
#  Discord token extractor - scans Stable / PTB / Canary together
#  Saves tokens to Desktop\discord_tokens.txt (one token per line)
#
#  Authorized use only. Run as the SAME Windows user who is logged into
#  Discord, on that user's own machine/session.
#  Requires PowerShell 7 (pwsh) to decrypt modern (SafeStorage) tokens.
# ============================================================================
Add-Type -AssemblyName System.Security
$ErrorActionPreference = 'Continue'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[WARN] Windows PowerShell 5.1 detected.' -ForegroundColor Yellow
    Write-Host '       Modern Discord tokens are encrypted with AesGcm, which 5.1 does not support.' -ForegroundColor Yellow
    Write-Host '       Install PowerShell 7 (winget install Microsoft.PowerShell) and run:  pwsh ./thisfile.ps1' -ForegroundColor Yellow
}

# --- read a file even when Discord holds a lock on it -----------------------
function Read-FileAllowLock {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
              [System.IO.FileAccess]::Read,
              [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        try {
            $ms = New-Object System.IO.MemoryStream
            $fs.CopyTo($ms)
            return [System.Text.Encoding]::GetEncoding(28591).GetString($ms.ToArray())
        }
        finally { $ms.Dispose(); $fs.Dispose() }
    }
    catch { return $null }
}

# --- find all discord* app dirs (stable, ptb, canary, ...) ------------------
function Get-DiscordAppDirs {
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $roots = @($env:APPDATA, $env:LOCALAPPDATA) | Where-Object { $_ }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
            if ($d.Name -notmatch '^discord') { continue }
            $ldb = Join-Path $d.FullName 'Local Storage\leveldb'
            if ((Test-Path -LiteralPath $ldb) -and $seen.Add($d.FullName)) {
                [pscustomobject]@{ Name = $d.Name; AppDir = $d.FullName; LevelDb = $ldb }
            }
        }
    }
}

# --- DPAPI-unwrap the AES master key from "Local State" ---------------------
function Get-DiscordMasterKey {
    param([string]$AppDir)
    $ls = Join-Path $AppDir 'Local State'
    if (-not (Test-Path -LiteralPath $ls)) { return $null }
    try {
        $state = Read-FileAllowLock -Path $ls | ConvertFrom-Json
        $b64 = [string]$state.os_crypt.encrypted_key
        if (-not $b64) { return $null }
        $raw = [Convert]::FromBase64String($b64)
        if ($raw.Length -lt 6) { return $null }
        $blob = New-Object byte[] ($raw.Length - 5)          # strip "DPAPI"
        [Array]::Copy($raw, 5, $blob, 0, $blob.Length)
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $blob, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    catch { return $null }
}

# --- AES-256-GCM decrypt a SafeStorage blob (v10 + nonce + ct + tag) --------
function ConvertFrom-DiscordBlob {
    param([byte[]]$Key, [byte[]]$Blob)
    if ($Blob.Length -lt 32) { return $null }
    $nonce = New-Object byte[] 12
    [Array]::Copy($Blob, 3, $nonce, 0, 12)
    $tagLen = 16
    $ctLen  = $Blob.Length - 15 - $tagLen
    $ct = New-Object byte[] $ctLen
    [Array]::Copy($Blob, 15, $ct, 0, $ctLen)
    $tag = New-Object byte[] $tagLen
    [Array]::Copy($Blob, $Blob.Length - $tagLen, $tag, 0, $tagLen)
    $aes = [System.Security.Cryptography.AesGcm]::new($Key, $tagLen)
    try {
        $plain = New-Object byte[] $ctLen
        $aes.Decrypt($nonce, $ct, $tag, $plain)
        return [System.Text.Encoding]::UTF8.GetString($plain)
    }
    finally { $aes.Dispose() }
}

# --- scan leveldb files for plaintext + encrypted tokens --------------------
function Get-DiscordTokens {
    param([string]$LevelDbDir, [byte[]]$MasterKey)
    $tokens = [System.Collections.Generic.List[string]]::new()
    $files = Get-ChildItem -LiteralPath $LevelDbDir -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in '.ldb', '.log' }
    foreach ($f in $files) {
        $data = Read-FileAllowLock -Path $f.FullName
        if (-not $data) { continue }
        foreach ($m in [regex]::Matches($data, '[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}')) { $tokens.Add($m.Value) }
        foreach ($m in [regex]::Matches($data, 'mfa\.[\w-]{84}'))                     { $tokens.Add($m.Value) }
        if ($MasterKey) {
            foreach ($m in [regex]::Matches($data, 'dQw4w9WgXcQ:([A-Za-z0-9+/=]+)')) {
                try {
                    $t = ConvertFrom-DiscordBlob -Key $MasterKey -Blob ([Convert]::FromBase64String($m.Groups[1].Value))
                    if ($t -match '^[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}$') { $tokens.Add($t) }
                }
                catch { }
            }
        }
    }
    return @($tokens | Select-Object -Unique)
}

# --- (optional) check a token against the API -------------------------------
function Test-DiscordToken {
    param([string]$Token)
    try {
        $r = Invoke-RestMethod -Uri 'https://discord.com/api/v9/users/@me' `
            -Headers @{ Authorization = $Token } -Method Get -TimeoutSec 10
        return "VALID -> $($r.username) ($($r.id))"
    }
    catch { return 'invalid / expired' }
}

# =============================== MAIN =======================================
$Validate = $false   # set $true to call Discord API and print account name

# locate the real Desktop (handles OneDrive redirection / missing folder)
$desktop = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrEmpty($desktop) -or -not (Test-Path -LiteralPath $desktop)) {
    $alt = Join-Path $env:USERPROFILE 'Desktop'
    $desktop = if (Test-Path -LiteralPath $alt) { $alt } else { $env:USERPROFILE }
}
$OutputPath = Join-Path $desktop 'discord_tokens.txt'

Write-Host "PowerShell : $($PSVersionTable.PSVersion)"
Write-Host "User       : $env:USERNAME"
Write-Host "Output file: $OutputPath`n"

$apps = @(Get-DiscordAppDirs)
if ($apps.Count -eq 0) {
    Write-Host '[!] No "discord*" app folder with Local Storage\leveldb was found.' -ForegroundColor Yellow
    Write-Host '    Checked: %APPDATA% and %LOCALAPPDATA%' -ForegroundColor Yellow
    Write-Host '    -> Is Discord installed and logged in under THIS Windows user?' -ForegroundColor Yellow
}
else {
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($app in $apps) {
        Write-Host "== $($app.Name)   [$($app.AppDir)]" -ForegroundColor Cyan
        $key = Get-DiscordMasterKey -AppDir $app.AppDir
        if (-not $key) {
            Write-Host '   no master key (Local State missing, or this is a different Windows user/machine) -> encrypted tokens skipped' -ForegroundColor DarkYellow
        }
        $found = @(Get-DiscordTokens -LevelDbDir $app.LevelDb -MasterKey $key)
        Write-Host "   tokens found: $($found.Count)"
        foreach ($t in $found) {
            $all.Add($t)
            Write-Host "   TOKEN: $t"
            if ($Validate) { Write-Host ('   ' + (Test-DiscordToken -Token $t)) }
        }
    }

    $unique = @($all | Select-Object -Unique)
    if ($unique.Count -gt 0) {
        # one token per line -> a single token produces a single-line file.
        # To merge ALL tokens into ONE single line instead, replace the next
        # line with:  [System.IO.File]::WriteAllText($OutputPath, ($unique -join ','))
        [System.IO.File]::WriteAllLines($OutputPath, [string[]]$unique)
        Write-Host "`n[OK] Saved $($unique.Count) token(s) to: $OutputPath" -ForegroundColor Green
    }
    else {
        Write-Host "`n[!] No token found in any Discord app, so no file was created." -ForegroundColor Yellow
        Write-Host "    Expected path: $OutputPath" -ForegroundColor Yellow
    }
}
