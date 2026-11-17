param(
    [int]$Count = 800,
    [int]$DelayMs = 15000,
    [string]$WorkDir = "C:\PoC_D07\Benign"
)
# Sinh hoat dong PowerShell BINH THUONG (benign) de mo rong dataset.
# - Moi lenh mang the "# D07-BENIGN:<kich_ban>" de extract_dataset.ps1 gan nhan theo NGUON GOC,
#   khong dua vao luat cua detector.
# - Chi doc thong tin he thong va ghi file trong $WorkDir. Khong dung mang, khong sua cau hinh
#   (ngoai 1 scheduled task tam, duoc xoa khi ket thuc).
# - Chay trong VM lab, can quyen admin cho kich ban scheduled task.

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

function Enc([string]$cmd) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)) }
function Tag([string]$name) { "# D07-BENIGN:$name" }
function Cmd([string]$name, [string]$cmd, [string]$extra = "") {
    "-NoProfile $extra -Command `"$cmd $(Tag $name)`""
}

$inv = Join-Path $WorkDir "inventory.ps1"
$out = Join-Path $WorkDir "report.txt"
$log = Join-Path $WorkDir "audit.log"
Set-Content -Path $inv -Encoding ASCII -Value @'
# D07-BENIGN:file_script
Get-ChildItem $env:TEMP -ErrorAction SilentlyContinue | Measure-Object | Out-File (Join-Path $PSScriptRoot 'inventory.txt')
'@

# W = trong so (ty le xuat hien). Cac kich ban "kho" (hard negative) mo phong cong cu quan tri
# hop phap; ty le cua chung quyet dinh muc false positive -> ghi ro trong bao cao.
$Scenarios = @(
    @{ N = "query_process";    W = 14; Exe = "powershell.exe"; A = (Cmd "query_process" 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5') },
    @{ N = "query_service";    W = 12; Exe = "powershell.exe"; A = (Cmd "query_service" 'Get-Service | Where-Object { $_.Status -eq ''Running'' } | Measure-Object') },
    @{ N = "list_files";       W = 10; Exe = "powershell.exe"; A = (Cmd "list_files" 'Get-ChildItem $env:WINDIR\System32 -Filter *.dll | Measure-Object') },
    @{ N = "cim_query";        W = 8;  Exe = "powershell.exe"; A = (Cmd "cim_query" 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version') },
    @{ N = "write_report";     W = 10; Exe = "powershell.exe"; A = (Cmd "write_report" ("Get-Date | Out-File -FilePath '{0}' -Append" -f $out)) },
    @{ N = "file_script";      W = 10; Exe = "powershell.exe"; A = "-NoProfile -ExecutionPolicy Bypass -File `"$inv`"" },
    @{ N = "iex_read";         W = 6;  Exe = "powershell.exe"; A = (Cmd "iex_read" 'Invoke-Expression ''Get-Date''') },
    @{ N = "via_cmd";          W = 6;  Exe = "cmd.exe";        A = "/c powershell.exe -NoProfile -Command `"Get-ChildItem `$env:USERPROFILE | Measure-Object $(Tag 'via_cmd')`"" },
    @{ N = "schtask_system";   W = 4;  Exe = "";               A = "" },
    # --- hard negatives ---
    @{ N = "enc_admin";        W = 3;  Exe = "powershell.exe"; A = "-NoProfile -NonInteractive -EncodedCommand $(Enc "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, FreeSpace $(Tag 'enc_admin')")" },
    @{ N = "enc_hidden_agent"; W = 1;  Exe = "powershell.exe"; A = "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $(Enc "Get-Date $(Tag 'enc_hidden_agent')")" },
    @{ N = "iex_write_admin";  W = 1;  Exe = "powershell.exe"; A = (Cmd "iex_write_admin" ("Invoke-Expression 'Add-Content -Path ''{0}'' -Value audit'" -f $log)) }
)

$taskName = "PoC_D07_BenignTask"
$hasTask = $false
try {
    $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$inv`""
    Register-ScheduledTask -TaskName $taskName -Action $act -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    $hasTask = $true
} catch {
    Write-Warning "Khong tao duoc scheduled task (can quyen admin) - bo qua kich ban schtask_system"
}

$pool = @($Scenarios | Where-Object { $_.N -ne "schtask_system" -or $hasTask })
$total = ($pool | ForEach-Object { $_.W } | Measure-Object -Sum).Sum
function Pick {
    $r = Get-Random -Minimum 0 -Maximum $total
    foreach ($s in $pool) { if ($r -lt $s.W) { return $s }; $r -= $s.W }
}

$counts = @{}
$start = Get-Date
Write-Host "Bat dau: $start | $Count lenh, cach nhau $DelayMs ms (~$([math]::Round($Count*$DelayMs/60000)) phut)"
try {
    for ($i = 1; $i -le $Count; $i++) {
        $s = Pick
        try {
            if ($s.N -eq "schtask_system") { Start-ScheduledTask -TaskName $taskName }
            else { Start-Process -FilePath $s.Exe -ArgumentList $s.A -WindowStyle Hidden }
            $counts[$s.N] = 1 + [int]$counts[$s.N]
        } catch { Write-Warning "[$i] $($s.N): $($_.Exception.Message)" }
        if ($i % 50 -eq 0) { Write-Host "  $i / $Count" }
        Start-Sleep -Milliseconds $DelayMs
    }
} finally {
    if ($hasTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    Write-Host "Ket thuc: $(Get-Date) (bat dau $start)"
    $counts.GetEnumerator() | Sort-Object Name | Format-Table Name, Value -AutoSize
}
