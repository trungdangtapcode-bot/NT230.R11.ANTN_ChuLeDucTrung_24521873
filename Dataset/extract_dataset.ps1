param(
    [int]$LookbackHours = 6,
    [string]$OutputPath = (Join-Path $PSScriptRoot "dataset.csv"),
    # Lop 4: cua so (phut) truoc process creation de tim event WMI 19/20/21
    [int]$SeqWindowMinutes = 60,
    # Ghep Event 4104 voi process: CUNG ProcessId va trong +/- N giay (tranh lan noi dung giua cac tien trinh)
    [int]$SbWindowSeconds = 10,
    # The nhan dien payload cua PoC (payload ghi vao C:\PoC_D07\Logs\marker_fileless*.txt)
    [string]$PocTag = "marker_fileless"
)

# NHAN (ground truth) duoc gan theo NGUON GOC, khong theo luat cua detector:
#   - malicious_fileless : lenh (sau khi giai ma) chua $PocTag -> do PoC sinh ra
#   - benign / workload  : lenh mang the "D07-BENIGN" hoac chay script trong \PoC_D07\Benign\
#   - benign / background: PowerShell khac cua he thong / nguoi dung
# Detector KHONG duoc dung cot Source/Scenario/Label.

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"
$startTime = (Get-Date).AddHours(-$LookbackHours)

Write-Host "Dang lay Sysmon Event ID 1..."
$sysmonEvents = Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 1; StartTime = $startTime } -ErrorAction SilentlyContinue

Write-Host "Dang lay Sysmon Event ID 19/20/21 (WMI Filter/Consumer/Binding)..."
$wmiEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 19,20,21; StartTime = $startTime.AddMinutes(-$SeqWindowMinutes) } -ErrorAction SilentlyContinue)

Write-Host "Dang lay PowerShell Script Block Log (Event 4104)..."
$scriptBlockEvents = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Id = 4104; StartTime = $startTime } -ErrorAction SilentlyContinue |
    ForEach-Object {
        if ($_.Message -match "(?s)Creating Scriptblock text \(\d+ of \d+\):\s*(.+?)\s*ScriptBlock ID:") {
            [PSCustomObject]@{ TimeCreated = $_.TimeCreated; ProcessId = $_.ProcessId; ScriptText = $matches[1] }
        }
    })

function Get-Field($Msg, $Name) {
    if ($Msg -match "(?m)^${Name}:\s*(.+)") { return $matches[1].Trim() }
    return ""
}
function Get-DecodedCommand([string]$CommandLine) {
    if ($CommandLine -match "-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]+)") {
        try { return [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($matches[1])) } catch { }
    }
    return ""
}
function Hide-User([string]$u) {
    if ($u -match "^NT AUTHORITY\\" -or [string]::IsNullOrEmpty($u) -or $u -eq "-") { return $u }
    return "[REDACTED]"
}

$dataset = foreach ($event in $sysmonEvents) {
    $msg = $event.Message
    $image = Get-Field $msg "Image"
    if ($image -notmatch "\\(powershell|pwsh)\.exe$") { continue }

    $parentImage    = Get-Field $msg "ParentImage"
    $commandLine    = Get-Field $msg "CommandLine"
    $userVal        = Hide-User (Get-Field $msg "User")
    $parentUser     = Hide-User (Get-Field $msg "ParentUser")
    $integrityLevel = Get-Field $msg "IntegrityLevel"
    $procId         = 0; [void][int]::TryParse((Get-Field $msg "ProcessId"), [ref]$procId)
    $decoded        = Get-DecodedCommand $commandLine
    $cmdAndDecoded  = "$commandLine $decoded"

    # ----- Nhan theo nguon goc -----
    if ($cmdAndDecoded -match [regex]::Escape($PocTag)) {
        $label = "malicious_fileless"; $source = "poc"
        # poc_wmi = thay duoc cha WmiPrvSE; poc_wmi_noparent = cha da thoat nen Sysmon ghi "-"
        $scenario = if ($parentImage -match "WmiPrvSE") { "poc_wmi" } elseif ($parentImage -eq "-" -or $parentImage -eq "") { "poc_wmi_noparent" } else { "poc_other" }
    } elseif ($cmdAndDecoded -match "D07-BENIGN:(\w+)") {
        $label = "benign"; $source = "workload"; $scenario = $matches[1]
    } elseif ($cmdAndDecoded -match "\\PoC_D07\\Benign\\") {
        $label = "benign"; $source = "workload"
        $scenario = if ($parentImage -match "svchost") { "schtask_system" } else { "file_script" }
    } else {
        $label = "benign"; $source = "background"; $scenario = "background"
    }

    # ----- Lop 6: noi dung script (4104 cung ProcessId) + lenh da giai ma -----
    $recTime = $event.TimeCreated
    $matched = $scriptBlockEvents | Where-Object { $_.ProcessId -eq $procId -and [Math]::Abs(($_.TimeCreated - $recTime).TotalSeconds) -le $SbWindowSeconds }
    $combinedText = (($matched | ForEach-Object { $_.ScriptText }) -join " ") + " " + $cmdAndDecoded

    $hasIEX     = $combinedText -match "Invoke-Expression|\bIEX\b"
    $hasWrite   = $combinedText -match "Add-Content|Set-Content|Out-File|New-Item|Remove-Item"
    $hasNetwork = $combinedText -match "DownloadString|WebClient|Invoke-WebRequest|Net\.Sockets"

    # ----- Lop 4: so loai event WMI 19/20/21 trong cua so truoc tien trinh -----
    $winStart = $recTime.AddMinutes(-$SeqWindowMinutes)
    $wmiSubCount = @($wmiEvents | Where-Object { $_.TimeCreated -ge $winStart -and $_.TimeCreated -le $recTime } |
        Select-Object -ExpandProperty Id -Unique).Count

    # ----- Lop 7: co file script tren dia khong -----
    $scriptOnDisk = $commandLine -match "-File\s+\S+\.ps1"

    [PSCustomObject]@{
        TimeCreated         = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Image               = $image
        ParentImage         = $parentImage
        CommandLine         = $commandLine
        User                = $userVal
        ParentUser          = $parentUser
        IntegrityLevel      = $integrityLevel
        HasIEX              = $hasIEX
        HasWriteAction      = $hasWrite
        HasNetworkIndicator = $hasNetwork
        WmiSubCount         = $wmiSubCount
        ScriptOnDisk        = $scriptOnDisk
        Source              = $source
        Scenario            = $scenario
        Label               = $label
    }
}

$dataset = @($dataset | Sort-Object TimeCreated)
$dataset | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Da xuat dataset: $($dataset.Count) records -> $OutputPath"
$dataset | Group-Object Label, Source | Select-Object Name, Count | Format-Table -AutoSize
