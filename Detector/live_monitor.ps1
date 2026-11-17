param(
    [int]$Threshold = 50,
    [int]$PollSeconds = 2,
    # Lop 4: coi 1 dang ky WMI (Sysmon 19/20/21) la "con hieu luc" trong N phut
    [int]$SeqWindowMinutes = 60
)

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

function Get-Field {
    param($Msg, $Name)
    if ($Msg -match "(?m)^${Name}:\s*(.+)") { return $matches[1].Trim() }
    return ""
}

# Lop 4: dem so loai event 19/20/21 trong cua so thoi gian
function Get-WmiSubCount {
    param([datetime]$At)
    $start = $At.AddMinutes(-$SeqWindowMinutes)
    $ids = Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 19,20,21; StartTime = $start; EndTime = $At } -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Id -Unique
    return @($ids).Count
}

function Get-RecordScore {
    param($Evt)
    $msg = $Evt.Message
    $score = 0
    $reasons = @()

    $parentImage = Get-Field $msg "ParentImage"
    $commandLine = Get-Field $msg "CommandLine"
    $parentUser  = Get-Field $msg "ParentUser"

    $isEncoded = $commandLine -match "-EncodedCommand|-enc\s"
    $hasIEX    = $commandLine -match "Invoke-Expression|\bIEX\b"

    if ($parentImage -match "WmiPrvSE\.exe") {
        $score += 40; $reasons += "L1 ParentImage=WmiPrvSE.exe"
    }
    if ($isEncoded) {
        $score += 30; $reasons += "L2 EncodedCommand"
    }
    if ($parentUser -match "NT AUTHORITY\\SYSTEM" -and $commandLine -notmatch "svchost|TrustedInstaller") {
        $score += 15; $reasons += "L3 SYSTEM context"
    }
    $wmiCount = Get-WmiSubCount -At $Evt.TimeCreated
    $wmiLike = ($parentImage -match "WmiPrvSE\.exe") -or ($parentImage -eq "-") -or ($parentImage -eq "")
    if ($wmiCount -ge 2 -and $wmiLike) {
        $score += 15; $reasons += "L4 WMI 19/20/21 x$wmiCount"
    }
    if ($commandLine -match "-WindowStyle\s+Hidden" -and $commandLine -match "-EncodedCommand") {
        $score += 25; $reasons += "L5 Hidden+Encoded"
    }
    # Lop 6 (4104) duoc danh gia o detector.ps1 tren dataset; live chi dung Sysmon 1.
    if (($isEncoded -or $hasIEX) -and $commandLine -notmatch "-File\s+\S+\.ps1") {
        $score += 20; $reasons += "L7 In-memory, no script file"
    }

    return [PSCustomObject]@{
        Score   = $score
        Reasons = ($reasons -join "; ")
    }
}

Write-Host "=== D07 LIVE MONITOR ===" -ForegroundColor Cyan
Write-Host "Nguong canh bao: $Threshold diem | Cua so WMI: $SeqWindowMinutes phut" -ForegroundColor Cyan
Write-Host "Dang giam sat Sysmon Event ID 1... (Ctrl+C de dung)" -ForegroundColor Cyan
Write-Host ""

$lastRecordId = (Get-WinEvent -LogName $SysmonLog -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
if (-not $lastRecordId) { $lastRecordId = 0 }

while ($true) {
    Start-Sleep -Seconds $PollSeconds

    $newEvents = Get-WinEvent -LogName $SysmonLog -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1 -and $_.RecordId -gt $lastRecordId } |
        Sort-Object RecordId

    if ($newEvents) {
        $lastRecordId = ($newEvents | Select-Object -Last 1).RecordId

        foreach ($evt in $newEvents) {
            $result = Get-RecordScore -Evt $evt
            $image = Get-Field $evt.Message "Image"
            $time = $evt.TimeCreated.ToString("HH:mm:ss")

            if ($result.Score -ge $Threshold) {
                Write-Host "[$time] *** CANH BAO *** Score=$($result.Score) | $image | $($result.Reasons)" -ForegroundColor Red
            } else {
                Write-Host "[$time] binh thuong  Score=$($result.Score) | $image" -ForegroundColor DarkGray
            }
        }
    }
}
