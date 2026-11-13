param(
    [int]$Threshold = 50,
    [int]$PollSeconds = 2
)

function Get-RecordScore {
    param($Msg)
    $score = 0
    $reasons = @()

    $parentImage = if ($Msg -match "(?m)^ParentImage:\s*(.+)") { $matches[1].Trim() } else { "" }
    $commandLine = if ($Msg -match "(?m)^CommandLine:\s*(.+)") { $matches[1].Trim() } else { "" }
    $parentUser  = if ($Msg -match "(?m)^ParentUser:\s*(.+)") { $matches[1].Trim() } else { "" }

    if ($parentImage -match "WmiPrvSE\.exe") {
        $score += 40
        $reasons += "ParentImage=WmiPrvSE.exe"
    }
    if ($commandLine -match "-EncodedCommand|-enc\s") {
        $score += 30
        $reasons += "EncodedCommand"
    }
    if ($parentUser -match "NT AUTHORITY\\SYSTEM" -and $commandLine -notmatch "svchost|TrustedInstaller") {
        $score += 15
        $reasons += "SYSTEM context"
    }
    if ($commandLine -match "-WindowStyle\s+Hidden" -and $commandLine -match "-EncodedCommand") {
        $score += 25
        $reasons += "Hidden+Encoded"
    }

    return [PSCustomObject]@{
        Score   = $score
        Reasons = ($reasons -join "; ")
    }
}

Write-Host "=== D07 LIVE MONITOR ===" -ForegroundColor Cyan
Write-Host "Nguong canh bao: $Threshold diem" -ForegroundColor Cyan
Write-Host "Dang giam sat Sysmon Event ID 1... (Ctrl+C de dung)" -ForegroundColor Cyan
Write-Host ""

$lastRecordId = (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
if (-not $lastRecordId) { $lastRecordId = 0 }

while ($true) {
    Start-Sleep -Seconds $PollSeconds

    $newEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1 -and $_.RecordId -gt $lastRecordId } |
        Sort-Object RecordId

    if ($newEvents) {
        $lastRecordId = ($newEvents | Select-Object -Last 1).RecordId

        foreach ($event in $newEvents) {
            $result = Get-RecordScore -Msg $event.Message
            $image = if ($event.Message -match "(?m)^Image:\s*(.+)") { $matches[1].Trim() } else { "?" }
            $time = $event.TimeCreated.ToString("HH:mm:ss")

            if ($result.Score -ge $Threshold) {
                Write-Host "[$time] *** CANH BAO *** Score=$($result.Score) | $image | $($result.Reasons)" -ForegroundColor Red
            } else {
                Write-Host "[$time] binh thuong  Score=$($result.Score) | $image" -ForegroundColor DarkGray
            }
        }
    }
}