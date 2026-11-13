param(
    [int]$LookbackHours = 24,
    [string]$OutputPath = "C:\PoC_D07\Dataset\dataset_final.csv"
)

Write-Host "Dang lay Sysmon Event ID 1..."
$startTime = (Get-Date).AddHours(-$LookbackHours)

$sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $startTime }

Write-Host "Dang lay PowerShell Script Block Log (Event 4104)..."
$scriptBlockEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 } |
    ForEach-Object {
        if ($_.Message -match "(?s)Creating Scriptblock text \(1 of 1\):\s*(.+?)\s*ScriptBlock ID:") {
            [PSCustomObject]@{ TimeCreated = $_.TimeCreated; ScriptText = $matches[1] }
        }
    }

$dataset = foreach ($event in $sysmonEvents) {
    $msg = $event.Message

    $image          = if ($msg -match "(?m)^Image:\s*(.+)") { $matches[1].Trim() } else { "" }
    $parentImage    = if ($msg -match "(?m)^ParentImage:\s*(.+)") { $matches[1].Trim() } else { "" }
    $commandLine    = if ($msg -match "(?m)^CommandLine:\s*(.+)") { $matches[1].Trim() } else { "" }
    $userVal        = if ($msg -match "(?m)^User:\s*(.+)") { $matches[1].Trim() } else { "" }
    $parentUser     = if ($msg -match "(?m)^ParentUser:\s*(.+)") { $matches[1].Trim() } else { "" }
    $integrityLevel = if ($msg -match "(?m)^IntegrityLevel:\s*(.+)") { $matches[1].Trim() } else { "" }

    if ($parentImage -match "WmiPrvSE") {
        $label = "malicious_fileless"
    } elseif ($commandLine -match "-WindowStyle\s+Hidden" -and $commandLine -match "-EncodedCommand") {
        $label = "malicious_fileless"
    } else {
        $label = "benign"
    }

    $recTime = $event.TimeCreated
    $matched = $scriptBlockEvents | Where-Object { [Math]::Abs(($_.TimeCreated - $recTime).TotalSeconds) -le 5 }
    $combinedText = ($matched | ForEach-Object { $_.ScriptText }) -join " "

    $hasIEX     = $combinedText -match "Invoke-Expression|\bIEX\b"
    $hasWrite   = $combinedText -match "Add-Content|Set-Content|Out-File|New-Item|Remove-Item"
    $hasNetwork = $combinedText -match "DownloadString|WebClient|Invoke-WebRequest|Net\.Sockets"

    if ($hasIEX -and ($hasWrite -or $hasNetwork)) {
        $label = "malicious_fileless"
    }

    [PSCustomObject]@{
        TimeCreated         = $event.TimeCreated
        Image               = $image
        ParentImage         = $parentImage
        CommandLine         = $commandLine
        User                = $userVal
        ParentUser          = $parentUser
        IntegrityLevel      = $integrityLevel
        Label               = $label
        HasIEX              = $hasIEX
        HasWriteAction      = $hasWrite
        HasNetworkIndicator = $hasNetwork
    }
}

$dataset | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "Da xuat dataset: $($dataset.Count) records -> $OutputPath"
$dataset | Group-Object Label | Select-Object Name, Count