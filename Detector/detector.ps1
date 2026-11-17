param(
    [string]$DatasetPath = (Join-Path $PSScriptRoot "..\Dataset\dataset.csv"),
    [string]$OutputPath  = (Join-Path $PSScriptRoot "detection_results.csv"),
    [int]$Threshold = 50,
    # Tat bot lop de lam ablation, vd: -DisableLayers 4,7
    [int[]]$DisableLayers = @()
)

# ===================== 7 LOP PHAT HIEN =====================

# Lop 1 - Cay tien trinh (Sysmon 1)
function Test-ProcessTreeAnomaly {
    param($Record)
    if ($Record.ParentImage -match "WmiPrvSE\.exe") { return 40 }
    return 0
}

# Lop 2 - Lenh bi ma hoa (Sysmon 1)
function Test-CommandLineObfuscation {
    param($Record)
    if ($Record.CommandLine -match "-EncodedCommand|-enc\s") { return 30 }
    return 0
}

# Lop 3 - Ngu canh SYSTEM (Sysmon 1)
function Test-UserContextAnomaly {
    param($Record)
    if ($Record.ParentUser -match "NT AUTHORITY\\SYSTEM" -and $Record.CommandLine -notmatch "svchost|TrustedInstaller") { return 15 }
    return 0
}

# Lop 4 - Chuoi su kien WMI (Sysmon 19/20/21)
# WmiSubCount = so loai event Filter(19)/Consumer(20)/Binding(21) xuat hien
# trong cua so thoi gian truoc process creation (xem extract_dataset.ps1).
function Test-WmiSequenceAnomaly {
    param($Record)
    $count = 0
    [void][int]::TryParse("$($Record.WmiSubCount)", [ref]$count)
    # Chi tinh khi tien trinh CO THE do WMI sinh ra: cha la WmiPrvSE.exe hoac khong
    # xac dinh duoc ("-", cha da thoat truoc khi Sysmon ghi log). Neu khong gioi han,
    # moi PowerShell chay trong cua so sau khi dang ky WMI deu bi cong diem (xem README).
    $parent = "$($Record.ParentImage)".Trim()
    $wmiLike = ($parent -match "WmiPrvSE\.exe") -or ($parent -eq "-") -or ($parent -eq "")
    if ($count -ge 2 -and $wmiLike) { return 15 }
    return 0
}

# Lop 5 - Chay an + ma hoa (Sysmon 1)
function Test-HiddenEncodedExecution {
    param($Record)
    if ($Record.CommandLine -match "-WindowStyle\s+Hidden" -and $Record.CommandLine -match "-EncodedCommand") { return 25 }
    return 0
}

# Lop 6 - Noi dung script (PowerShell 4104)
function Test-ScriptBlockContent {
    param($Record)
    $hasIEX   = "$($Record.HasIEX)" -eq "True"
    $hasWrite = "$($Record.HasWriteAction)" -eq "True"
    $hasNet   = "$($Record.HasNetworkIndicator)" -eq "True"

    if ($hasNet) { return 60 }
    if ($hasIEX -and $hasWrite) { return 55 }
    if ($hasIEX) { return 15 }
    return 0
}

# Lop 7 - Memory artifact: code chay trong RAM (encoded / IEX inline)
# ma KHONG co file script tuong ung tren dia (-File *.ps1).
function Test-MemoryArtifact {
    param($Record)
    $inMemory = ($Record.CommandLine -match "-EncodedCommand|-enc\s") -or ("$($Record.HasIEX)" -eq "True")
    $onDisk   = "$($Record.ScriptOnDisk)" -eq "True"
    if ($inMemory -and -not $onDisk) { return 20 }
    return 0
}

$Layers = @(
    @{ Id = 1; Name = "ParentImage=WmiPrvSE.exe"; Fn = ${function:Test-ProcessTreeAnomaly} },
    @{ Id = 2; Name = "EncodedCommand";           Fn = ${function:Test-CommandLineObfuscation} },
    @{ Id = 3; Name = "SYSTEM context";           Fn = ${function:Test-UserContextAnomaly} },
    @{ Id = 4; Name = "WMI 19/20/21 sequence";    Fn = ${function:Test-WmiSequenceAnomaly} },
    @{ Id = 5; Name = "Hidden+Encoded";           Fn = ${function:Test-HiddenEncodedExecution} },
    @{ Id = 6; Name = "ScriptBlock content";      Fn = ${function:Test-ScriptBlockContent} },
    @{ Id = 7; Name = "In-memory, no script file";Fn = ${function:Test-MemoryArtifact} }
)

function Invoke-Detector {
    param($DatasetPath, $Threshold)
    $records = Import-Csv -Path $DatasetPath
    foreach ($record in $records) {
        $score = 0
        $reasons = @()
        foreach ($layer in $Layers) {
            if ($DisableLayers -contains $layer.Id) { continue }
            $s = & $layer.Fn -Record $record
            if ($s -gt 0) {
                $score += $s
                $reasons += "L$($layer.Id) $($layer.Name)(+$s)"
            }
        }
        $prediction = if ($score -ge $Threshold) { "malicious_fileless" } else { "benign" }

        [PSCustomObject]@{
            TimeCreated = $record.TimeCreated
            Score       = $score
            Prediction  = $prediction
            ActualLabel = $record.Label
            Reasons     = ($reasons -join "; ")
            Correct     = ($prediction -eq $record.Label)
        }
    }
}

$detectionResults = @(Invoke-Detector -DatasetPath $DatasetPath -Threshold $Threshold)
$detectionResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$TP = @($detectionResults | Where-Object { $_.Prediction -eq "malicious_fileless" -and $_.ActualLabel -eq "malicious_fileless" }).Count
$FP = @($detectionResults | Where-Object { $_.Prediction -eq "malicious_fileless" -and $_.ActualLabel -eq "benign" }).Count
$TN = @($detectionResults | Where-Object { $_.Prediction -eq "benign" -and $_.ActualLabel -eq "benign" }).Count
$FN = @($detectionResults | Where-Object { $_.Prediction -eq "benign" -and $_.ActualLabel -eq "malicious_fileless" }).Count

$precision = if (($TP+$FP) -gt 0) { $TP/($TP+$FP) } else { 0 }
$recall    = if (($TP+$FN) -gt 0) { $TP/($TP+$FN) } else { 0 }
$f1        = if (($precision+$recall) -gt 0) { 2*$precision*$recall/($precision+$recall) } else { 0 }
$fpr       = if (($FP+$TN) -gt 0) { $FP/($FP+$TN) } else { 0 }

Write-Host "Dataset   : $DatasetPath"
Write-Host "Tong so records: $($detectionResults.Count)"
if ($DisableLayers.Count -gt 0) { Write-Host "Da tat lop: $($DisableLayers -join ', ')" }
Write-Host "KET QUA"
Write-Host "TP=$TP  FP=$FP  TN=$TN  FN=$FN"
Write-Host ("Precision = {0:P2}" -f $precision)
Write-Host ("Recall    = {0:P2}" -f $recall)
Write-Host ("F1-Score  = {0:P2}" -f $f1)
Write-Host ("FPR       = {0:P2}" -f $fpr)
Write-Host "Chi tiet: $OutputPath"
