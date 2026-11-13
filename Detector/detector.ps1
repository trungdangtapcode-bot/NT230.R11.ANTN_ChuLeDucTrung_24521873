param(
    [string]$DatasetPath = "C:\PoC_D07\Dataset\full_dataset_v3.csv",
    [int]$Threshold = 50
)

function Test-ProcessTreeAnomaly {
    param($Record)
    if ($Record.ParentImage -match "WmiPrvSE\.exe") { return 40 }
    return 0
}

function Test-CommandLineObfuscation {
    param($Record)
    if ($Record.CommandLine -match "-EncodedCommand|-enc\s") { return 30 }
    return 0
}

function Test-UserContextAnomaly {
    param($Record)
    if ($Record.ParentUser -match "NT AUTHORITY\\SYSTEM" -and $Record.CommandLine -notmatch "svchost|TrustedInstaller") { return 15 }
    return 0
}

function Test-HiddenEncodedExecution {
    param($Record)
    if ($Record.CommandLine -match "-WindowStyle\s+Hidden" -and $Record.CommandLine -match "-EncodedCommand") { return 25 }
    return 0
}

function Test-ScriptBlockContent {
    param($Record)
    $hasIEX = $Record.HasIEX -eq "True"
    $hasWrite = $Record.HasWriteAction -eq "True"
    $hasNet = $Record.HasNetworkIndicator -eq "True"

    if ($hasNet) { return 60 }
    if ($hasIEX -and $hasWrite) { return 55 }
    if ($hasIEX) { return 15 }
    return 0
}

function Invoke-Detector {
    param($DatasetPath, $Threshold)
    $records = Import-Csv -Path $DatasetPath
    $results = foreach ($record in $records) {
        $score = 0
        $reasons = @()

        $s1 = Test-ProcessTreeAnomaly -Record $record
        if ($s1 -gt 0) { $reasons += "ParentImage=WmiPrvSE.exe(+$s1)" }
        $score += $s1

        $s2 = Test-CommandLineObfuscation -Record $record
        if ($s2 -gt 0) { $reasons += "EncodedCommand(+$s2)" }
        $score += $s2

        $s3 = Test-UserContextAnomaly -Record $record
        if ($s3 -gt 0) { $reasons += "SYSTEM context(+$s3)" }
        $score += $s3

        $s5 = Test-HiddenEncodedExecution -Record $record
        if ($s5 -gt 0) { $reasons += "Hidden+Encoded(+$s5)" }
        $score += $s5

        $s6 = Test-ScriptBlockContent -Record $record
        if ($s6 -gt 0) { $reasons += "ScriptBlock content(+$s6)" }
        $score += $s6

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
    return $results
}

$detectionResults = Invoke-Detector -DatasetPath $DatasetPath -Threshold $Threshold
$detectionResults | Export-Csv -Path "C:\PoC_D07\Detector\detection_results_v3.csv" -NoTypeInformation

$TP = ($detectionResults | Where-Object { $_.Prediction -eq "malicious_fileless" -and $_.ActualLabel -eq "malicious_fileless" }).Count
$FP = ($detectionResults | Where-Object { $_.Prediction -eq "malicious_fileless" -and $_.ActualLabel -eq "benign" }).Count
$TN = ($detectionResults | Where-Object { $_.Prediction -eq "benign" -and $_.ActualLabel -eq "benign" }).Count
$FN = ($detectionResults | Where-Object { $_.Prediction -eq "benign" -and $_.ActualLabel -eq "malicious_fileless" }).Count

Write-Host "KET QUA"
Write-Host "TP=$TP  FP=$FP  TN=$TN  FN=$FN"

$precision = if (($TP+$FP) -gt 0) { $TP/($TP+$FP) } else { 0 }
$recall = if (($TP+$FN) -gt 0) { $TP/($TP+$FN) } else { 0 }
$f1 = if (($precision+$recall) -gt 0) { 2*$precision*$recall/($precision+$recall) } else { 0 }

Write-Host ("Precision = {0:P2}" -f $precision)
Write-Host ("Recall    = {0:P2}" -f $recall)
Write-Host ("F1-Score  = {0:P2}" -f $f1)