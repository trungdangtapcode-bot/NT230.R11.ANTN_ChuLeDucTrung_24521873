# cleanup_wmi.ps1 - Don dep WMI Subscription sau khi test

Write-Host "Dang don dep WMI Temporary Event Subscription..."

Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match "PoC_D07" } |
    Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "PoC_D07_TempFilter" } |
    Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "PoC_D07_TempConsumer" } |
    Remove-WmiObject

Write-Host "Da don dep xong."

# Kiem tra lai da xoa het chua
Write-Host "`n=== Kiem tra con sot lai gi khong ==="
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -match "PoC_D07" }
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -match "PoC_D07" }