# baseline_script.ps1
# Mục đích: Marker vô hại - ghi log xác nhận thực thi thành công
# Mô phỏng hành vi "benign admin script" chạy trực tiếp từ file trên đĩa

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logPath = "C:\PoC_D07\Logs\marker_filebased.txt"

$logEntry = "[$timestamp] Baseline file-based execution - PID: $PID - User: $env:USERNAME"
Add-Content -Path $logPath -Value $logEntry

Write-Host "Baseline script executed successfully at $timestamp"