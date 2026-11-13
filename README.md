# D07 — Fileless Malware Detection via PowerShell/WMI

Kho lưu trữ này tập trung vào phát hiện và phân tích fileless execution,
với detector dựa trên Sysmon và PowerShell Script Block Logging.

Để an toàn, repo không chứa script tạo WMI Event Subscription hoặc chạy
payload. Dataset đã được ẩn danh các trường tài khoản người dùng.

## Kết quả
- 76 mẫu thử (53 benign + 23 malicious)
- Precision: 95.8% | Recall: 100% | F1-Score: 97.87%

## Cảnh báo an toàn
Chỉ thu thập log và chạy detector trên hệ thống bạn được phép kiểm thử.
Script mô phỏng tạo WMI subscription và thực thi payload không được đưa vào repo.
