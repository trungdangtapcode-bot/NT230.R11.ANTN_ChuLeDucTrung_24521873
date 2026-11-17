# D07 — Đánh giá detector (mục C, D)

Tái lập: `python3 Detector/verify_metrics.py Dataset/dataset.csv --by Scenario --split 0.5`
(hoặc `Detector\detector.ps1` trong Windows). Ngưỡng cảnh báo 50 điểm, **chưa tinh chỉnh theo dữ liệu**.

## 1. Dữ liệu

785 tiến trình PowerShell thu thật trong VM cô lập, nhãn gán **theo nguồn gốc** (không dùng luật của detector).

| Nhóm | Số mẫu | Nguồn gốc |
|---|---|---|
| `malicious_fileless` | 102 | Payload PoC ghi `marker_fileless` (83 mẫu cha `-`, 19 mẫu cha `WmiPrvSE.exe`) |
| `benign` workload | 676 | 12 kịch bản do `benign_workload.ps1` sinh ra |
| `benign` background | 7 | PowerShell của hệ thống / người dùng |

Các kịch bản benign "khó" (giống công cụ quản trị): `enc_admin` 21, `enc_hidden_agent` 9, `iex_write_admin` 9.
Tỷ lệ này do nhóm đặt (khoảng 6% số lệnh benign) nên FPR dưới đây **không phải FPR ngoài đời thật**.

## 2. Kết quả

| Cấu hình | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| **Đủ 7 lớp (ngưỡng 50)** | 102 | 39 | 644 | 0 | 72,34% | 100% | 83,95% | 5,71% |
| Bỏ lớp 4 | 102 | 39 | 644 | 0 | 72,34% | 100% | 83,95% | 5,71% |
| Bỏ lớp 7 | 102 | 18 | 665 | 0 | 85,00% | 100% | 91,89% | 2,64% |
| DEV (50% đầu) | 32 | 16 | 344 | 0 | 66,67% | 100% | 80,00% | 4,44% |
| TEST (50% sau) | 70 | 23 | 300 | 0 | 75,27% | 100% | 85,89% | 7,12% |

Báo nhầm theo kịch bản (ngưỡng 50): `enc_admin` 21/21, `enc_hidden_agent` 9/9, `iex_write_admin` 9/9;
mọi kịch bản benign còn lại (`query_*`, `list_files`, `write_report`, `file_script`, `iex_read`, `schtask_system`...) đều **0** báo nhầm.

## 3. Các lỗi tìm thấy khi đo trên dữ liệu thật (đã sửa)

Bản đầu (7 lớp, v6) cho TP=102 FP=92 Precision 52,58% FPR 13,47%. Nguyên nhân và cách sửa:

1. **Lớp 4 cộng điểm cho mọi tiến trình.** `WmiSubCount ≥ 2` đúng với 680/683 mẫu benign vì lớp này chỉ xét
   "có đăng ký WMI trong 60 phút trước", không gắn với tiến trình. Sửa: chỉ tính khi cha là `WmiPrvSE.exe`
   hoặc không xác định (`-`). FP giảm 92 → 50, Recall vẫn 100%.
2. **Ghép nhầm nội dung script (Event 4104) giữa các tiến trình.** Ghép theo thời gian ±2 giây trong khi workload
   chạy cách nhau 4 giây nên `HasIEX`/`HasWriteAction` bị lẫn từ tiến trình bên cạnh. Sửa: ghép theo `ProcessId`
   cùng cửa sổ thời gian. FP giảm 50 → 39.
3. **Nhãn tên sai.** Kịch bản `poc_manual` thực ra là mẫu do WMI sinh ra nhưng Sysmon ghi cha là `-`.
   Đổi tên thành `poc_wmi_noparent`.

Số liệu mục 2 là sau cả ba bản sửa, trên cùng bộ log thu (trích lại bằng script mới).

## 4. Phát hiện về tín hiệu

- **Lớp 1 (cây tiến trình) chỉ thấy ở 19/102 mẫu PoC.** 83/102 mẫu có `ParentImage = "-"` vì `WmiPrvSE.exe` đã thoát
  trước khi Sysmon ghi nhận cha. Recall 100% là nhờ lớp 2 (mã hoá) + lớp 5 (ẩn + mã hoá) + lớp 7 (chạy trong RAM)
  (75–90 điểm), không phải nhờ cây tiến trình.
- **Lớp 4 không đổi kết quả** trên dataset này (bỏ lớp 4 vẫn ra đúng số trên). Giữ lại vì rẻ và không gây hại sau khi sửa,
  nhưng không có bằng chứng đo được là nó cải thiện detector.
- **Đánh đổi giữa lớp 7 và báo nhầm.** Lệnh mã hoá, không ẩn cửa sổ, cha `powershell.exe` chỉ được lớp 2 + lớp 7 = 50 điểm.
  Biến thể V3 (mẫu tấn công, tập 75 mẫu thu sớm) và kịch bản `enc_admin` (benign) có **cùng đặc trưng**, nên không tách được bằng
  dòng lệnh. Bật lớp 7 thì bắt V3 (3/3, tập 75 mẫu) nhưng báo nhầm 21 mẫu `enc_admin`; tắt lớp 7 thì ngược lại (FP 39 → 18,
  V3 bị bỏ sót).
- **`enc_hidden_agent` giống hệt payload PoC về dòng lệnh** (ẩn + mã hoá, 75 điểm). Chỉ khác ở nguồn gốc (cha `powershell.exe`
  thấy rõ, không do WMI). Nâng ngưỡng lên 55–75 vẫn không loại được nhóm này; tới 80 thì Recall rơi xuống 78,43%.

Quét ngưỡng (7 lớp):

| Ngưỡng | FP | Precision | Recall | FPR |
|---|---|---|---|---|
| 30 | 86 | 54,26% | 100% | 12,59% |
| 40–50 | 39 | 72,34% | 100% | 5,71% |
| 55–75 | 18 | 85,00% | 100% | 2,64% |
| 80 | 0 | 100% | 78,43% | 0% |

Ngưỡng 55–75 loại được `enc_admin` (50 điểm) nhưng làm V3 bị bỏ sót. Nhóm giữ ngưỡng 50 để ưu tiên Recall.

## 5. Hạn chế (cần nêu khi báo cáo)

- **Một payload duy nhất.** 102 mẫu malicious có đúng **1 dòng lệnh** (cùng một payload mã hoá). Recall 100% là trên một kỹ thuật,
  không đại diện cho các biến thể khác.
- **Kịch bản benign do nhóm tự sinh.** Chúng không đại diện hoạt động thật của người dùng/doanh nghiệp; FPR phụ thuộc trực tiếp
  vào tỷ lệ ca khó nhóm chọn.
- **DEV/TEST không phải tập kiểm tra độc lập.** Hai bản sửa (mục 3) được tìm ra khi xem toàn bộ dữ liệu. Chúng là lỗi cấu trúc
  (lớp 4 không gắn với tiến trình, ghép 4104 sai), không phải chỉnh ngưỡng, nhưng số TEST vẫn nên đọc như tham khảo.
- **`ParentImage = "-"` làm lớp 4 nới lỏng.** Ngoài đời, nhiều tiến trình có cha `-` (cha thoát sớm), nên lớp 4 có thể
  bị kích hoạt oan hơn trong dataset này (benign ở đây luôn thấy cha).
- **Phụ thuộc log:** vô hiệu nếu Sysmon / Script Block Logging bị tắt.
- **Tập 75 mẫu thu sớm** (`dataset_75_rule_labeled.csv`) gán nhãn bằng luật gần giống detector nên kết quả 100% trên tập đó
  không có giá trị đánh giá; chỉ dùng để mô tả biến thể (xem `VARIANTS.md`).

## 6. Hướng cải tiến

- Dùng trường `Destination` của Sysmon Event 20 (WMI Consumer) để khớp **đúng dòng lệnh** của tiến trình với Consumer đã đăng ký,
  thay cho cửa sổ thời gian ở lớp 4. Cách này giải quyết trường hợp cha `-` và tách `enc_hidden_agent` khỏi PoC.
- Allowlist theo tiến trình cha / đường dẫn đã ký của công cụ quản trị thật (không dựa vào kịch bản benign tự sinh, để tránh tự chấm).
- Thu thêm biến thể tấn công và dữ liệu benign từ môi trường thật.
