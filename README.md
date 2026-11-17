# D07 — Fileless Malware Detection via PowerShell/WMI

Đồ án môn học: tái hiện **vô hại** kỹ thuật fileless execution qua WMI Event
Subscription, so sánh với thực thi file-based, và xây dựng detector 7 lớp dựa trên
Sysmon + PowerShell Script Block Logging.

## Cấu trúc repo

| Thư mục | Nội dung |
|---|---|
| `Baseline/baseline.ps1` | Đối chứng file-based: chạy `-File *.ps1`, ghi 1 dòng marker |
| `Fileless/trigger_wmi_fileless.ps1` | **Không có trong repo công khai** (đã `.gitignore`). Script PoC đăng ký Filter/Consumer/Binding với payload chỉ ghi 1 dòng log; chỉ nộp kèm bài cho giảng viên |
| `Fileless/cleanup_wmi.ps1` | Gỡ toàn bộ subscription `PoC_D07_*` và kiểm tra lại |
| `Dataset/extract_dataset.ps1` | Thu Sysmon 1/19/20/21 + PowerShell 4104, xuất `dataset.csv` |
| `Dataset/dataset.csv` | Dataset 785 mẫu dùng để chấm (xem mục Dataset) |
| `Detector/detector.ps1` | Detector 7 lớp chạy trên dataset, xuất metric |
| `Detector/live_monitor.ps1` | Giám sát real-time Sysmon |
| `Detector/verify_metrics.py` | Bản Python cùng logic, để đối chiếu trên máy không có PowerShell |
| `EVALUATION.md` | Kết quả đo, phân tích báo nhầm, đánh đổi và hạn chế (mục C/D) |
| `DESIGN.md` | Sơ đồ luồng thực thi, pipeline phát hiện, giới hạn PoC (mục A) |
| `SAFETY.md` | Cấu hình VM, checklist an toàn, threat model (mục D) |
| `VARIANTS.md` | Phân tích biến thể + trade-off né tránh/phát hiện (mục B) |
| `Detector/analyze_variants.py` | Script tái lập bảng biến thể (5 lớp vs 7 lớp) |

## Detector — 7 lớp

Ngưỡng cảnh báo: **tổng điểm ≥ 50**.

| Lớp | Nguồn | Điều kiện | Điểm |
|---|---|---|---|
| 1. Cây tiến trình | Sysmon 1 | `ParentImage` là `WmiPrvSE.exe` (chỉ thấy ở khoảng 19% mẫu PoC, xem EVALUATION.md) | 40 |
| 2. Lệnh mã hoá | Sysmon 1 | `CommandLine` chứa `-EncodedCommand` / `-enc` | 30 |
| 3. Ngữ cảnh SYSTEM | Sysmon 1 | `ParentUser` = SYSTEM, không phải svchost/TrustedInstaller | 15 |
| 4. Chuỗi sự kiện WMI | Sysmon 19/20/21 | ≥ 2/3 loại event Filter/Consumer/Binding trong 60 phút trước tiến trình, **và** cha là `WmiPrvSE.exe` hoặc không xác định (`-`) | 15 |
| 5. Ẩn + mã hoá | Sysmon 1 | `-WindowStyle Hidden` **và** `-EncodedCommand` | 25 |
| 6. Nội dung script | PowerShell 4104 | Có network → 60; IEX + ghi file → 55; chỉ IEX → 15 | ≤ 60 |
| 7. Memory artifact | Sysmon 1 + 4104 | Code chạy trong RAM (encoded / IEX) **không có** file `.ps1` tương ứng trên đĩa | 20 |

`live_monitor.ps1` dùng các lớp 1–5 và 7 (lớp 6 cần 4104 nên chỉ dùng trong `detector.ps1`).

## Dataset

| File | Nội dung |
|---|---|
| `Dataset/dataset.csv` | **785 mẫu thật** thu trong VM: 102 `malicious_fileless` + 683 `benign`. Nhãn gán **theo nguồn gốc** |
| `Dataset/dataset_75_rule_labeled.csv` | 75 mẫu thu sớm, nhãn gán bằng luật gần giống detector (chỉ dùng cho phân tích biến thể V1–V4) |

Schema: `TimeCreated, Image, ParentImage, CommandLine, User, ParentUser, IntegrityLevel,
HasIEX, HasWriteAction, HasNetworkIndicator, WmiSubCount, ScriptOnDisk, Source, Scenario, Label`
(tên tài khoản đã ẩn danh; `Source`, `Scenario`, `Label` chỉ dùng để chấm, detector không đọc).

Nhãn theo nguồn gốc (`extract_dataset.ps1`):

| Nhãn | Source | Cách nhận biết |
|---|---|---|
| `malicious_fileless` | `poc` | Lệnh (sau giải mã base64) có `marker_fileless`, chỉ payload PoC ghi vào file này |
| `benign` | `workload` | Lệnh có thẻ `D07-BENIGN:<kịch bản>` do `benign_workload.ps1` sinh ra |
| `benign` | `background` | PowerShell khác của hệ thống / người dùng |

`benign_workload.ps1` sinh 12 kịch bản bình thường, gồm cả **ca khó** mô phỏng công cụ quản trị
(`enc_admin`, `enc_hidden_agent`, `iex_write_admin`...). Tỷ lệ ca khó do nhóm đặt (trọng số `W`
trong script, khoảng 6% số lệnh benign) nên **FPR không phải tỷ lệ báo nhầm ngoài đời thật**.

## Kết quả (tái lập được)

```powershell
cd Detector
.\detector.ps1                       # đủ 7 lớp
.\detector.ps1 -DisableLayers 7      # ablation
```
hoặc `python3 verify_metrics.py ../Dataset/dataset.csv [--disable 4,7] [--by Scenario] [--split 0.5]`

Ngưỡng 50, chưa tinh chỉnh. Dataset 785 mẫu:

| Cấu hình | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| **Đủ 7 lớp** | 102 | 39 | 644 | 0 | 72,34% | 100% | 83,95% | 5,71% |
| Bỏ lớp 4 | 102 | 39 | 644 | 0 | 72,34% | 100% | 83,95% | 5,71% |
| Bỏ lớp 7 | 102 | 18 | 665 | 0 | 85,00% | 100% | 91,89% | 2,64% |
| Phần TEST (50% sau theo thời gian) | 70 | 23 | 300 | 0 | 75,27% | 100% | 85,89% | 7,12% |

Phân tích chi tiết, nguyên nhân báo nhầm, các lỗi đã sửa và hạn chế: xem **[EVALUATION.md](EVALUATION.md)**.

## An toàn (bắt buộc)

> Chi tiết đầy đủ ở **[SAFETY.md](SAFETY.md)** (cấu hình VM, checklist, threat model) và
> **[DESIGN.md](DESIGN.md)** (sơ đồ luồng, giới hạn PoC).


- Chỉ chạy trong **VM Windows cô lập, có snapshot**. Không kết nối Internet, không có C2.
- Payload không phá hoại: chỉ ghi 1 dòng log. Không thu thập credential, không exfiltration.
- Subscription tạo bằng `Set-WmiInstance` trong `root\subscription` **tồn tại tới khi bị xoá**,
  kể cả qua reboot. Luôn chạy `Fileless/cleanup_wmi.ps1` sau khi test, rồi revert snapshot.
- Trong demo, nhóm tắt rule ASR của Microsoft Defender
  (`Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions Disabled`)
  để PoC chạy được. Đây là **bước chuẩn bị lab chỉ trong VM**, không áp dụng trên máy thật.

## Tái hiện

Chỉ để chấm lại kết quả (không cần VM): chạy `detector.ps1` / `verify_metrics.py` / `analyze_variants.py` trên `Dataset/`.

Thu lại dataset trong VM (đã snapshot, ngắt mạng, Sysmon bật Event 1/19/20/21, bật Script Block Logging 4104):
1. Xoá log cũ: `wevtutil cl "Microsoft-Windows-Sysmon/Operational"` và `... "Microsoft-Windows-PowerShell/Operational"`.
2. Cửa sổ 1: `Fileless\trigger_wmi_fileless.ps1` (script nộp riêng, không có trên GitHub).
3. Cửa sổ 2: `Dataset\benign_workload.ps1 -Count 600 -DelayMs 4000` (khoảng 40 phút; không đặt `-DelayMs` dưới 3000).
   Đừng click vào cửa sổ đang chạy (chế độ Select làm script tạm dừng).
4. Xong: `Fileless\cleanup_wmi.ps1` (**bắt buộc**, subscription tồn tại qua reboot), kiểm tra không còn `PoC_D07_*`.
5. `Dataset\extract_dataset.ps1 -LookbackHours <số giờ đã chạy>`, rồi `Detector\detector.ps1`.
6. (tuỳ chọn) `Detector\live_monitor.ps1` chạy song song với bước 2 để xem cảnh báo real-time.
7. Revert snapshot.

MITRE ATT&CK: T1059.001 (PowerShell), T1047 (WMI), T1546.003 (WMI Event Subscription), T1027 (Obfuscation).
