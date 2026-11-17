# D07 — Thiết kế: luồng thực thi & pipeline phát hiện

Tài liệu này mô tả (A) cơ chế của PoC fileless và đối chứng file-based, (B) luồng
của detector, và (C) giới hạn/điều kiện cần của PoC.

## 1. So sánh luồng thực thi: file-based vs fileless

```mermaid
flowchart TD
    subgraph FB["Đối chứng: FILE-BASED (baseline.ps1)"]
        A1["Người dùng/Admin chạy lệnh"] --> A2["powershell.exe -File baseline.ps1"]
        A2 --> A3["Đọc file .ps1 TRÊN ĐĨA"]
        A3 --> A4["Ghi marker_filebased.txt"]
        A2 -. "ParentImage = powershell.exe / explorer.exe" .-> A5(("Sysmon Event 1"))
    end

    subgraph FL["PoC: FILELESS (trigger_wmi_fileless.ps1)"]
        B1["Đã có quyền chạy lệnh (Initial Foothold)"] --> B2["Set-WmiInstance: tạo 3 đối tượng WMI trong root\\subscription"]
        B2 --> B3["__EventFilter: WITHIN 10, Win32_LocalTime.Second = 30"]
        B2 --> B4["CommandLineEventConsumer: powershell -EncodedCommand (payload base64)"]
        B2 --> B5["__FilterToConsumerBinding: nối Filter + Consumer"]
        B3 & B4 & B5 --> B6{"Điều kiện khớp?"}
        B6 -- "mỗi 10s, khi giây = 30" --> B7["WmiPrvSE.exe tự sinh tiến trình"]
        B7 --> B8["powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ..."]
        B8 --> B9["Giải mã base64 & chạy TRONG RAM — không có .ps1 trên đĩa"]
        B9 --> B10["Ghi marker_fileless.txt (payload vô hại)"]
        B7 -. "ParentImage = WmiPrvSE.exe" .-> B11(("Sysmon Event 1"))
        B2 -. "đăng ký Filter/Consumer/Binding" .-> B12(("Sysmon Event 19/20/21"))
        B8 -. "nội dung sau giải mã" .-> B13(("PowerShell Event 4104"))
    end
```

**Điểm khác biệt cốt lõi mà detector khai thác:** ở nhánh fileless, tiến trình
`powershell.exe` có **cha là `WmiPrvSE.exe`** (không phải `explorer.exe`/`powershell.exe`),
payload **không có file `.ps1` tương ứng trên đĩa**, và trước đó có **dấu vết đăng ký WMI
(event 19/20/21)**.

## 2. Ánh xạ MITRE ATT&CK

```mermaid
flowchart LR
    T1["Initial Foothold<br/>(đã có quyền exec)"] --> T2["Execution<br/>T1059.001 PowerShell<br/>T1047 WMI"]
    T2 --> T3["Defense Evasion<br/>T1027 Obfuscation (Base64)"]
    T3 --> T4["Persistence<br/>T1546.003 WMI Event Subscription"]
    T4 --> T5["Actions on Objective<br/>Ghi log — mô phỏng, vô hại"]
```

> Lưu ý thuật ngữ: subscription tạo trong `root\subscription` là **permanent** (tồn tại
> qua reboot tới khi bị xoá), dù tên biến trong script gọi là "Temporary". Vì vậy ánh xạ
> Persistence chính xác là **T1546.003**.

## 3. Pipeline phát hiện (detector 7 lớp)

```mermaid
flowchart TD
    subgraph SRC["Nguồn log (trong VM)"]
        S1["Sysmon Event 1<br/>(Process Create)"]
        S2["Sysmon Event 19/20/21<br/>(WMI Filter/Consumer/Binding)"]
        S3["PowerShell Event 4104<br/>(Script Block)"]
    end

    S1 & S2 & S3 --> EX["extract_dataset.ps1<br/>trích + giải mã base64 + gán nhãn"]
    EX --> DS["dataset.csv<br/>13 cột feature"]

    DS --> DET["detector.ps1 — chấm điểm 7 lớp"]
    DET --> L1["L1 ParentImage=WmiPrvSE +40"]
    DET --> L2["L2 EncodedCommand +30"]
    DET --> L3["L3 SYSTEM context +15"]
    DET --> L4["L4 WMI 19/20/21 sequence +15"]
    DET --> L5["L5 Hidden+Encoded +25"]
    DET --> L6["L6 ScriptBlock (IEX/ghi/mạng) ≤60"]
    DET --> L7["L7 In-memory, no .ps1 on disk +20"]
    L1 & L2 & L3 & L4 & L5 & L6 & L7 --> SUM{"Tổng điểm ≥ 50?"}
    SUM -- "Có" --> M["malicious_fileless"]
    SUM -- "Không" --> B["benign"]
    M & B --> OUT["detection_results.csv + Precision/Recall/F1/FPR"]

    S1 -. "real-time" .-> LIVE["live_monitor.ps1<br/>(L1-L5, L7)"]
```

Detector **độc lập với PoC**: nó chỉ đọc log, không gọi script tấn công. Các lớp dùng
nhiều nguồn khác nhau (process tree, command-line, ngữ cảnh user, chuỗi sự kiện WMI, nội
dung script, dấu vết memory) nên một kỹ thuật né một lớp vẫn còn các lớp khác bắt.

## 4. Giới hạn & điều kiện cần của PoC

**Điều kiện để PoC chạy được:**
- Cần quyền **Administrator**: ghi vào namespace `root\subscription` yêu cầu quyền cao.
  Không có admin thì không tạo được subscription.
- Cần WMI service (`Winmgmt`) hoạt động bình thường (mặc định luôn bật trên Windows).
- Trong lab, nhóm tắt rule ASR của Defender để PoC chạy; nếu bật đầy đủ EDR/ASR, Consumer
  có thể bị chặn (xem SAFETY.md).

**PoC KHÔNG bao phủ (giới hạn phạm vi — có chủ đích):**
- Không có bước lấy quyền ban đầu: giả định "đã có foothold" như slide 8.
- Không C2, không tải payload từ xa, không exfiltration, không credential theft.
- Payload chỉ ghi 1 dòng log; không mô phỏng hành vi phá hoại thật.
- Chỉ 1 cơ chế trigger (Win32_LocalTime). Các trigger WMI khác (logon, process start,
  __TimerInstruction…) không nằm trong phạm vi bản này.

**Giới hạn của detector:**
- Phụ thuộc hoàn toàn vào log: nếu kẻ tấn công tắt Sysmon/PowerShell logging thì mất tác dụng.
- Chấm điểm theo luật tĩnh (rule-based), chưa có học máy; ngưỡng 50 đặt thủ công.
- `WmiSubCount` trong dataset đi kèm được gán theo quy tắc (xem README) — cần thu lại
  event 19/20/21 thật để đo chính xác lớp 4.
