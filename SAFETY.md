# D07 — An toàn, cấu hình lab & threat model

PoC này tái hiện kỹ thuật fileless **chỉ để nghiên cứu phát hiện**. Tài liệu này mô tả
môi trường cô lập, checklist vận hành an toàn, mô hình đe doạ và giới hạn.

## 1. Cấu hình lab (môi trường cô lập)

| Thành phần | Cấu hình dùng trong đồ án |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Guest OS | Windows 11 (máy clone từ 1 base image) |
| Snapshot | Tạo snapshot "clean" **trước** khi test, revert **sau** khi test |
| Mạng | Không nối Internet (khuyến nghị NAT tắt / Host-only / hoặc gỡ card mạng) |
| Telemetry | Sysmon (Operational log) + PowerShell Script Block Logging |

**Sysmon — các Event ID cần bật:**
- `1` Process Create — lấy Image, ParentImage, CommandLine, User, ParentUser, IntegrityLevel.
- `19` WmiEventFilter, `20` WmiEventConsumer, `21` WmiEventConsumerToFilter — bắt việc đăng ký WMI.

> Nhiều config Sysmon phổ biến (ví dụ cấu hình modular dạng SwiftOnSecurity) đã bật sẵn
> nhóm event WMI. Cần kiểm tra mục `WmiEvent` không bị `onmatch` loại bỏ.

**PowerShell Script Block Logging (Event 4104):** bật qua Group Policy
`Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell
Script Block Logging`, hoặc registry
`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`.

**Về việc tắt ASR trong demo:** để Consumer chạy được, nhóm tạm tắt rule Attack Surface
Reduction của Microsoft Defender:
```
Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Disabled
```
Đây là **thao tác chỉ thực hiện bên trong VM lab cô lập** để quan sát kỹ thuật; **không**
thực hiện trên máy thật. Rule liên quan: "Block process creations originating from PSExec
and WMI commands". Nên bật lại (hoặc đơn giản là revert snapshot) sau khi test.

## 2. Checklist an toàn

**Trước khi test**
- [ ] Đang ở trong VM, **không** phải máy host.
- [ ] VM đã ngắt Internet (host-only hoặc gỡ card mạng).
- [ ] Đã tạo snapshot "clean".
- [ ] Đã xác nhận payload trong `trigger_wmi_fileless.ps1` chỉ `Add-Content` 1 dòng log.

**Trong khi test**
- [ ] Chỉ chạy `baseline.ps1`, `trigger_wmi_fileless.ps1`, `extract_dataset.ps1`, `detector.ps1`, `live_monitor.ps1`.
- [ ] Không thêm hành vi mạng, không tải file ngoài, không đổi payload thành hành vi phá hoại.

**Sau khi test**
- [ ] Chạy `Fileless\cleanup_wmi.ps1` và xác nhận không còn `PoC_D07_*`.
- [ ] Kiểm tra lại:
      `Get-WmiObject -Namespace root\subscription -Class __EventFilter | ? {$_.Name -match 'PoC_D07'}`
      (phải trả về rỗng).
- [ ] Bật lại ASR nếu đã tắt, hoặc **revert snapshot** (cách chắc chắn nhất).

> ⚠️ WMI Event Subscription là cơ chế **persistence**: nó **không tự biến mất** sau reboot.
> Bỏ qua bước cleanup sẽ để lại subscription chạy ngầm trong VM. Luôn cleanup + revert.

## 3. Threat model

**Giả định (assumptions)**
- Kẻ tấn công **đã có quyền thực thi lệnh + quyền admin** trên máy nạn nhân (giai đoạn
  sau khai thác). PoC không mô phỏng bước lấy quyền ban đầu.
- Hệ thống phòng thủ **có thu thập log** Sysmon + PowerShell. Nếu không, detector không thấy gì.

**Trong phạm vi (in scope)**
- Đăng ký WMI Event Subscription để thực thi fileless.
- Obfuscation bằng Base64 `-EncodedCommand`, chạy ẩn cửa sổ.
- Phát hiện dựa trên process tree, command-line, ngữ cảnh user, chuỗi sự kiện WMI, nội
  dung script, dấu vết in-memory.

**Ngoài phạm vi (out of scope — không thực hiện)**
- C2, kết nối Internet, tải payload từ xa.
- Credential theft, exfiltration dữ liệu.
- Lan truyền (lateral movement), mã hoá/phá huỷ dữ liệu.
- Né tránh EDR thương mại thật; bypass cơ chế bảo mật của hệ thống production.

## 4. Giới hạn & khả năng khái quát

- **Dataset nhỏ (75 mẫu)** thu trong 1 VM, 1 người dùng → chưa đại diện môi trường thật.
- **Nhãn gán theo luật** gần giống các feature của detector → kết quả cao cần đọc thận trọng,
  không nên công bố như độ chính xác thực địa.
- **Điểm mù còn lại:** công cụ admin hợp pháp dùng `-EncodedCommand` có thể bị báo nhầm
  (lớp 2 + lớp 7 = 50 điểm). Hướng giảm: allowlist theo chữ ký/đường dẫn tiến trình tin cậy.
- **Phụ thuộc log:** vô hiệu nếu attacker tắt/giả mạo Sysmon hoặc PowerShell logging, hoặc
  dùng kỹ thuật không sinh các event này.
- **Khái quát hoá:** luật lớp 1–5 bám khá sát đúng 1 biến thể trigger. Với trigger WMI khác
  hoặc ngôn ngữ script khác, cần thu thêm dữ liệu và chỉnh trọng số.

## 5. Tuyên bố sử dụng hợp lệ

Mã trong repo chỉ để học tập và nghiên cứu phát hiện trong môi trường được phép. Không
dùng trên hệ thống không thuộc quyền kiểm soát của bạn.
