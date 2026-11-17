# D07 — Phân tích biến thể có kiểm soát (mục B)

Tài liệu này so sánh các **biến thể thực thi đã có trong dataset** và đo xem detector 7 lớp
bắt được mỗi loại ra sao. Mục tiêu là đánh giá độ phủ của detector và trade-off giữa mức độ
"ẩn mình" của kỹ thuật và khả năng bị phát hiện — **không nhằm tạo kỹ thuật né tránh mới**.

Tái lập: `cd Detector && python3 analyze_variants.py`

## 1. Bảng biến thể (so với V1 làm mốc)

Tất cả biến thể đều thực thi cùng một payload vô hại (ghi 1 dòng log). Chúng khác nhau ở
**cách** khởi chạy, nên để lại dấu vết khác nhau.

| Mã | Thay đổi so với V1 | n | Lớp detector kích hoạt | Điểm | Phát hiện |
|---|---|---|---|---|---|
| **V1** Fileless qua WMI | (mốc) chạy qua WmiPrvSE, encoded, ẩn cửa sổ, quyền SYSTEM | 18 | L1+L2+L3+L4+L5+L7 | 145 | 18/18 |
| **V2** Encoded + Hidden | bỏ WMI, chạy encoded trực tiếp từ powershell.exe | 1 | L2+L5+L7 | 75 | 1/1 |
| **V3** Encoded, không ẩn cửa sổ | như V2 nhưng bỏ `-WindowStyle Hidden` | 3 | L2+L7 | 50 | 3/3 |
| **V4** IEX inline | bỏ mã hoá hẳn, dùng `-Command "Invoke-Expression ..."` | 4 | L6+L7 | 75 | 4/4 |
| **B1** benign IEX chỉ đọc | IEX nhưng không ghi file/mạng | 1 | L6(+15)+L7 | 35 | 0/1 ✓ đúng |
| **B2** benign `-File .ps1` | script hợp lệ trên đĩa | 20 | — | 0 | 0/20 ✓ đúng |
| **B3** benign console/-Command | PowerShell tương tác thông thường | 28 | — | 0 | 0/28 ✓ đúng |

## 2. Trade-off: càng "né" thì lớp nào vẫn lộ ra

Đọc bảng theo chiều giảm dần dấu vết (V1 → V3) cho thấy **cơ chế phòng thủ nhiều lớp**:
mỗi lần kẻ tấn công bỏ một chỉ dấu để ẩn hơn, điểm giảm nhưng một lớp khác vẫn giữ lại
tín hiệu.

```
V1  145đ ─ bỏ parent WmiPrvSE (mất L1+L3+L4 = 70đ) ─▶ V2  75đ
V2   75đ ─ bỏ ẩn cửa sổ        (mất L5 = 25đ)        ─▶ V3  50đ  ← sát ngưỡng
V3   50đ: chỉ còn L2 (encoded, 30đ) + L7 (memory, 20đ)
V4   75đ: bỏ mã hoá hẳn → L2 tắt, nhưng nội dung thật (IEX+ghi file) lộ ở L6 = 55đ
```

- **Không có "điểm mù chồng điểm mù".** Bỏ dấu vết process (V2, V3) thì **mã hoá** và
  **dấu vết memory** vẫn lộ. Bỏ mã hoá (V4) thì **nội dung script** lộ ở Event 4104.
- **Muốn thật sự im lặng thì phải bỏ luôn tính fileless/độc hại** — tức là trở về B1/B2/B3,
  vốn được 0–35 điểm và detector đúng khi không báo.
- **Quan sát ↔ phát hiện:** V1 "ồn ào nhất" (6 lớp), dễ thấy trong log. Càng ẩn thì càng ít
  tín hiệu process, nhưng kênh còn lại (encoding / nội dung / memory) lại gánh việc phát hiện.

## 3. Vai trò của 2 lớp mới (trước/sau khi nâng cấp detector)

So sánh detector cũ (5 lớp, bỏ L4 + L7) với bản mới (7 lớp) trên từng biến thể:

| Biến thể | Điểm 5 lớp | Phát hiện (cũ) | Điểm 7 lớp | Phát hiện (mới) |
|---|---|---|---|---|
| V1 | 110 | ✅ | 145 | ✅ |
| V2 | 55 | ✅ | 75 | ✅ |
| **V3** | **30** | ❌ **bỏ sót** | **50** | ✅ **bắt được** |
| V4 | 55 | ✅ | 75 | ✅ |

**Kết luận:** Lớp 7 (memory artifact) là yếu tố quyết định kéo **V3 từ bỏ sót thành phát
hiện** — đây chính là 3 mẫu làm Recall tăng từ 88,46% lên 100%. V3 là biến thể "ẩn" nhất
còn giữ tính fileless, nên việc bắt được nó cho thấy giá trị của việc thêm tín hiệu memory.
Lớp 4 không thêm mẫu nào trên dataset này (các mẫu WMI đã vượt ngưỡng nhờ lớp khác) nhưng
là lưới dự phòng nếu kẻ tấn công đổi cách sinh tiến trình con.

## 4. Hạn chế của phân tích

- Các biến thể lấy từ dataset sẵn có, số mẫu mỗi nhóm chênh lệch (V2 chỉ 1 mẫu).
- Phần benign chưa có ca khó nhất với detector: **công cụ admin hợp lệ dùng `-EncodedCommand`**
  sẽ rơi vào kiểu giống V3 (L2+L7 = 50) và bị báo nhầm. Đây là false positive tiềm năng cần
  xử lý bằng allowlist (hướng phát triển ở mục C).
