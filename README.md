# artexscan

Quét port 80/443/8787 theo danh sách IP, fingerprint HTTP/TLS và lọc ra các host đang chạy **ARTEX**.
Kết quả chính là file `artex.txt`, mỗi dòng một `IP:port`.

Viết bằng Go, không phụ thuộc thư viện ngoài — chỉ cần `go build` là ra một binary tĩnh.

---

## 1. Tại sao Go chứ không phải Python

Anh đang phân vân giữa hai bên. Với quy mô >50.000 IP × 3 port ≈ **150.000 kết nối TCP**, khác biệt thực tế nằm ở ba chỗ:

| | Go | Python asyncio |
|---|---|---|
| Chi phí mỗi kết nối | goroutine ~4 KB stack | coroutine + đối tượng transport, nặng hơn vài lần |
| Mức đồng thời thoải mái trên 1 VM 4 vCPU | 2.000–10.000 | 500–2.000 trước khi event loop bắt đầu trễ |
| Triển khai | 1 file binary, `scp` là chạy | cần Python 3.8+, venv, pip trên máy quét |
| TLS + HTTP client | `crypto/tls`, `net/http` trong stdlib | stdlib `asyncio` không có HTTP client, phải `pip install` |
| Sửa nhanh tại chỗ | phải build lại | sửa file là chạy |

Thời gian chạy ước tính cho 50.000 IP (tính theo trường hợp xấu — mọi port đều timeout):

- Go, `-c 1000`, timeout 2s → `50000 × 3 × 2 / 1000` ≈ **5 phút**
- Python asyncio, concurrency 500 → ≈ **10 phút**

Cả hai đều chấp nhận được. Nên lý do chọn Go **không phải tốc độ** mà là triển khai: một binary tĩnh chạy được trên jump host không có Python, không đụng tới môi trường sẵn có, và chịu tải tốt hơn khi số file descriptor lên cao.

**Đánh đổi thật thà:** nếu đội của anh quen sửa Python hơn Go, và sẽ thường xuyên chỉnh logic fingerprint, thì Python đáng cân nhắc hơn. Tool này đã tách toàn bộ dấu hiệu ra file JSON riêng (`artex-rules.json`) chính là để đội vận hành sửa dấu hiệu mà không phải đụng vào code — nên lý do "dễ sửa" của Python yếu đi nhiều.

Nếu anh vẫn muốn bản Python, nói em một tiếng, em viết lại tương đương.

**Khi nào nên thêm masscan:** nếu phạm vi vượt ~200.000 IP hoặc cần chạy trong dưới 1 phút, hãy để `masscan` làm pha 1 (SYN scan), rồi đưa danh sách port mở sang tool này làm pha 2. Xem mục 6.

---

## 2. Build

```bash
cd artexscan
go build -o artexscan .
```

Cross-compile cho máy quét Linux từ máy khác:

```bash
GOOS=linux GOARCH=amd64 go build -o artexscan .
```

---

## 3. Bước bắt buộc trước khi quét: lấy dấu hiệu thật

File `artex-rules.json` hiện tại **mới chỉ dựa trên chữ "ARTEX"** — em chưa truy cập được trang mẫu của anh (xem mục 8). Chạy chế độ profile để lấy dấu hiệu thật:

```bash
./artexscan -profile http://47.120.40.162:8787/login
```

Nó in ra:

- `<title>`, toàn bộ response header, cookie, Server, X-Powered-By
- **favicon mmh3 hash** (cùng chuẩn với `http.favicon.hash` của Shodan) và sha256
- CN/SAN của TLS cert nếu có
- Các chuỗi đáng chú ý trong body: tên file JS/CSS có hash build, dấu hiệu framework
- Một khối JSON `rules` gợi ý, dán thẳng được vào `artex-rules.json`

Sau đó mở `artex-rules.json` và:

1. Thay phần `rules` bằng khối gợi ý.
2. **Xóa những rule quá chung chung.** Ví dụ `Server: nginx` sẽ khớp với hàng nghìn host không phải ARTEX. Giữ lại những thứ chỉ ARTEX mới có: favicon hash, tên file JS có hash build, chuỗi tên sản phẩm, tên cookie riêng.
3. Cân lại `score` và `min_score`.

> Nếu có thể, profile thêm 1–2 instance ARTEX thật trong hệ thống nội bộ rồi lấy phần **giao nhau** giữa các bộ dấu hiệu. Làm vậy mới chắc rule không bám vào thứ chỉ đúng với riêng máy demo (hostname, cert, cấu hình proxy).

---

## 4. Quét

```bash
./artexscan \
  -targets ips.txt \
  -rules artex-rules.json \
  -ports 80,443,8787 \
  -c 800 \
  -out ket-qua
```

File `ips.txt` nhận lẫn lộn các dạng:

```
# một IP
10.20.30.40
# cả dải
10.20.0.0/16
# khoảng
10.21.5.1-10.21.5.250
# CSV — chỉ lấy cột đầu
10.22.1.7,web-fe-01,Khối Hạ tầng
```

### Kết quả trong `ket-qua/`

| File | Nội dung |
|---|---|
| **`artex.txt`** | **Deliverable chính** — `IP:port`, mỗi dòng một host xác định là ARTEX, đã sắp xếp và loại trùng |
| `results.csv` | Toàn bộ bằng chứng mọi host có HTTP — mở Excel, lọc cột `verdict` |
| `results.jsonl` | Mỗi host một dòng JSON, đẩy thẳng vào SIEM/SOAR |
| `.scanned` | Danh sách IP đã quét xong, phục vụ `-resume` |

`artex.txt` được ghi và `fsync` ngay mỗi khi tìm thấy một host — mất điện giữa chừng vẫn còn kết quả.

---

## 5. Tham số

| Cờ | Mặc định | Ghi chú |
|---|---|---|
| `-targets` | — | File danh sách IP (bắt buộc) |
| `-rules` | `artex-rules.json` | File dấu hiệu |
| `-ports` | `80,443,8787` | |
| `-out` | `ket-qua` | Thư mục kết quả |
| `-c` | `500` | Số IP quét đồng thời. Xem mục 6 |
| `-rate` | `0` | Giới hạn kết nối/giây. 0 = không giới hạn |
| `-dial-timeout` | `2s` | Timeout bắt tay TCP |
| `-http-timeout` | `5s` | Timeout một request HTTP |
| `-ua` | `VinSOC-AssetDiscovery/1.0` | User-Agent |
| `-resume` | `false` | Bỏ qua IP đã quét ở lần chạy trước |
| `-no-shuffle` | `false` | Mặc định xáo trộn thứ tự IP để trải đều tải |
| `-allow-large` | `false` | Cho phép CIDR lớn hơn `/16` |
| `-v` | `false` | In host khớp ngay khi tìm thấy |
| `-profile URL` | — | Chế độ lấy dấu hiệu |

---

## 6. Chạy ở quy mô trên 50.000 IP

**Nâng giới hạn file descriptor trước khi chạy** — đây là lỗi hay gặp nhất:

```bash
ulimit -n 65535
```

Nếu không, scan sẽ báo `too many open files` và mọi host sau đó bị đánh nhầm là đóng port — tức là **false negative hàng loạt mà không có cảnh báo rõ ràng**.

**Chọn `-c`:**

| Môi trường | `-c` gợi ý |
|---|---|
| Qua VPN / WAN liên chi nhánh | 200–400 |
| LAN nội bộ, VM 2–4 vCPU | 500–1.000 |
| LAN nội bộ, VM 8+ vCPU, đã nâng ulimit | 1.500–2.500 |

**Chạy từng mảng mạng thay vì một phát 50.000 IP.** Chia theo site/VLAN, mỗi lần một file targets. Dễ theo dõi, dễ chạy lại phần lỗi, và nếu có sự cố mạng thì khoanh vùng được ngay.

**Nếu cần nhanh hơn nữa**, ghép với masscan:

```bash
# Pha 1 - tìm port mở
masscan -iL ips.txt -p80,443,8787 --rate 5000 -oG open.gnmap

# Lấy IP có port mở
awk '/Ports:/{print $2}' open.gnmap | sort -u > open-ips.txt

# Pha 2 - fingerprint
./artexscan -targets open-ips.txt -rules artex-rules.json -c 500
```

---

## 7. Lưu ý vận hành

- **Báo trước cho trực ca.** 150.000 kết nối từ một nguồn sẽ bắn alert trên IDS/NDR và có thể bị WAF chặn IP. Mặc định User-Agent là `VinSOC-AssetDiscovery/1.0` để anh em trực nhận ra ngay đây là scan nội bộ chứ không phải tấn công — nếu có quy ước UA riêng thì đổi bằng `-ua`.
- **Tool chỉ bắt tay TCP và gửi `GET`.** Không gửi payload, không thử credential, không khai thác. Nhưng vẫn là quét chủ động — vẫn cần nằm trong phạm vi được phê duyệt.
- **TLS không verify cert** (`InsecureSkipVerify`) — cố ý, để đọc được cert tự ký mà fingerprint. Chấp nhận được vì đây là discovery, không truyền dữ liệu nhạy cảm, nhưng cần biết là kênh không chống được MITM.
- **Không tự động đi theo redirect.** `Location` được ghi lại để đối chiếu. Nếu ARTEX luôn redirect `/` → `/login` thì rule nên đặt trên path `/login`, hoặc match `location`.
- **Mặc định xáo trộn thứ tự IP** để không nện liên tiếp vào cùng một /24.

---

## 8. Giới hạn cần biết trước khi tin kết quả

Ba điều em phải nói thẳng:

1. **Code chưa được biên dịch thử.** Shell trong phiên làm việc này bị chặn nên em không chạy được `go build`. Anh build lần đầu, nếu có lỗi cú pháp thì gửi em output, em sửa ngay.

2. **Em chưa xem được trang `http://47.129.49.162:8787/login`.** `WebFetch` trả về `ROBOTS_DISALLOWED` và trình duyệt cũng bị chặn trong phiên này. Vì vậy bộ rule hiện tại **chưa phải dấu hiệu thật của ARTEX** — nó chỉ dựa trên chữ "ARTEX". Bắt buộc chạy `-profile` trước (mục 3). Em không đoán hash favicon hay tên cookie, vì đoán sai thì tool chạy sạch mà không ra kết quả nào, còn tệ hơn là báo lỗi.

3. **Luôn kiểm chứng mẫu trước khi dùng kết quả.** Sau lần quét đầu, mở `results.csv`, lọc `verdict=suspect`, và kiểm tay 5–10 host. Nếu có host ARTEX thật bị xếp vào `suspect` thì hạ `min_score`; nếu có host lạ lọt vào `artex` thì rule đang quá rộng.

---

## 9. Cách tính điểm

Mỗi rule khớp cộng `score`. Tổng điểm quyết định `verdict`:

- `>= min_score` → **`artex`** → vào `artex.txt`
- `>= suspect_from` → **`suspect`** → chỉ vào CSV, cần người xem
- còn lại → `other`

Thiết kế cộng điểm thay vì match đơn lẻ là có chủ ý: một dấu hiệu lẻ (chữ "artex" trong body) có thể trùng ngẫu nhiên, nhưng favicon hash + tên file JS + title khớp cùng lúc thì gần như chắc chắn. Một host muốn trốn phải giấu được cả ba.
