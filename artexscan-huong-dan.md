---
VinSOC · MIR
---

# artexscan

Quét port 80/443/8787 theo danh sách IP, fingerprint HTTP/TLS và lọc ra các host đang chạy ARTEX. Kết quả chính là file do `-o` chỉ định (vd `output.txt`), mỗi dòng một `IP:port`.

- Go · stdlib, không thư viện ngoài
- Quy mô > 50.000 IP
- Dấu hiệu tách rời trong JSON
- Có resume

---

## 01 · Cách tool hoạt động

Ba pha nối tiếp nhau. Mỗi IP là một đơn vị công việc — một worker xử lý trọn cả ba port của một IP rồi mới sang IP khác, nên tải không dồn vào cùng một máy đích.

```
ips.txt            PHA 1            PHA 2                 PHA 3            artex.txt
IP · CIDR · dải →  TCP connect  →   Fingerprint      →    Chấm điểm   →   IP:port
                   80 · 443 · 8787  title · header         artex-rules.json
                   → port mở        cookie · favicon       cộng dồn score
                                    hash · TLS cert
```

Pha 1 lọc rất mạnh, nên pha 2 và 3 chỉ chạy trên phần nhỏ còn lại. Mọi host có HTTP đều được ghi bằng chứng vào `results.csv`, kể cả loại "nghi ngờ".

## 02 · Go hay Python?

Anh phân vân giữa hai bên. Với **50.000 IP × 3 port ≈ 150.000 kết nối TCP**, khác biệt thực tế nằm ở ba chỗ:

| | Go | Python asyncio |
|---|---|---|
| Chi phí mỗi kết nối | goroutine ~4 KB stack | coroutine + transport object, nặng hơn vài lần |
| Đồng thời thoải mái trên VM 4 vCPU | 2.000 – 10.000 | 500 – 2.000 trước khi event loop trễ |
| Triển khai | 1 binary tĩnh, `scp` là chạy | cần Python 3.8+, venv, pip trên máy quét |
| HTTP + TLS client | có sẵn trong stdlib | stdlib asyncio không có HTTP client, phải cài thêm |
| Sửa nhanh tại chỗ | phải build lại | sửa file là chạy |

Thời gian ước tính cho 50.000 IP, tính theo trường hợp xấu nhất là mọi port đều timeout 2 giây:

- Go, `-c 1000` → `50000 × 3 × 2 / 1000` ≈ **5 phút**
- Python asyncio, concurrency 500 → ≈ **10 phút**

> **Khuyến nghị**
>
> **Chọn Go — nhưng không phải vì tốc độ.** Cả hai đều chạy xong trong thời gian chấp nhận được. Lý do thật là triển khai: một binary tĩnh chạy được trên jump host không có Python, không đụng tới môi trường sẵn có, và chịu tải tốt hơn khi số file descriptor lên cao.
>
> **Đánh đổi:** nếu đội quen sửa Python hơn và sẽ thường xuyên chỉnh logic fingerprint thì Python đáng cân nhắc. Tool này đã tách toàn bộ dấu hiệu ra `artex-rules.json` chính là để đội vận hành sửa dấu hiệu mà không đụng vào code — nên lợi thế "dễ sửa" của Python yếu đi nhiều. Nếu anh vẫn muốn bản Python, em viết lại tương đương.

**Khi nào cần masscan:** nếu phạm vi vượt khoảng 200.000 IP hoặc cần xong trong dưới 1 phút, để `masscan` làm pha 1 (SYN scan) rồi đưa danh sách port mở sang tool này làm pha 2. Lệnh cụ thể nằm trong README.

## 03 · Bước bắt buộc trước khi quét

> **⚠️ Đọc trước khi chạy**
>
> File `artex-rules.json` hiện tại **mới chỉ dựa trên chữ "ARTEX"**. Em chưa truy cập được trang mẫu của anh (chi tiết ở mục 07), nên chưa có dấu hiệu thật. Quét diện rộng ngay bây giờ nhiều khả năng ra kết quả rỗng hoặc sai.

Chạy chế độ profile để tool tự lấy dấu hiệu từ trang ARTEX anh đã dựng:

```bash
go build -o artexscan .
./artexscan -profile http://47.120.40.162:8787/login
```

Nó in ra:

- `<title>`, toàn bộ response header, cookie, Server, X-Powered-By
- **favicon mmh3 hash** — cùng chuẩn với `http.favicon.hash` của Shodan — và sha256
- CN/SAN của TLS cert nếu có
- Chuỗi đáng chú ý trong body: tên file JS/CSS có hash build, dấu hiệu framework
- Một khối JSON `rules` gợi ý, dán thẳng được vào `artex-rules.json`

Sau đó mở `artex-rules.json` và làm ba việc:

1. Thay phần `rules` bằng khối gợi ý.
2. **Xóa những rule quá chung chung.** `Server: nginx` sẽ khớp với hàng nghìn host không phải ARTEX. Giữ lại thứ chỉ ARTEX mới có: favicon hash, tên file JS có hash build, chuỗi tên sản phẩm, tên cookie riêng.
3. Cân lại `score` và `min_score`.

> **Nên làm**
>
> Profile thêm 1–2 instance ARTEX thật trong nội bộ rồi lấy **phần giao nhau** giữa các bộ dấu hiệu. Làm vậy mới chắc rule không bám vào thứ chỉ đúng với riêng máy demo — hostname, cert, cấu hình proxy.

## 04 · Chạy quét

```bash
./artexscan \
  -targets ips.txt \
  -rules artex-rules.json \
  -ports 80,443,8787 \
  -c 800 \
  -o output.txt
```

Chế độ thường **bắt buộc** `-o <file>`: file nhận danh sách `IP:port` các host xác định là ARTEX. Dùng `-debug` để in toàn bộ thông tin quan sát được trên mỗi host (không cần `-o`). Thêm `-out <thư mục>` nếu muốn giữ bằng chứng đầy đủ (CSV/JSONL) và trạng thái resume.

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

| Nơi | Nội dung | Khi nào có |
|---|---|---|
| File `-o` (vd `output.txt`) | **Deliverable chính** — `IP:port`, mỗi dòng một host xác định là ARTEX, đã sắp xếp và loại trùng | Chế độ thường |
| `results.csv` (trong `-out`) | Toàn bộ bằng chứng mọi host có HTTP — mở Excel, lọc cột `verdict` | Khi có `-out` |
| `results.jsonl` (trong `-out`) | Mỗi host một dòng JSON, đẩy thẳng vào SIEM/SOAR | Khi có `-out` |
| `.scanned` (trong `-out`) | IP đã quét xong, phục vụ `-resume` | Khi có `-out` |
| stdout | Toàn bộ thông tin quan sát được trên mỗi host có HTTP | Chế độ `-debug` |

File `-o` được ghi và `fsync` ngay mỗi khi tìm thấy một host — mất điện giữa chừng vẫn còn kết quả.

## 05 · Chạy ở quy mô trên 50.000 IP

> **⚠️ Lỗi hay gặp nhất**
>
> Nâng giới hạn file descriptor *trước khi* chạy: `ulimit -n 65535`. Nếu không, scan sẽ báo `too many open files` và mọi host sau đó bị đánh nhầm là đóng port — tức là **false negative hàng loạt mà không có cảnh báo rõ ràng**.

| Môi trường | `-c` gợi ý |
|---|---|
| Qua VPN / WAN liên chi nhánh | 200 – 400 |
| LAN nội bộ, VM 2–4 vCPU | 500 – 1.000 |
| LAN nội bộ, VM 8+ vCPU, đã nâng ulimit | 1.500 – 2.500 |

**Chia theo mảng mạng thay vì một phát 50.000 IP.** Mỗi site/VLAN một file targets. Dễ theo dõi, dễ chạy lại phần lỗi, và nếu có sự cố mạng thì khoanh vùng được ngay.

## 06 · Lưu ý vận hành

- **Báo trước cho trực ca.** 150.000 kết nối từ một nguồn sẽ bắn alert trên IDS/NDR và có thể bị WAF chặn IP. Mặc định User-Agent là `VinSOC-AssetDiscovery/1.0` để anh em trực nhận ra ngay đây là scan nội bộ chứ không phải tấn công — đổi bằng `-ua` nếu có quy ước riêng.
- **Tool chỉ bắt tay TCP và gửi `GET`.** Không gửi payload, không thử credential, không khai thác. Nhưng vẫn là quét chủ động, vẫn cần nằm trong phạm vi được phê duyệt.
- **TLS không verify cert.** Cố ý, để đọc được cert tự ký mà fingerprint. Chấp nhận được vì đây là discovery và không truyền dữ liệu nhạy cảm, nhưng cần biết là kênh không chống MITM.
- **Không tự động đi theo redirect.** `Location` được ghi lại để đối chiếu. Nếu ARTEX luôn redirect `/` → `/login` thì đặt rule trên path `/login`, hoặc match trường `location`.
- **Mặc định xáo trộn thứ tự IP** để không nện liên tiếp vào cùng một /24.

## 07 · Giới hạn cần biết trước khi tin kết quả

> **⚠️ Ba điều phải nói thẳng**
>
> 1. **Code chưa được biên dịch thử.** Shell trong phiên làm việc này bị chặn nên em không chạy được `go build`. Anh build lần đầu, nếu có lỗi cú pháp thì gửi em output, em sửa ngay.
> 2. **Em chưa xem được trang `http://47.120.40.162:8787/login`.** WebFetch trả về `ROBOTS_DISALLOWED` và trình duyệt cũng bị chặn trong phiên này. Vì vậy bộ rule hiện tại **chưa phải dấu hiệu thật của ARTEX**. Bắt buộc chạy `-profile` trước. Em không đoán hash favicon hay tên cookie — đoán sai thì tool chạy sạch mà không ra kết quả nào, còn tệ hơn là báo lỗi.
> 3. **Luôn kiểm chứng mẫu.** Sau lần quét đầu, mở `results.csv`, lọc `verdict=suspect` và kiểm tay 5–10 host. Có host ARTEX thật bị xếp vào `suspect` thì hạ `min_score`; có host lạ lọt vào `artex` thì rule đang quá rộng.

## 08 · Cách tính điểm

Mỗi rule khớp thì cộng `score`. Tổng điểm quyết định `verdict`:

| Điều kiện | Verdict | Đi đâu |
|---|---|---|
| ≥ `min_score` | **artex** | file `-o` |
| ≥ `suspect_from` | suspect | chỉ vào CSV, cần người xem |
| còn lại | other | chỉ vào CSV |

Thiết kế cộng điểm thay vì match đơn lẻ là có chủ ý. Một dấu hiệu lẻ — chữ "artex" trong body — có thể trùng ngẫu nhiên. Nhưng favicon hash, tên file JS và title khớp cùng lúc thì gần như chắc chắn. Một host muốn trốn phải giấu được cả ba.

---

*artexscan · tài liệu đi kèm bộ mã nguồn `main.go`, `artex-rules.json`, `README.md`, `ips.example.txt`.*
