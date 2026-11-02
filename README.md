# 🛡️ Secure Proxy

Một **HTTP/HTTPS Proxy Server** được xây dựng bằng **Java + Netty**, hỗ trợ lọc truy cập theo domain (blocklist), ghi access log, và triển khai hoàn toàn bằng **Docker Compose**.

---

## 📋 Mục lục

- [Tính năng](#-tính-năng)
- [Kiến trúc](#-kiến-trúc)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Yêu cầu hệ thống](#-yêu-cầu-hệ-thống)
- [Hướng dẫn chạy](#-hướng-dẫn-chạy)
- [Cấu hình Blocklist](#-cấu-hình-blocklist)
- [Kiểm thử](#-kiểm-thử)
- [Công nghệ sử dụng](#-công-nghệ-sử-dụng)

---

## ✨ Tính năng

- ✅ **HTTP Proxy** — chuyển tiếp các request HTTP thông thường đến server đích
- ✅ **HTTPS Proxy (HTTP CONNECT Tunneling)** — thiết lập tunnel TCP trong suốt để truyền tải TLS/SSL nguyên bản
- ✅ **Domain Blocklist** — chặn truy cập đến các tên miền bị cấm (bao gồm cả subdomain)
- ✅ **Smart Policies** — lọc theo danh mục, wildcard/regex, lịch theo thứ/ngày và chế độ whitelist; chỉnh sửa trên dashboard
- ✅ **Proxy access security** — chỉ CIDR mạng private/loopback được dùng proxy; rate limit theo IP và chặn phishing, quảng cáo/tracker từ public feeds
- ✅ **Access Log** — ghi nhật ký mọi request với timestamp, IP client, host, method và kết quả (`ALLOWED` / `BLOCKED` / `ERROR`)
- ✅ **WebSocket** — đẩy access log mới theo thời gian thực đến dashboard
- ✅ **PostgreSQL** — lưu access log bền vững; log cũ trong `/data/access.log` được nhập vào database khi Admin API khởi động
- ✅ **Đóng gói bằng Docker** — build multi-stage, không cần cài Java trên máy host
- ✅ **Test server tích hợp** — nginx trả về response mẫu để kiểm thử nhanh

---

## 🏗️ Kiến trúc

```
Client (curl / trình duyệt)
        │
        │  HTTP hoặc HTTPS CONNECT
        ▼
┌─────────────────────────┐
│    secure-proxy :8888   │  ← Java + Netty
│                         │
│  ┌─────────────────┐    │
│  │  ProxyServer    │    │  Lắng nghe port 8888, khởi tạo pipeline Netty
│  └────────┬────────┘    │
│           │             │
│  ┌────────▼────────┐    │
│  │  ProxyHandler   │    │  Xử lý HTTP & CONNECT, relay TCP tunnel
│  └────────┬────────┘    │
│           │             │
│  ┌────────▼────────┐    │
│  │  PolicyService  │    │  Kiểm tra domain với blocklist
│  └─────────────────┘    │
│  ┌─────────────────┐    │
│  │   AccessLog     │    │  Ghi log ra stdout
│  └─────────────────┘    │
└─────────────────────────┘
        │
        │  Forward request
        ▼
┌─────────────────────────┐
│  proxy-test-web :8081   │  ← nginx (server thử nghiệm)
└─────────────────────────┘
```

### Luồng xử lý

| Loại request | Xử lý |
|---|---|
| HTTP (`GET`, `POST`, ...) | Parse URI → kiểm tra policy → kết nối đến đích → relay response về client |
| HTTPS (`CONNECT`) | Kiểm tra policy → kết nối TCP đến đích → gửi `200 Connection Established` → relay raw bytes hai chiều |
| Domain bị chặn | Trả về `403 Forbidden` ngay lập tức, ghi log `BLOCKED` |

---

## 📁 Cấu trúc thư mục

```
project-Proxy/
├── compose.yaml                    # Docker Compose: proxy + nginx test server
├── target/
│   └── nginx.conf                  # Cấu hình nginx cho test server
└── proxy/
    ├── Dockerfile                  # Multi-stage build: Maven → JRE
    ├── pom.xml                     # Maven build config
    └── src/main/java/vn/secureproxy/
        ├── ProxyServer.java        # Entry point, khởi tạo Netty server
        ├── ProxyHandler.java       # Logic xử lý HTTP & HTTPS CONNECT
        ├── PolicyService.java      # Quản lý blocklist domain
        └── AccessLog.java          # Ghi access log ra stdout
```

---

## 🖥️ Yêu cầu hệ thống

| Công cụ | Phiên bản |
|---|---|
| Docker | 20.10+ |
| Docker Compose | v2+ |

> Không cần cài Java hay Maven — mọi thứ được build bên trong container.

---

## 🚀 Hướng dẫn chạy

### 1. Clone & chạy bằng Docker Compose

```bash
# Build image và khởi động tất cả services
docker compose up --build
```

Sau khi khởi động thành công, console sẽ hiển thị:
```
Secure Proxy dang chay tai cong 8888
```

### 2. Kiểm tra nhanh qua curl

```bash
# Truy cập test server qua proxy (HTTP)
curl -x http://127.0.0.1:8888 http://proxy-test-web/

# Kỳ vọng: "Secure Proxy test server is working!"
```
### 3. Chạy trình duyệt
http://127.0.0.1:3000

### 4. Dừng services

```bash
docker compose down
```

---

## 🚫 Cấu hình Blocklist

Quản lý các domain tùy chỉnh trong tab **Blocklist**. Để cấu hình chế độ lọc, nhóm domain, wildcard/regex và lịch, dùng tab **Smart Policies**.

**Một số domain có trong cấu hình mặc định:**

| Domain | Subdomain cũng bị chặn |
|---|---|
| `facebook.com` | ✅ |
| `tiktok.com` | ✅ |
| `instagram.com` | ✅ |
| `netflix.com` | ✅ |
| `blocked.example` | ✅ |
| `example.org` | ✅ |

> **Lưu ý:** Blocklist áp dụng cho cả subdomain. Ví dụ, chặn `facebook.com` sẽ tự động chặn `m.facebook.com`, `api.facebook.com`, v.v.

## 🧠 Smart Policies

Mở tab **Smart Policies** trên dashboard để chọn chế độ `BLOCKLIST` hoặc `WHITELIST`, chỉnh timezone, allowlist và thêm/sửa/xóa danh mục. Proxy tự nạp policy mới trong khoảng 5 giây; không cần khởi động lại container.

- Mỗi mẫu domain một dòng: `facebook.com` khớp domain và subdomain; `*.fbcdn.net` chỉ khớp subdomain.
- Regex dùng tiền tố `regex:`, ví dụ `regex:^play[0-9]+\.example$`.
- Mỗi lịch một dòng theo dạng `MON,TUE 07:30-17:00`; dùng `*` cho mọi ngày. Khoảng giờ qua nửa đêm như `MON 22:00-06:00` được hỗ trợ. Để trống lịch nghĩa là danh mục hoạt động cả ngày.
- Mẫu trong allowlist luôn được cho phép trước các danh mục. Ở chế độ whitelist, domain không nằm trong allowlist sẽ bị chặn.

API quản trị policy: `GET /api/policy` để đọc và `PUT /api/policy` để lưu file `/data/policy.json`. Các trường được kiểm tra trước khi ghi; file được thay thế nguyên tử để proxy không đọc phải JSON dở dang.

## 🔐 Bảo mật proxy

- Proxy chỉ nhận kết nối từ `127.0.0.0/8`, `::1/128`, các mạng IPv4 private `10/8`, `172.16/12`, `192.168/16` và IPv6 ULA `fc00::/7`. Client ngoài các dải này bị đóng kết nối trước khi xử lý HTTP. ACL đọc IP nguồn của socket, không tin `X-Forwarded-For`.
- Compose chỉ publish proxy trên `127.0.0.1` mặc định. Để các máy trong LAN dùng proxy, đặt `PROXY_HOST_BIND` thành IP LAN của máy Docker, ví dụ `192.168.1.20`; chỉ bind vào địa chỉ mạng private, không bind vào IP public. Cấu hình firewall của host chỉ cho phép subnet LAN cần thiết.
- Tùy chỉnh dải CIDR bằng biến `PROXY_ALLOWED_CIDRS` (danh sách phân tách bằng dấu phẩy). Nếu thay đổi, chỉ thêm các mạng bạn quản lý; không thêm `0.0.0.0/0` hoặc `::/0`.
- Rate limit mặc định là 120 request/phút/IP, burst 30; chỉnh bằng `PROXY_RATE_LIMIT_PER_MINUTE` và `PROXY_RATE_LIMIT_BURST`. Khi vượt ngưỡng proxy trả HTTP 429. CONNECT được tính một request khi bắt đầu tunnel.
- Mỗi 6 giờ proxy tải feed phishing [OpenPhish community feed](https://github.com/openphish/public_feed) và feed ads/tracker [StevenBlack hosts](https://github.com/StevenBlack/hosts) qua HTTPS. Domains được cache tại `/data/phishing-domains.txt` và `/data/ads-trackers.txt`, nạp lại tự động; khi feed không tải được thì tiếp tục dùng bản cache hợp lệ trước đó. Hostname chỉ được kiểm tra cục bộ, không gửi truy vấn DNS cho bên thứ ba.
- Đây là lọc domain trên lưu lượng đi qua HTTP proxy, không phải DNS server/DNS sinkhole cho toàn mạng. Thiết bị cần cấu hình dùng proxy để được lọc; HTTPS CONNECT chỉ kiểm tra hostname đích, không giải mã URL/path.
- Dashboard và cổng Admin API được bind vào localhost (`127.0.0.1:3000`, `127.0.0.1:8080`) vì API quản trị chưa có đăng nhập. Giữ nguyên giới hạn này khi triển khai trên máy dùng chung; nếu cần truy cập dashboard từ LAN, đặt sau VPN hoặc reverse proxy có xác thực.

Compose có thể cấu hình qua file `.env` trong thư mục dự án, ví dụ:

```dotenv
PROXY_ALLOWED_CIDRS=127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
PROXY_HOST_BIND=192.168.1.20
PROXY_RATE_LIMIT_PER_MINUTE=120
PROXY_RATE_LIMIT_BURST=30
```

Sau khi chỉnh, áp dụng bằng `docker compose up -d --build proxy`.

---

## 🧪 Kiểm thử

### Kiểm tra log trong PostgreSQL

```bash
docker compose exec db psql -U secureproxy -d secureproxy \
  -c "SELECT id, logged_at, host, result, reason FROM access_logs ORDER BY id DESC LIMIT 10;"
```

Admin API đọc log từ database tại `GET http://127.0.0.1:8080/api/logs`. Các log cũ trong file được nhập lại an toàn khi API khởi động; log trùng được bỏ qua.

Dashboard nhận log mới qua WebSocket tại `ws://127.0.0.1:3000/ws/logs` (hoặc `wss://` khi dùng HTTPS).

### Dashboard giám sát

Tab **Dashboard** hiển thị lưu lượng theo khoảng thời gian, tổng request, tỷ lệ ALLOWED/BLOCKED, top domain và top client (đã gộp cổng kết nối). Dữ liệu được tổng hợp từ PostgreSQL, làm mới khi có log WebSocket mới và định kỳ mỗi 30 giây.

Tab **Access Logs** hỗ trợ lọc theo khoảng thời gian, địa chỉ client/IP và domain; kết quả được phân trang. API tương ứng là `GET /api/monitoring` và `GET /api/logs/search`.

### Kiểm tra domain bị chặn

```bash
# Thử truy cập facebook.com qua proxy
curl -x http://127.0.0.1:8888 http://www.facebook.com/

# Kỳ vọng: HTTP 403 - "Access denied by Secure Proxy"
```

### Kiểm tra HTTPS CONNECT

```bash
# Thử kết nối HTTPS qua proxy
curl -x http://127.0.0.1:8888 https://example.com/

# Domain được phép → tunnel thành công
```

### Xem Access Log

Log được in ra stdout của container:

```bash
docker compose logs -f proxy
```

**Định dạng log:**
```
[2026-10-29 10:30:00] Client=/172.18.0.1:54321 Host=example.com Method=GET Result=ALLOWED
[2026-10-29 10:30:01] Client=/172.18.0.1:54322 Host=facebook.com Method=CONNECT Result=BLOCKED
```

---

## 🔧 Công nghệ sử dụng

| Thành phần | Công nghệ | Phiên bản |
|---|---|---|
| Ngôn ngữ | Java | 17 |
| Networking framework | Netty | 4.1.118.Final |
| Logging | SLF4J Simple | 2.0.16 |
| Build tool | Maven + Shade Plugin | 3.9.9 / 3.6.0 |
| Runtime image | Eclipse Temurin JRE | 17 |
| Container | Docker (multi-stage build) | — |
| Orchestration | Docker Compose | v2 |
| Test server | nginx | alpine |
