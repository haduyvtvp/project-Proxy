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
- ✅ **Access Log** — ghi nhật ký mọi request với timestamp, IP client, host, method và kết quả (`ALLOWED` / `BLOCKED` / `ERROR`)
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

Danh sách domain bị chặn được định nghĩa trong [`PolicyService.java`](proxy/src/main/java/vn/secureproxy/PolicyService.java).

**Danh sách mặc định:**

| Domain | Subdomain cũng bị chặn |
|---|---|
| `facebook.com` | ✅ |
| `tiktok.com` | ✅ |
| `instagram.com` | ✅ |
| `netflix.com` | ✅ |
| `blocked.example` | ✅ |
| `example.org` | ✅ |

**Để thêm domain vào blocklist**, chỉnh sửa `danhSachChan` trong `PolicyService.java`:

```java
private final Set<String> danhSachChan = new HashSet<>(
    Arrays.asList(
        "facebook.com",
        "domain-muon-chan.com",   // ← thêm vào đây
        ...
    )
);
```

> **Lưu ý:** Blocklist áp dụng cho cả subdomain. Ví dụ, chặn `facebook.com` sẽ tự động chặn `m.facebook.com`, `api.facebook.com`, v.v.

---

## 🧪 Kiểm thử

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
