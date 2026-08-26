# DPIA-lite (1 trang)

## 1. Dữ liệu gì

`search_docs` đọc ticket không tin cậy; ticket có thể chứa mã khách và nội
dung nghiệp vụ. `read_customer` là kho private, có tên, CCCD, SĐT, STK,
email và liên kết ticket. Ledger chỉ lưu metadata quyết định và hash đối số,
không lưu đối số hay PII thô.

## 2. Mục đích gì

Mục đích là tổng hợp ticket hỗ trợ và, khi cần đối soát hợp lệ, đọc hồ sơ
khách được suy ra từ bảng quan hệ `related_tickets`. Nội dung document không
được dùng để chọn khách cần đọc. PII được redact trước khi ticket được đưa
vào phần tóm tắt.

## 3. Chảy đi đâu

Trong đường chấm `--mock`, không có API model provider nào được gọi. Dữ liệu
đi từ corpus/private store vào process cục bộ; ledger ghi ở `reports/` và
sink `localhost:9999` chỉ là mô phỏng exfiltration. PEP cấm mọi egress khi
classification là `restricted`, nên record khách không thể được POST.

Nếu vận hành với `--model`, ticket đã redact có thể được gửi tới API model
provider; đó là luồng xuyên biên giới tiềm năng và phải được đưa vào hồ sơ
60 ngày, có cơ sở xử lý, thời hạn lưu giữ, DPA và đánh giá nhà cung cấp trước
khi bật. Không dùng model thật trong evidence này.
