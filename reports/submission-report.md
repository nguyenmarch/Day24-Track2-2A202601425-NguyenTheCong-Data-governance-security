# Báo cáo Lab 24 — Data Governance & Security

| Thông tin | Giá trị |
|---|---|
| Họ và tên | Nguyễn Thế Công |
| MSSV | 2A202601425 |
| Bài thực hành | Day 24: Data governance and Security — Attack your own agent, then contain it |
| Chế độ kiểm thử | `--mock` (deterministic) |

## Kết quả thực hiện

Baseline đã bị prompt injection khiến agent đọc và gửi PII tổng hợp của
`KH-000999` tới local sink. Evidence gốc nằm tại
[`attack-before.log`](attack-before.log).

Sau containment, agent tách Run A (untrusted documents) và Run B (private
data); Run B chỉ nhận ticket ID trích từ tên file và tra customer qua quan hệ
tin cậy `related_tickets`. Policy chặn egress của dữ liệu `restricted`, nên
sink không nhận POST nào. Evidence nằm tại
[`attack-after.log`](attack-after.log) và [`ledger.jsonl`](ledger.jsonl).

## Controls đã triển khai

| Control | Mục tiêu | Evidence |
|---|---|---|
| PII gate | Phát hiện và redact CCCD, SĐT, STK, email trước khi đưa ticket vào summary. | `agent/pii.py` |
| Policy Enforcement Point | Kiểm tra policy trước mỗi tool call và luôn trả về reason. | `agent/policy.py` |
| Trifecta split | Không dùng free text để quyết định customer nào được đọc; không run nào sở hữu cả untrusted content, PII và egress. | `agent/runner.py` |
| Tamper-evident ledger | Ghi append-only mỗi quyết định tool call với SHA-256 hash chain. | `agent/ledger.py`, `reports/ledger.jsonl` |

## Xác minh

Lệnh kiểm thử: `python3 -m pytest -q -s`

Kết quả: **14 passed**; PII precision = **1.000**, recall = **1.000**.

Chi tiết đối chiếu yêu cầu nằm tại
[`compliance-mapping.md`](compliance-mapping.md) và
[`dpia-lite.md`](dpia-lite.md).
