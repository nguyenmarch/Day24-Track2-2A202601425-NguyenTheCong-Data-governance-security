# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade; dữ liệu lab synthetic và đây là stretch goal cần quy trình xoá riêng. | `Guide.md:185` |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory, nêu rõ mock không gọi model provider và điều kiện khi dùng model thật. | `reports/dpia-lite.md:20` |
| ASI03 — privilege abuse | Policy-as-code PEP trước mỗi tool call, identity `run-a`/`run-b`, hash-chain audit. | `agent/runner.py:76`, `agent/policy.py:39`, `agent/ledger.py:50` |
| ASI01 — goal hijack | Trifecta split: Run B chỉ nhận typed ticket IDs từ tên file và trusted relationship lookup; egress của restricted data bị deny. | `agent/runner.py:101`, `agent/runner.py:115`, `agent/runner.py:159`, `reports/attack-after.log:3` |
| ISO 42001 Clause 5-6 | Policy-as-code có reason bắt buộc; các tool decision được append vào ledger có thể verify. | `agent/policy.py:39`, `agent/ledger.py:44` |
