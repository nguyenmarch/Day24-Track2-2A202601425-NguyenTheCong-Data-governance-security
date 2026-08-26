"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])")
_CCCD_LABELLED = re.compile(r"\b(?:CCCD|căn\s*cước(?:\s*công\s*dân)?)\s*(?:là|:)?\s*(\d{12})\b", re.IGNORECASE)
_CCCD_BARE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_BANK = re.compile(
    r"\b(?:STK|số\s*tài\s*khoản|tài\s*khoản)\s*(?:là|:|tới)?\s*(\d{8,16})\b",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)(0\d(?:[ .-]?\d){8,9})(?!\d)")


def detect(text: str) -> list[dict]:
    """Return non-overlapping, typed PII spans in stable document order."""
    candidates: list[dict] = []

    def add(kind: str, start: int, end: int) -> None:
        candidates.append({"type": kind, "start": start, "end": end})

    for match in _EMAIL.finditer(text):
        add("EMAIL", match.start(), match.end())
    for match in _BANK.finditer(text):
        add("VN_BANK_ACCOUNT", match.start(1), match.end(1))
    for match in _CCCD_LABELLED.finditer(text):
        add("VN_CCCD", match.start(1), match.end(1))
    # A bare 12-digit value is treated as CCCD unless a more specific
    # labelled bank-account match already owns that span.
    for match in _CCCD_BARE.finditer(text):
        add("VN_CCCD", match.start(), match.end())
    for match in _PHONE.finditer(text):
        add("VN_PHONE", match.start(1), match.end(1))

    # Prefer the contextual classifiers above generic numeric matches, then
    # remove overlaps so one value cannot be emitted as two entity types.
    priority = {"VN_BANK_ACCOUNT": 0, "VN_CCCD": 1, "VN_PHONE": 2, "EMAIL": 3}
    selected: list[dict] = []
    for entity in sorted(candidates, key=lambda e: (e["start"], priority[e["type"]], -(e["end"] - e["start"]))):
        if any(entity["start"] < kept["end"] and kept["start"] < entity["end"] for kept in selected):
            continue
        selected.append(entity)
    return sorted(selected, key=lambda e: (e["start"], e["end"]))


def redact(text: str) -> str:
    for entity in reversed(detect(text)):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + replacement + text[entity["end"] :]
    return text
