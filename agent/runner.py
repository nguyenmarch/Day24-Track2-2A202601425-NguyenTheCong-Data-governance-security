"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
_TICKET_ID = re.compile(r"^ticket-(\d+)(?:[a-z]*)\.md$", re.IGNORECASE)


def _args_hash(args: object) -> str:
    payload = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _record(
    ledger_path: Path,
    run_id: str,
    agent_id: str,
    tool: str,
    args: object,
    classification: str,
    allowed: bool,
    reason: str,
) -> None:
    ledger.append(
        {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason or "Policy decision recorded without a supplied reason.",
        },
        ledger_path,
    )


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Convert only document *names* into typed cross-run input.

    Document text is deliberately excluded: it is attacker-controlled and
    must not influence the private-data run.
    """
    ids = set()
    for doc in docs:
        match = _TICKET_ID.fullmatch(str(doc.get("id", "")))
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _trusted_customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Resolve tickets through the trusted relationship table, never prose."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_set = set(ticket_ids)
    return [
        str(customer["customer_id"])
        for customer in customers
        if ticket_set.intersection(customer.get("related_tickets", []))
    ]


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid4().hex}"

    # Run A owns untrusted document retrieval only.
    run_a_context = PolicyContext("internal", "summarize-tickets", "run-a", 0, False)
    allowed, reason = check(run_a_context)
    _record(ledger_path, run_id, "run-a", "search_docs", {"query": message}, "internal", allowed, reason)
    docs = tools.search_docs(message) if allowed else []

    untrusted_text = "\n\n".join(str(doc["text"]) for doc in docs)
    injection = llm.find_injection(untrusted_text)
    safe_docs = [{"id": doc["id"], "text": pii.redact(str(doc["text"]))} for doc in docs]
    trusted_ticket_ids = _ticket_ids(docs)

    # Run B receives just list[int], then maps it using data-owned ticket
    # relations. It can read private data but can never make a network call.
    run_b_context = PolicyContext("restricted", "support-reconciliation", "run-b", 1, False)
    for customer_id in _trusted_customers_for_tickets(trusted_ticket_ids):
        allowed, reason = check(run_b_context)
        _record(
            ledger_path, run_id, "run-b", "read_customer", {"customer_id": customer_id},
            "restricted", allowed, reason,
        )
        if allowed:
            try:
                tools.read_customer(customer_id)
            except tools.ToolError:
                # The failed tool use was still audited before execution.
                pass

    # An injection is evidence of an attempted egress. The PEP evaluates and
    # records it, but the real http_post tool is never invoked after a deny.
    if injection is not None:
        egress_context = PolicyContext("restricted", "untrusted-instruction", "run-a", 0, True)
        allowed, reason = check(egress_context)
        _record(
            ledger_path, run_id, "run-a", "http_post",
            {"url": injection.target_url, "customer_ids": injection.customer_ids},
            "restricted", allowed, reason,
        )
        if allowed:  # Defensive: the minimum policy rule must make this unreachable.
            tools.http_post(injection.target_url, {"records": []})

    return llm.summarize(safe_docs)
