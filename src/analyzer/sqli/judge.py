from __future__ import annotations

import html
import re
import statistics
from dataclasses import dataclass
from urllib.parse import quote

# 응답 본문에서 이 문구가 나오면 SQLi로 판정 (error-based / union 판정용 시그니처)
UNION_ERROR_KEYWORDS: tuple[str, ...] = (
    "the used select statements have a different number of columns",
    "column count doesn't match",
)

DB_ERROR_KEYWORDS: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "mysql_fetch",
    "mysqli_",
    "sql syntax",
    "mariadb server version",
    "supplied argument is not a valid mysql",
    "division by zero",
    "duplicate entry",
    "xpath syntax error",
    "the used select statements have a different number of columns",
    "column count doesn't match",
)

# Time-based 기준 — rules_sqli.py 의 _SLEEP 과 짝. (_SLEEP - 0.5 여유 권장)
SLEEP_THRESHOLD = 2.5   # (레거시) baseline 방식 절대 문턱 — control 대조 방식에선 미사용, 폐기 여부 확정 대기
DELAY_MARGIN = 2.0      # (레거시) baseline 대비 최소 추가 지연 — control 대조 방식에선 미사용
MIN_REPEAT_CONFIRM = 2

# Time(#10) control 대조 방식 — Δ = elapsed(attack) - elapsed(control) 이 마진 이상이면 지연으로 인정
TIME_MARGIN_FLOOR = 2.0   # Δ 절대 하한(초) — σ 불안정 대비 안전판(항상 유지)
TIME_SIGMA_K = 3.0        # Δ >= k·σ_control

# Error-based 정보추출 마커 — 값 양쪽을 이 구분자로 감싸 응답에서 추출. hex 0x7e7e.
EXTRACT_MARKER = "~~"


@dataclass
class SqliVerdict:
    vulnerable: bool
    confidence: str
    evidence: str
    # "vulnerable" | "safe" | "inconclusive"
    final_status: str = "vulnerable"


@dataclass
class TimePairInput:  # Time(#10) 한 pair_id의 회차별 응답시간
    pair_id: str
    attack: dict[int, float]   # iteration -> elapsed(초)
    control: dict[int, float]  # iteration -> elapsed(초)


_MIN_STRIP_LEN = 4


# 응답 본문에서 payload/입력값 반사분을 제거 (동적 diff 비교 시 반사 노이즈 제거용)
def _strip_value(body: str, value: str) -> str:
    if not value:
        return body
    variants = {value, quote(value), html.escape(value), html.escape(quote(value))}
    for v in variants:
        if v and len(v) >= _MIN_STRIP_LEN:
            body = body.replace(v, "")
    return body


def _strip_dynamic(body: str, markers: list[tuple[str, str]]) -> str:
    for prefix, suffix in markers:
        if not prefix or not suffix:
            continue
        pattern = re.escape(prefix) + r".*?" + re.escape(suffix)
        body = re.sub(pattern, prefix + suffix, body, flags=re.DOTALL)
    return body


def judge_union_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()
    for kw in UNION_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "medium", f"UNION-based SQLi: 컬럼 수 불일치 에러 노출 ('{kw}')")
    return SqliVerdict(False, "", "UNION 에러 시그니처 없음")


# payload가 뽑아내려는 정보 종류 (증거에 공격-정보 연관성 명시용)
def _info_kind(payload: str) -> str:
    p = (payload or "").lower()
    if "version(" in p:
        return "version"
    if "current_user(" in p or "session_user(" in p:
        return "current_user"
    if "database(" in p:
        return "database"
    return ""


# 마커로 감싼 값이 공격 응답에만 있고 baseline엔 없으면 그 값을 반환 (정보추출 근거)
def _extract_marked_value(baseline_body: str, attack_body: str, marker: str) -> str | None:
    if not marker:
        return None
    m = re.escape(marker)
    pattern = re.compile(m + r"(.+?)" + m, re.DOTALL)
    for match in pattern.finditer(attack_body):
        if match.group(0) not in baseline_body:
            return match.group(1)
    return None


# Error-based 2분기: 마커로 값 노출→vulnerable / 그 외(DB 에러만 있거나 아무것도 없음)→safe. 기본 structural.
def judge_error_based_sqli(
    baseline_body: str,
    attack_body: str,
    *,
    extract_marker: str = EXTRACT_MARKER,
    judgment: str = "structural",
    payload: str = "",
) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()

    # 1) extraction만 마커 확인
    if judgment == "extraction":
        value = _extract_marked_value(baseline_body or "", attack_body or "", extract_marker)
        if value is not None:
            kind = _info_kind(payload)
            kind_str = f"{kind} " if kind else ""
            return SqliVerdict(
                True, "high",
                f"Error-based SQLi (정보추출): {kind_str}값 '{value}' 이 마커 {extract_marker}로 공격 응답에만 노출",
                final_status="vulnerable",
            )

    # 2) baseline엔 없던 DB 에러만 노출 → 정보추출은 확인 못 했으니 취약 근거로 보지 않음 (safe)
    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(
                False, "",
                f"DB 에러가 공격 응답에만 노출됐지만 정보추출 미확인 — 취약 근거 부족 ('{kw}')",
                final_status="safe",
            )

    # 3) baseline에도 DB 에러 → 정상 동작
    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw in base_lower:
            return SqliVerdict(
                False, "", f"DB 에러 문구가 baseline에도 있음 — 이 페이지의 정상 동작 ('{kw}')",
                final_status="safe",
            )

    return SqliVerdict(False, "", "DB 에러·마커 시그니처 없음", final_status="safe")


# control 표본으로 마진 산출 — 표본 2개 이상이면 k·σ, 항상 2.0 하한 유지(σ 튈 때 안전판)
def _time_margin(control_elapseds: list[float]) -> float:
    if len(control_elapseds) >= 2:
        return max(TIME_MARGIN_FLOOR, TIME_SIGMA_K * statistics.pstdev(control_elapseds))
    return TIME_MARGIN_FLOOR


# Time(#10): pair_id별 attack·control을 iteration끼리 짝지어 Δ=attack-control 로 판정.
# baseline 대신 대조(sleep 0)를 기준선으로 써 서버 부하·rate-limit 상쇄. 서로 다른 payload 합산 금지(pair 단위).
def judge_time_based_sqli(pairs: list[TimePairInput]) -> SqliVerdict:
    margin = _time_margin([v for p in pairs for v in p.control.values()])

    scored: list[tuple[str, int, int, float]] = []  # (pair_id, 초과회차수, 총회차수, 최대Δ)
    for p in pairs:
        iters = sorted(set(p.attack) & set(p.control))  # attack·control 둘 다 있는 회차만
        if not iters:
            continue
        deltas = [p.attack[i] - p.control[i] for i in iters]
        exceed = sum(1 for d in deltas if d >= margin)
        scored.append((p.pair_id, exceed, len(iters), max(deltas)))

    # attack↔control 짝을 하나도 못 묶음 → 계약 필드 없음/불충분 → 검사 미완료(safe 금지)
    if not scored:
        return SqliVerdict(False, "", "time pair 요청 없음/불충분으로 검사 미완료(대조 짝 없음)",
                           final_status="inconclusive")

    # 한 pair에서 마진 초과 회차가 MIN_REPEAT_CONFIRM 이상 → confirmed
    confirmed = [s for s in scored if s[1] >= MIN_REPEAT_CONFIRM]
    if confirmed:
        pid, cnt, tot, best = max(confirmed, key=lambda s: s[3])
        return SqliVerdict(
            True, "high",
            f"Time-based SQLi (confirmed): pair {pid}에서 {cnt}/{tot}회차 대조 대비 Δ>={margin:.2f}s "
            f"(최대 Δ {best:.2f}s)",
            final_status="vulnerable",
        )

    # 초과 회차 1개 이상이나 재현 문턱 미달 → suspected
    suspected = [s for s in scored if s[1] >= 1]
    if suspected:
        pid, cnt, tot, best = max(suspected, key=lambda s: s[3])
        return SqliVerdict(
            True, "medium",
            f"Time-based SQLi (suspected): pair {pid}에서 {cnt}/{tot}회차만 Δ>={margin:.2f}s — 재현성 부족",
            final_status="vulnerable",
        )

    return SqliVerdict(False, "", f"대조 대비 유의미한 지연 없음 (Δ<{margin:.2f}s)", final_status="safe")
