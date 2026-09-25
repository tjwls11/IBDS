from __future__ import annotations

from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any

from .finding import Finding
from .sqli.judge import (
    EXTRACT_MARKER,
    MIN_REPEAT_CONFIRM,
    TimePairInput,
    judge_error_based_sqli,
    judge_time_based_sqli,
    judge_union_sqli,
    _strip_dynamic,
    _strip_value,
)

# Boolean 판정 문턱
_TRUE_GATE = 0.85
_GATE_MARGIN = 0.05
_STATIC_EPS = 0.002


def _successful(result: dict | None) -> bool:
    return bool(result) and result.get("status") == "ok"


def _body(result: dict | None) -> str:
    if result is None or not _successful(result):
        return ""
    return result.get("response_body") or ""


def _finding(family: dict, result: dict, confidence: str, evidence: str,
             final_status: str = "inconclusive") -> Finding:
    case = result.get("case") or {}
    return Finding(
        vuln_type="sqli",
        family_id=str(family.get("family_id") or ""),
        target_id=str(family.get("target_id") or ""),
        param=str(family.get("param") or ""),
        attack_id=str(family.get("attack_id") or ""),
        technique=str(family.get("technique") or ""),
        case_id=str(case.get("case_id") or ""),
        method=case.get("method"),
        url=case.get("url"),
        location=case.get("body_type"),
        payload=case.get("payload"),
        raw_verdict={"vulnerable": final_status == "vulnerable", "confidence": confidence, "evidence": evidence},
        headless_checked=False,
        headless_verdict=None,
        final_status=final_status,
    )


def _payload_of(mutation: dict) -> str:
    return str((mutation.get("case") or {}).get("payload") or "")


def _clean_body(family: dict, result: dict | None) -> str:
    # payload 반사분·dynamic_markers 제거해 diff 노이즈 걷어냄
    body = _strip_value(_body(result), _payload_of(result or {}))
    return _strip_dynamic(body, family.get("dynamic_markers") or [])


# safe·inconclusive finding의 식별 필드용 대표 case — 첫 mutation, 없으면 baseline
def _representative_result(family: dict) -> dict:
    mutations = family.get("mutations") or []
    return mutations[0] if mutations else (family.get("baseline") or {})


def _family_finding(family: dict, final_status: str, evidence: str) -> Finding:
    return _finding(family, _representative_result(family), "", evidence, final_status)


def _bcase(mutation: dict, key: str) -> Any:  # MutationCase의 SQLi 비교 계약 필드 접근 (#9)
    return (mutation.get("case") or {}).get(key)


def _sim(base_clean: str, family: dict, mutation: dict) -> float:
    return SequenceMatcher(None, base_clean, _clean_body(family, mutation)).ratio()


# Boolean(#9): pair_id로 묶어 expected 방향 비교, control로 노이즈 게이트, repeat로 재현성 확인
def _analyze_boolean(family: dict) -> list[Finding]:
    base_clean = _clean_body(family, family.get("baseline"))
    muts = [m for m in family.get("mutations", []) if _successful(m)]
    attacks = [m for m in muts if _bcase(m, "role") in ("attack_true", "attack_false")]

    # pair 필드가 없거나(옛 구조) 성공한 공격 응답이 없으면 검사 미완료 (safe 금지)
    if not base_clean or not attacks:
        return [_family_finding(family, "inconclusive", "boolean pair 요청 없음/불충분으로 검사 미완료")]

    # control(비-SQL 잡음)로 노이즈 바닥 측정 — 입력만 바꿔도 흔들리는 페이지면 노이즈가 큼
    control_scores = [_sim(base_clean, family, m) for m in muts if _bcase(m, "role") == "control"]
    noise = (1.0 - min(control_scores)) if control_scores else 0.0

    bmr = family.get("baseline_match_ratio")
    gate = max(0.0, bmr - _GATE_MARGIN) if bmr is not None else _TRUE_GATE

    # pair_id별로 expected 방향에 따라 점수 수집 (repeat 포함)
    pairs: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"approx": [], "differ": []})
    for m in attacks:
        exp = _bcase(m, "expected")
        score = _sim(base_clean, family, m)
        if exp == "approx_baseline":
            pairs[_bcase(m, "pair_id")]["approx"].append(score)
        elif exp == "differ_baseline":
            pairs[_bcase(m, "pair_id")]["differ"].append(score)

    hits: list[tuple[str, float, float, float, bool]] = []  # (pair_id, gap, approx_min, differ_max, reproduced)
    for pid, g in pairs.items():
        if not g["approx"] or not g["differ"]:
            continue  # 한쪽만 성공한 pair는 판정 불가 → 스킵
        approx_min = min(g["approx"])   # approx 역은 baseline과 가까워야 — 최악(min)으로 확인
        differ_max = max(g["differ"])   # differ 역은 baseline과 달라야 — 최악(max)으로 확인
        gap = approx_min - differ_max
        if approx_min >= gate and gap > max(noise, _STATIC_EPS):  # 방향 일치 + 노이즈 초과
            reproduced = len(g["approx"]) >= 2 and len(g["differ"]) >= 2  # true·false 둘 다 반복 존재
            hits.append((pid, gap, approx_min, differ_max, reproduced))

    if not hits:
        return [_family_finding(family, "safe", "pair 내 expected 방향 분기 없음(노이즈 이내)")]

    best_pid, best_gap, best_approx, best_differ, best_repro = max(hits, key=lambda h: h[1])
    confirmed = len(hits) >= MIN_REPEAT_CONFIRM and best_repro
    confidence = "high" if confirmed else "medium"
    status = "confirmed" if confirmed else "suspected - 재현성/컨텍스트 부족, 추가 검증 필요"
    evidence = (
        f"Boolean SQLi ({status}): {len(hits)}개 pair에서 expected 방향대로 분기 "
        f"(approx={best_approx:.3f}, differ={best_differ:.3f}, gap={best_gap:.3f}, noise={noise:.3f})"
    )
    rep = next((m for m in attacks if _bcase(m, "pair_id") == best_pid), attacks[0])
    return [_finding(family, rep, confidence, evidence, "vulnerable")]


def _elapsed(result: dict) -> float:
    return float(result.get("elapsed") or 0.0)


# Time(#10): 성공 mutation을 pair_id별로 묶고 step으로 attack·control 분리, iteration을 키로 elapsed 수집
def _build_time_pairs(mutations: list[dict]) -> list[TimePairInput]:
    groups: dict[str, dict[str, dict[int, float]]] = defaultdict(lambda: {"attack": {}, "control": {}})
    for m in mutations:
        pid, step, it = _bcase(m, "pair_id"), _bcase(m, "step"), _bcase(m, "iteration")
        if pid is None or step not in ("attack", "control") or it is None:
            continue
        groups[str(pid)][step][int(it)] = _elapsed(m)
    return [TimePairInput(pid, g["attack"], g["control"]) for pid, g in groups.items()]


def _slowest_attack(mutations: list[dict]) -> dict:  # 증거 case — attack 중 가장 느린 것
    attacks = [m for m in mutations if _bcase(m, "step") == "attack"]
    return max(attacks or mutations, key=_elapsed)


def _analyze_sqli(family: dict) -> list[Finding]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family)

    baseline = family.get("baseline") or {}
    baseline_body = _body(baseline)
    raw_mutations = family.get("mutations") or []
    mutations = [item for item in raw_mutations if _successful(item)]

    # 성공한 공격 응답이 없음: 공격이 있었는데 전부 전송 실패면 검사 미완료(safe 금지), 애초에 없었으면 스킵
    if not mutations:
        if raw_mutations:
            return [_family_finding(family, "inconclusive", "공격 요청 전송 실패로 검사 미완료")]
        return []

    if technique.startswith("time"):
        verdict = judge_time_based_sqli(_build_time_pairs(mutations))
        if verdict.final_status == "vulnerable":
            return [_finding(family, _slowest_attack(mutations), verdict.confidence, verdict.evidence, "vulnerable")]
        return [_family_finding(family, verdict.final_status, verdict.evidence)]  # safe 또는 inconclusive

    # UNION 계열: 컬럼 수 불일치 DB 에러 시그니처가 공격 응답에만 있으면 취약, 없으면 안전 (2분기, 정보추출 없음)
    if technique == "union":
        for mutation in mutations:
            verdict = judge_union_sqli(baseline_body, _body(mutation))
            if verdict.vulnerable:
                return [_finding(family, mutation, verdict.confidence, verdict.evidence, "vulnerable")]
        return [_family_finding(family, "safe", "UNION 에러 시그니처 없음")]

    # error 계열: 마커 값 노출이면 vulnerable, 아니면 safe. error_extract technique는 extraction으로 분기
    judgment = "extraction" if technique == "error_extract" else str(family.get("judgment") or "structural")
    marker = family.get("extract_marker") or EXTRACT_MARKER
    for mutation in mutations:
        verdict = judge_error_based_sqli(
            baseline_body, _body(mutation), extract_marker=marker, judgment=judgment,
            payload=_payload_of(mutation),
        )
        if verdict.final_status == "vulnerable":
            return [_finding(family, mutation, verdict.confidence, verdict.evidence, "vulnerable")]
    return [_family_finding(family, "safe", "DB 에러·마커 시그니처 없음")]


def analyze_family(family: dict) -> list[Finding]:
    if str(family.get("vuln_type") or "").lower() != "sqli":
        return []
    # baseline 전송 실패 → 비교 기준 없음 → 검사 미완료 (safe 금지)
    if not _successful(family.get("baseline")):
        return [_family_finding(family, "inconclusive", "baseline 전송 실패로 비교 불가")]
    return _analyze_sqli(family)
