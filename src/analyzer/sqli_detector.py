from __future__ import annotations

import os
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any

from utilities.file_utils import load_json
from .finding import Finding
from .final_status import POTENTIAL_HIGH, POTENTIAL_MEDIUM, POTENTIAL_LOW, INCONCLUSIVE
from .sqli.judge import (
    EXTRACT_MARKER,
    MIN_REPEAT_CONFIRM,
    judge_error_based_sqli,
    judge_time_based_sqli,
    _strip_dynamic,
    _strip_value,
)

# Boolean 판정 문턱
_TRUE_GATE = 0.85
_GATE_MARGIN = 0.05
_STATIC_EPS = 0.002

# SQLi 판정 단계, 누적: E0 단순비교 < E1 기준2회 < E2 대조 < E3 반복
_DEFAULT_STAGE = 3
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")


# 설정에서 단계 읽기 ("E0"~"E3" 또는 0~3). 없으면 전체(E3) — 기존 동작 유지
def _load_stage() -> int:
    raw = load_json(_TARGET_CONFIG, default={}).get("sqli_stage", _DEFAULT_STAGE)
    try:
        return max(0, min(3, int(str(raw).upper().lstrip("E"))))
    except (ValueError, TypeError):
        return _DEFAULT_STAGE


def _successful(result: dict | None) -> bool:
    return bool(result) and result.get("send_status") == "ok"


def _body(result: dict | None) -> str:
    if result is None or not _successful(result):
        return ""
    return result.get("response_body") or ""


def _finding(family: dict, result: dict, confidence: str, evidence: str, final_status: str = INCONCLUSIVE) -> Finding:
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
        value_index=family.get("value_index"),
        payload=case.get("payload"),
        raw_verdict={
            "vulnerable": final_status in (POTENTIAL_HIGH, POTENTIAL_MEDIUM),
            "confidence": confidence, "evidence": evidence,
        },
        headless_checked=False,
        headless_verdict=None,
        final_status=final_status,
    )


def _payload_of(mutation: dict) -> str:
    return str((mutation.get("case") or {}).get("payload") or "")


def _clean_body(family: dict, result: dict | None, strip_dynamic: bool = True) -> str:
    # payload 반사분 제거(항상) + dynamic_markers 제거(E1 이상)
    body = _strip_value(_body(result), _payload_of(result or {}))
    if strip_dynamic:
        body = _strip_dynamic(body, family.get("dynamic_markers") or [])
    return body


# safe, inconclusive finding의 식별 필드
def _representative_result(family: dict) -> dict:
    mutations = family.get("mutations") or []
    return mutations[0] if mutations else (family.get("baseline") or {})


def _family_finding(family: dict, final_status: str, evidence: str) -> Finding:
    return _finding(family, _representative_result(family), "", evidence, final_status)


def _bcase(mutation: dict, key: str) -> Any:  # MutationCase의 SQLi 비교 계약 필드 접근
    return (mutation.get("case") or {}).get(key)


def _is_time_control(mutation: dict) -> bool:
    role = _bcase(mutation, "role")
    if role is not None:
        return role == "control"
    return str(_bcase(mutation, "step") or "") == "control"


def _sim(base_clean: str, family: dict, mutation: dict, strip_dynamic: bool = True) -> float:
    return SequenceMatcher(None, base_clean, _clean_body(family, mutation, strip_dynamic)).ratio()


# Boolean : pair_id로 묶어 expected 방향 비교, control로 노이즈 게이트, repeat로 재현성 확인
def _analyze_boolean(family: dict, stage: int = _DEFAULT_STAGE) -> list[Finding]:
    strip_dyn = stage >= 1       # E1: 동적 영역 제거
    use_bmr = stage >= 1         # E1: 기준 2회 유사도 문턱
    use_noise = stage >= 2       # E2: 대조 노이즈
    require_repeat = stage >= 3  # E3: 반복 재현 요구

    base_clean = _clean_body(family, family.get("baseline"), strip_dyn)
    muts = [m for m in family.get("mutations", []) if _successful(m)]
    attacks = [m for m in muts if _bcase(m, "role") in ("attack_true", "attack_false")]

    # pair 필드가 없거나 성공한 공격 응답이 없으면 검사 미완료
    if not base_clean or not attacks:
        return [_family_finding(family, INCONCLUSIVE, "boolean pair 요청이 없거나 성공한 요청이 없어 검사 미완료")]

    # control(비-SQL 잡음)로 노이즈 바닥 측정 — 입력만 바꿔도 흔들리는 페이지면 노이즈가 큼 (E2 이상)
    control_scores = [_sim(base_clean, family, m, strip_dyn) for m in muts if _bcase(m, "role") == "control"]
    noise = (1.0 - min(control_scores)) if (use_noise and control_scores) else 0.0

    bmr = family.get("baseline_match_ratio")
    gate = max(0.0, bmr - _GATE_MARGIN) if (use_bmr and bmr is not None) else _TRUE_GATE

    # pair_id별로 expected 방향에 따라 점수 수집 (repeat 포함)
    pairs: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"approx": [], "differ": []})
    for m in attacks:
        exp = _bcase(m, "expected")
        score = _sim(base_clean, family, m, strip_dyn)
        if exp == "approx_baseline":
            pairs[_bcase(m, "pair_id")]["approx"].append(score)
        elif exp == "differ_baseline":
            pairs[_bcase(m, "pair_id")]["differ"].append(score)

    hits: list[tuple[str, float, float, float, bool]] = []  # (pair_id, gap, approx_min, differ_max, reproduced)
    for pid, g in pairs.items():
        if not g["approx"] or not g["differ"]:
            continue  # 한쪽만 성공한 pair는 판정 불가 -> 스킵
        approx_min = min(g["approx"])   # approx 역은 baseline과 가까워야 최악(min)으로 확인
        differ_max = max(g["differ"])   # differ 역은 baseline과 달라야 최악(max)으로 확인
        gap = approx_min - differ_max
        if approx_min >= gate and gap > max(noise, _STATIC_EPS):  # 방향 일치 + 노이즈 초과
            reproduced = len(g["approx"]) >= 2 and len(g["differ"]) >= 2  # true, false 둘 다 반복 존재
            hits.append((pid, gap, approx_min, differ_max, reproduced))

    if not hits:
        return [_family_finding(family, POTENTIAL_LOW, "pair 내 expected 방향 분기 안보임(노이즈 이내)")]

    best_pid, best_gap, best_approx, best_differ, best_repro = max(hits, key=lambda h: h[1])
    # E3: 여러 pair 적중 + 반복 재현까지 요구 / E2 이하: 방향 분기만으로 high (재현 요구 안 함)
    confirmed = (len(hits) >= MIN_REPEAT_CONFIRM and best_repro) if require_repeat else True
    confidence = "high" if confirmed else "medium"
    status = "confirmed" if confirmed else "suspected - 재현성/컨텍스트 부족, 추가 검증 필요"
    evidence = (
        f"Boolean SQLi ({status}): {len(hits)}개 pair에서 expected 방향대로 분기 "
        f"(approx={best_approx:.3f}, differ={best_differ:.3f}, gap={best_gap:.3f}, noise={noise:.3f})"
    )
    rep = next((m for m in attacks if _bcase(m, "pair_id") == best_pid), attacks[0])
    return [_finding(family, rep, confidence, evidence, POTENTIAL_HIGH if confirmed else POTENTIAL_MEDIUM)]


# 무신호 종결 상태. 공격 일부가 전송 실패했으면 미검사 구간이 있어 POTENTIAL_LOW 금지 → inconclusive
def _no_signal_status(raw_mutations: list, mutations: list, evidence: str) -> tuple[str, str]:
    failed = len(raw_mutations) - len(mutations)
    if failed > 0:
        return INCONCLUSIVE, f"{evidence} — 공격 {failed}건 전송 실패로 미검사 구간 있음(POTENTIAL_LOW 금지)"
    return POTENTIAL_LOW, evidence


def _analyze_sqli(family: dict, stage: int = _DEFAULT_STAGE) -> list[Finding]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family, stage)

    baseline = family.get("baseline") or {}
    raw_mutations = family.get("mutations") or []
    mutations = [item for item in raw_mutations if _successful(item)]

    # 성공한 공격 응답이 없음: 공격이 있었는데 전부 전송 실패면 검사 미완료, 애초에 없었으면 스킵
    if not mutations:
        if raw_mutations:
            return [_family_finding(family, INCONCLUSIVE, "공격 요청 전송 실패로 검사 미완료")]
        return []

    if technique.startswith("time"):
        attack_muts = [m for m in mutations if not _is_time_control(m)]
        control_muts = [m for m in mutations if _is_time_control(m)]
        if not attack_muts:
            return [_family_finding(family, INCONCLUSIVE, "공격 요청 전송 실패로 검사 미완료 (대조 요청만 성공)")]
        baseline_elapsed = float(baseline.get("elapsed") or 0.0)
        attack_elapsed = [float(m.get("elapsed") or 0.0) for m in attack_muts]
        # E2: sleep0 대조로 기준 시간 보정, E3: 지연 반복 재현 요구
        control_elapsed = [float(m.get("elapsed") or 0.0) for m in control_muts] if stage >= 2 else []
        verdict = judge_time_based_sqli(baseline_elapsed, attack_elapsed, control_elapsed,
                                        require_repeat=stage >= 3)
        if verdict.vulnerable:
            slowest = max(attack_muts, key=lambda m: float(m.get("elapsed") or 0.0))
            return [_finding(family, slowest, verdict.confidence, verdict.evidence, verdict.final_status)]
        return [_family_finding(family, POTENTIAL_LOW, verdict.evidence)]

    baseline_body = _body(baseline)

    # error 계열(union 포함): 추출 마커 확인 시 HIGH, baseline엔 없던 DB 에러만 노출 시 MEDIUM.
    # union의 컬럼 수 불일치 시그니처는 DB_ERROR_KEYWORDS에 이미 포함돼 있어 여기로 합류.
    # error_extract technique는 extraction으로 분기
    judgment = "extraction" if technique == "error_extract" else str(family.get("judgment") or "structural")
    marker = family.get("extract_marker") or EXTRACT_MARKER
    medium_hit = None
    for mutation in mutations:
        verdict = judge_error_based_sqli(
            baseline_body, _body(mutation), extract_marker=marker, judgment=judgment,
            payload=_payload_of(mutation),
        )
        if verdict.final_status == POTENTIAL_HIGH:
            return [_finding(family, mutation, verdict.confidence, verdict.evidence, POTENTIAL_HIGH)]
        if verdict.final_status == POTENTIAL_MEDIUM and medium_hit is None:
            medium_hit = (mutation, verdict)
    if medium_hit is not None:
        mutation, verdict = medium_hit
        return [_finding(family, mutation, verdict.confidence, verdict.evidence, POTENTIAL_MEDIUM)]
    status, evidence = _no_signal_status(raw_mutations, mutations, "DB 에러, 마커 시그니처 없음")
    return [_family_finding(family, status, evidence)]


def analyze_family(family: dict, stage: int | None = None) -> list[Finding]:
    if stage is None:  # 명시 안 하면 설정값(기본 E3) — 실험 때는 단계를 직접 넘겨 재판정
        stage = _load_stage()
    if str(family.get("vuln_type") or "").lower() != "sqli":
        return []
    if not _successful(family.get("baseline")):
        return [_family_finding(family, INCONCLUSIVE, "기준값 전송 실패로 비교 불가")]
    return _analyze_sqli(family, stage)
