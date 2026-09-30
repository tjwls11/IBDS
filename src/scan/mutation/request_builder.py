from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from scan.match.matcher import AttackRule, match_and_render
from scan.match.rules_builder import get_rules
from ..models import DiscoveryResult, RequestFamily, ScanPoint
from .discovery import _CANDIDATE_SPECIALS
from .scan_point import build_scan_points
from .variant import build_baseline_case, build_mutation_case

_DOM_TECHNIQUE = "dom"  # DOM 계열: URL 소스 주입 (hash/쿼리)
_DOM_QUERY_STEP = "attack_query"  # DOM 쿼리(location.search) 소스 스텝 — 나머지 DOM 스텝은 fragment(location.hash)
_BOOLEAN_REPEAT = 2  # boolean 동일 조건 재검증용 반복 횟수 — 같은 (pair_id, role)을 이 횟수만큼 전송
_BOOL_STEP_META: dict[str, tuple[str, str, str]] = {
    "and_true":  ("and", "attack_true",  "approx_baseline"),
    "and_false": ("and", "attack_false", "differ_baseline"),
    "or_true":   ("or",  "attack_true",  "differ_baseline"),
    "or_false":  ("or",  "attack_false", "approx_baseline"),
    "control":   ("control", "control",  "approx_baseline"),
}
_TIME_STEP_ROLE: dict[str, str] = {"attack": "attack", "control": "control"}


def _short_step(step: str) -> str:
    s = step.removesuffix("attack").rstrip("_")
    return s or "a"


# ScanPoint 하나 + 룰 목록 -> RequestFamily 목록. payload_filter가 있으면 조건을 만족하는 payload만 mutation으로 남김
def build_families_for_point(
    sp: ScanPoint,
    target: dict,
    rules: list[AttackRule],
    payload_filter: Callable[[str], bool] | None = None,
    dynamic_markers: list[tuple[str, str]] | None = None,
    baseline_match_ratio: float | None = None,
    with_fragment: bool = True,
) -> list[RequestFamily]:
    families: list[RequestFamily] = []

    for matched in match_and_render(sp, rules):
        family_id = f"{sp.target_id}_{sp.tag}_{matched.attack_id}"
        baseline = build_baseline_case(target, sp.location, f"{family_id}_baseline")
        is_dom = matched.technique == _DOM_TECHNIQUE

        mutations = []
        p_idx = 0
        seen_cases: set[tuple] = set()
        for step in matched.sequence:
            if step == "baseline":
                continue
            bool_meta = _BOOL_STEP_META.get(step) if matched.technique == "boolean" else None
            # DOM 소스 분기: attack=fragment(location.hash), attack_query=쿼리(location.search)로 주입
            inject_frag = is_dom and step != _DOM_QUERY_STEP
            if inject_frag and not with_fragment:
                continue
            time_role = _TIME_STEP_ROLE.get(step) if matched.technique.startswith("time") else None
            for ctx_idx, payload in enumerate(matched.rendered_payloads.get(step, [])):
                if payload_filter is not None and not payload_filter(payload):
                    continue  # Discovery 결과 등으로 실행 불가능하다고 판단된 payload 제외
                repeats = _BOOLEAN_REPEAT if bool_meta else 1
                for repeat_index in range(repeats):
                    case = build_mutation_case(
                        target, sp.location, sp.name, sp.original_value,
                        payload, step, f"{family_id}_{_short_step(step)}{p_idx}",
                        value_index=sp.value_index, inject_fragment=inject_frag,
                    )
                    if bool_meta:
                        group, role, expected = bool_meta
                        case.pair_id = f"{family_id}_{group}_c{ctx_idx}"
                        case.role = role
                        case.expected = expected
                        case.repeat_index = repeat_index
                    elif time_role:
                        case.pair_id = f"{family_id}_time_c{ctx_idx}"
                        case.role = time_role
                        case.repeat_index = repeat_index
                    key = (case.url, case.body, tuple(sorted(case.headers.items())), case.pair_id, case.role, case.repeat_index)  # 헤더 지점은 URL, 본문이 같아 헤더도 키에 포함
                    if key in seen_cases:
                        continue
                    seen_cases.add(key)
                    mutations.append(case)
                    p_idx += 1

        if not mutations:
            continue  # 살아남은 payload가 없으면 family 자체 미생성

        families.append(RequestFamily(
            family_id=family_id,
            target_id=sp.target_id,
            param=sp.name,
            attack_id=matched.attack_id,
            vuln_type=matched.vuln_type,
            technique=matched.technique,
            baseline=baseline,
            mutations=mutations,
            location=sp.location,
            value_index=sp.value_index,
            dynamic_markers=dynamic_markers or [],
            baseline_match_ratio=baseline_match_ratio,
        ))

    return families


# 타겟 목록 -> 모든 ScanPoint에 룰을 매칭해 RequestFamily 목록 생성 (기존 배치 진입점, 동작 변화 없음)
def generate_families(
    targets_path: str | Path,
    vuln_types: list[str] | None = None,
) -> list[RequestFamily]:
    with open(targets_path, encoding="utf-8") as f:
        targets = json.load(f)

    rules = get_rules()
    if vuln_types is not None:
        rules = [r for r in rules if r.vuln_type in vuln_types]

    target_by_id = {f"t{idx}": target for idx, target in enumerate(targets)}
    scan_points = build_scan_points(targets)

    families: list[RequestFamily] = []
    for sp in scan_points:
        families.extend(build_families_for_point(sp, target_by_id[sp.target_id], rules))
    return families


# payload 문자열에 실제로 등장하는 특수문자 집합 — 이 payload가 살아남으려면 필요한 최소 조건
def _required_specials(payload: str) -> set[str]:
    return {ch for ch in _CANDIDATE_SPECIALS if ch in payload}


# injection_context -> 유효한 technique 집합 매핑 (dom은 context 무관하게 항상 포함)
# "suppressed"는 명시적으로 빈 집합 -> dom 외 모든 technique 억제
_CONTEXT_TECHNIQUES: dict[str, set[str]] = {
    "inHTML":     {"body", "html_comment", "filter_bypass", "template", "json", "css"},
    "inAttr":     {"attr_value", "attr_event"},
    "inAttrUrl":  {"attr_href"},
    "inScript":   {"script", "script_raw", "attr_event"},
    "inRawText":  {"raw_text_escape"},
    "suppressed": set(),
}


# fragment는 파라미터와 무관한 URL 단위 소스 → 타겟의 첫 스캔 지점에서만 생성 (파라미터 수만큼 중복 방지)
def _owns_fragment(sp: ScanPoint, target: dict) -> bool:
    first = next(iter(build_scan_points([target])), None)
    return first is not None and (first.name, first.value_index) == (sp.name, sp.value_index)


# XSS family 생성 — DOM 계열과 reflected 계열을 서버 반사 종속성 기준으로 분리 (#2)
def generate_xss_families(sp: ScanPoint, target: dict, discovery: DiscoveryResult) -> list[RequestFamily]:
    families: list[RequestFamily] = []

    # DOM 계열: URL 소스라 GET 쿼리 지점에서만 생성(POST+쿼리는 헤드리스 GET 확인 불가라 제외), 필터 미적용
    if sp.location == "query" and (sp.method or "GET") == "GET":
        dom_rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique == _DOM_TECHNIQUE]
        families.extend(build_families_for_point(sp, target, dom_rules, with_fragment=_owns_fragment(sp, target)))

    # reflected 계열: 입력이 서버 응답에 반사돼야 의미가 있음 → 반사가 없으면 생성 안 함.
    if discovery.reflected:
        rules = [r for r in get_rules()
                 if r.vuln_type == "xss" and r.technique not in ("stored", _DOM_TECHNIQUE)]
        if discovery.injection_context is not None:
            valid = _CONTEXT_TECHNIQUES.get(discovery.injection_context, set())
            rules = [r for r in rules if r.technique in valid]
        families.extend(build_families_for_point(
            sp, target, rules,
            payload_filter=lambda payload: _required_specials(payload).issubset(discovery.valid_specials),
        ))

    return families




# Stored XSS — Discovery 없이, form(POST) 파라미터에만, PL-XSS-STORED 룰만 적용
def generate_stored_xss_families(sp: ScanPoint, target: dict) -> list[RequestFamily]:
    if sp.location != "form":
        return []
    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique == "stored"]
    return build_families_for_point(sp, target, rules)


# SQLi
def generate_sqli_families(
    sp: ScanPoint,
    target: dict,
    dynamic_markers: list[tuple[str, str]] | None = None,
    baseline_match_ratio: float | None = None,
) -> list[RequestFamily]:
    rules = [r for r in get_rules() if r.vuln_type == "sqli"]
    return build_families_for_point(
        sp, target, rules, dynamic_markers=dynamic_markers, baseline_match_ratio=baseline_match_ratio,
    )


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    result = generate_families(t_path)
    print(json.dumps([asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)