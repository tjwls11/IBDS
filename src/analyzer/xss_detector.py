from __future__ import annotations

import json
import os
from dataclasses import asdict

from scan.match.exec_token import exec_token
from utilities.file_utils import append_jsonl
from .finding import Finding
from .final_status import POTENTIAL_HIGH, POTENTIAL_LOW, INCONCLUSIVE
from .xss.headless import HeadlessSession, HeadlessVerdict
from .xss.revisit import diff_new_region
from .xss.judge import judge_xss

_DOM_TECHNIQUE = "dom"
_STORED_TECHNIQUE = "stored"


# 재조회 응답이 유효한지
def _is_valid_revisit_status(status) -> bool:
    return isinstance(status, int) and 200 <= status < 400


# raw 판정에서 걸렸거나 raw로는 원천적으로 확인이 안 되는 기법(dom)이면 headless 대상
def _is_headless_target(vulnerable: bool, technique: str) -> bool:
    return vulnerable or technique == _DOM_TECHNIQUE


# 이 payload에 대해 headless가 실행 인정 시 요구할 토큰
def _expected_token(payload: str) -> str | None:
    tok = exec_token()
    return tok if tok in (payload or "") else None


# headless 확인 결과까지 반영한 최종 상태 판정 (reflected/DOM 공용).
# XSS는 표현 확정본상 MEDIUM이 없음 — 실행 미확인은 반사 여부와 무관하게 POTENTIAL_LOW로 통일
def _final_status(headless_checked: bool, hv: HeadlessVerdict | None) -> str:
    if not headless_checked:
        return POTENTIAL_LOW  # raw 판정만으로 실행가능 반사 없음 (headless 대상 아님)
    if hv is None or not hv.ok:
        return INCONCLUSIVE  # headless 검증을 끝내지 못함 → 안전 아님
    return POTENTIAL_HIGH if hv.executed else POTENTIAL_LOW


# Finding 생성 헬퍼 (stored 분기용) — raw/headless 없으면 기본값 채움
def _mk_finding(family: dict, case: dict, final_status: str, *, raw=None, hv=None, evidence: str = "") -> Finding:
    return Finding(
        vuln_type="xss",
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=family["technique"],
        case_id=case["case_id"],
        method=case.get("method"),
        url=case.get("url"),
        location=case.get("body_type"),
        value_index=family.get("value_index"),  # #25 지점 식별 계약
        payload=case.get("payload"),
        raw_verdict=asdict(raw) if raw else {"vulnerable": False, "confidence": "", "evidence": evidence},
        headless_checked=hv is not None,
        headless_verdict=asdict(hv) if hv else None,
        final_status=final_status,
    )



# stored 판정: 재조회 diff → 새 영역(추가된 줄)만 judge_xss → 실제 발화(navigate)
def _judge_stored(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    payload = case.get("payload") or ""

    # 마커 반사 미확인 -> inconclusive
    if not family.get("sink_confirmed"):
        return _mk_finding(family, case, INCONCLUSIVE, evidence="sink 미확인")

    before = case_result.get("before_revisit_body") or ""
    after = case_result.get("revisit_body") or ""

    # 재조회 성공했는데 payload 없음(저장 안 됨) -> 등록 응답 에코를 headless로 실제 발화 확인
    # 저장 자체가 확인 안 됐으므로 발화 여부와 무관하게 POTENTIAL_HIGH는 못 감
    if case_result.get("revisit_found") is False:
        # 재조회 응답 자체가 무효(403/500 등)면 재조회 실패
        if not _is_valid_revisit_status(case_result.get("revisit_status")):
            return _mk_finding(family, case, INCONCLUSIVE,
                                evidence=f"재조회 응답 무효(상태 코드 {case_result.get('revisit_status')})")
        echo = judge_xss(case_result.get("response_body") or "", payload) if payload else None
        if echo and echo.vulnerable:
            # 등록 응답을 원래 URL, 응답 헤더(CSP, Content-Type) 그대로 render해서 실제 발화 확인
            hv = headless.confirm_via_render(
                case_result.get("response_body") or "",
                url=case["url"], headers=case_result.get("response_headers"),
                exec_token=_expected_token(payload),
            )
            if not hv.ok:  # 렌더링 실패
                return _mk_finding(family, case, INCONCLUSIVE, raw=echo, hv=hv)
            # 등록 응답에 실행가능 반사는 있으나 저장 미확인 -> LOW
            return _mk_finding(family, case, POTENTIAL_LOW, raw=echo, hv=hv)
        # 에코 없음 / escape로 raw 미적중
        return _mk_finding(family, case, POTENTIAL_LOW, evidence="재조회에 공격 요청 안보임")

    # 재조회 자체 실패(revisit_found None 등)로 payload 확인 불가 -> inconclusive
    if not payload or payload not in after:
        return _mk_finding(family, case, INCONCLUSIVE, evidence="재조회 N회 실패(payload 미확인)")

    # diff로 새로 생긴 영역(추가된 줄) 추출
    new_region = diff_new_region(before, after)
    if not new_region:
        return _mk_finding(family, case, POTENTIAL_LOW, evidence="diff 새 영역 없음(잔재)")

    # 추가된 줄(새 영역)만 judge_xss에 넘김 (마커로 payload 유일 -> 새 줄에 잡힘)
    raw = judge_xss(new_region, payload)
    if not raw.vulnerable:
        return _mk_finding(family, case, POTENTIAL_LOW, raw=raw, evidence="새 영역에 실행가능 반사 없음")

    hv = headless.confirm_via_navigate(        # 실제 발화 확인 — revisit 페이지를 headless로 열어봄
        case_result.get("revisit_url_used") or case["url"],
        case_result.get("effective_cookies") or {},
        "GET",
        exec_token=_expected_token(payload),
    )
    if not hv.ok:  # navigate 검증 실패 -> 확인 불가 (POTENTIAL_HIGH/LOW로 확정 금지)
        return _mk_finding(family, case, INCONCLUSIVE, raw=raw, hv=hv)
    # 저장 확인(diff)됨 -> 실행 확인 여부로 HIGH/LOW만 갈림
    return _mk_finding(family, case, POTENTIAL_HIGH if hv.executed else POTENTIAL_LOW, raw=raw, hv=hv)


# mutation case 1건에 대한 raw 판정 + (필요시) headless 확인
def judge_case(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    technique = family["technique"]
    payload = case.get("payload") or ""

    if case_result.get("status") == "error":  # 요청 자체가 실패한 case는 판정 불가
        return Finding(
            vuln_type="xss",
            family_id=family["family_id"],
            target_id=family["target_id"],
            param=family["param"],
            attack_id=family["attack_id"],
            technique=technique,
            case_id=case["case_id"],
            method=case.get("method"),
            url=case.get("url"),
            location=case.get("body_type"),
            value_index=family.get("value_index"),
            payload=case.get("payload"),
            raw_verdict={"vulnerable": False, "confidence": "", "evidence": "요청 실패로 판정 불가"},
            headless_checked=False,
            headless_verdict=None,
            final_status=INCONCLUSIVE,
        )

    if technique == _STORED_TECHNIQUE:  # stored는 재조회 diff 게이트 경로로 분기
        return _judge_stored(family, case_result, headless)

    raw_verdict = judge_xss(case_result.get("response_body") or "", payload)
    headless_checked = _is_headless_target(raw_verdict.vulnerable, technique)

    headless_verdict = None
    if headless_checked:
        if technique == _DOM_TECHNIQUE:
            headless_verdict = headless.confirm_via_navigate(
                case["url"], case_result.get("effective_cookies") or {}, case["method"],
                exec_token=_expected_token(payload),
            )
        else:  # 원래 URL, 응답 헤더(CSP·Content-Type) 그대로 render
            headless_verdict = headless.confirm_via_render(
                case_result.get("response_body") or "",
                url=case["url"], headers=case_result.get("response_headers"),
                exec_token=_expected_token(payload),
            )

    return Finding(
        vuln_type="xss",
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=technique,
        case_id=case["case_id"],
        method=case.get("method"),
        url=case.get("url"),
        location=case.get("body_type"),
        value_index=family.get("value_index"),
        payload=case.get("payload"),
        raw_verdict=asdict(raw_verdict),
        headless_checked=headless_checked,
        headless_verdict=asdict(headless_verdict) if headless_verdict else None,
        final_status=_final_status(headless_checked, headless_verdict),
        # 쿼리 값은 서버로 전송되므로, 응답에 반사됐다면 JS(DOM)가 아니라 서버 반사로 발화한 것
        # (fragment는 서버로 안 가서 해당 없음, technique은 생성 추적용으로 dom 유지)
        server_reflected=technique == _DOM_TECHNIQUE and case.get("body_type") == "query"
                         and raw_verdict.vulnerable,
    )


# request_results.jsonl을 읽어 XSS family만 판정, xss_findings.jsonl 생성
def run(results_path: str, headless: HeadlessSession | None = None) -> str:
    out_path = os.path.join(os.path.dirname(results_path), "xss_findings.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)  # append_jsonl은 이어쓰기라 재실행 시 중복 방지

    owns_headless = headless is None
    headless = headless or HeadlessSession()
    non_xss_skipped = 0

    try:
        with open(results_path, encoding="utf-8") as f:
            for line in f:
                family = json.loads(line)
                if family["vuln_type"] != "xss":
                    non_xss_skipped += 1
                    continue
                for case_result in family["mutations"]:
                    try:  # 개별 case 판정 실패는 로그만 남기고 계속 진행
                        finding = judge_case(family, case_result, headless)
                    except Exception as e:
                        print(f"[ERROR] XSS 판정 실패: family={family['family_id']} case={case_result.get('case', {}).get('case_id')} - {e}")
                        continue
                    append_jsonl(out_path, asdict(finding))
    finally:
        if owns_headless:
            headless.close()

    print(f"[JUDGE] xss_findings.jsonl -> {out_path} ({non_xss_skipped}건 non-XSS family는 판정 로직 미연결 - 건너뜀)")
    return out_path
