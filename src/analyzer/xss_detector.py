from __future__ import annotations

import json
import os
from dataclasses import asdict

from utilities.file_utils import append_jsonl
from .finding import Finding
from .final_status import POTENTIAL_HIGH, POTENTIAL_MEDIUM, POTENTIAL_LOW, INCONCLUSIVE
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


# headless가 실행 인정 시 요구할 토큰 — case마다 고유 (None이면 dialog가 떠도 실행 미인정)
def _expected_token(case: dict) -> str | None:
    return case.get("exec_token")


# headless 결과 반영한 최종 상태 (reflected/DOM 공용). 반사 확인+실행 미확인은 MEDIUM, 검증 미완료는 inconclusive
def _final_status(headless_checked: bool, hv: HeadlessVerdict | None, raw_reflected: bool) -> str:
    if not headless_checked:
        return POTENTIAL_LOW  # raw 판정만으로 실행가능 반사 없음 (headless 대상 아님)
    if hv is None or not hv.ok:
        return INCONCLUSIVE  # headless 검증을 끝내지 못함 → 안전 아님
    if hv.executed:
        return POTENTIAL_HIGH
    return POTENTIAL_MEDIUM if raw_reflected else POTENTIAL_LOW  # 반사 확인 + 실행 미확인 -> 취약 신호 관찰


# inconclusive 사유 결정 - 시도 결과에 먼저 기록된 사유 우선, 판정 단계 사유는 reason_note로 보충
def _inconclusive_reason(case_result: dict, own: str | None) -> tuple[str | None, str | None]:
    prior = case_result.get("reason")
    if prior and own and prior != own:
        return prior, own
    return prior or own, None


# Finding 생성 헬퍼 (stored 분기용) — raw/headless 없으면 기본값 채움
def _mk_finding(family: dict, case_result: dict, final_status: str, *, raw=None, hv=None, evidence: str = "",
                reason: str | None = None) -> Finding:
    case = case_result["case"]
    if final_status == INCONCLUSIVE:
        reason, reason_note = _inconclusive_reason(case_result, reason)
    else:  # 판정은 났지만 귀속 불가 경고창이 있었던 경우만 사유 기록
        reason, reason_note = (hv.reason if hv else None), None
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
        value_index=family.get("value_index"),  # 지점 식별용
        payload=case.get("payload"),
        raw_verdict=asdict(raw) if raw else {"vulnerable": False, "confidence": "", "evidence": evidence},
        headless_checked=hv is not None,
        headless_verdict=asdict(hv) if hv else None,
        final_status=final_status,
        reason=reason,
        reason_note=reason_note,
    )



# stored 판정: 재조회 diff → 새 영역(추가된 줄)만 judge_xss → 실제 발화(navigate)
def _judge_stored(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    payload = case.get("payload") or ""

    # 마커 반사 미확인 -> inconclusive
    if not family.get("sink_confirmed"):
        return _mk_finding(family, case_result, INCONCLUSIVE, evidence="sink 미확인", reason="sink_not_confirmed")

    before = case_result.get("before_revisit_body") or ""
    after = case_result.get("revisit_body") or ""

    # 재조회 성공했는데 payload 없음(저장 안 됨) -> 등록 응답 에코를 headless로 실제 발화 확인
    # 저장 자체가 확인 안 됐으므로 발화 여부와 무관하게 POTENTIAL_HIGH는 못 감
    if case_result.get("revisit_found") is False:
        # 재조회 응답 자체가 무효(403/500 등)면 재조회 실패
        if not _is_valid_revisit_status(case_result.get("revisit_status")):
            return _mk_finding(family, case_result, INCONCLUSIVE, reason="revisit_failed",
                                evidence=f"재조회 응답 무효(상태 코드 {case_result.get('revisit_status')})")
        echo = judge_xss(case_result.get("response_body") or "", payload) if payload else None
        if echo and echo.vulnerable:
            # 등록 응답을 원래 URL, 응답 헤더(CSP, Content-Type) 그대로 render해서 실제 발화 확인
            hv = headless.confirm_via_render(
                case_result.get("response_body") or "",
                url=case["url"], headers=case_result.get("response_headers"),
                exec_token=_expected_token(case),
            )
            if not hv.ok:  # 렌더링 실패
                return _mk_finding(family, case_result, INCONCLUSIVE, raw=echo, hv=hv, reason=hv.reason)
            # 등록 응답에 반사 확인, 저장 미확인 -> 실행되면 MEDIUM(반사형 신호), 아니면 LOW
            return _mk_finding(family, case_result, POTENTIAL_MEDIUM if hv.executed else POTENTIAL_LOW, raw=echo, hv=hv)
        # 에코 없음 / escape로 raw 미적중
        return _mk_finding(family, case_result, POTENTIAL_LOW, evidence="재조회에 공격 요청 안보임")

    # 재조회 자체 실패(revisit_found None 등)로 payload 확인 불가 -> inconclusive
    if not payload or payload not in after:
        return _mk_finding(family, case_result, INCONCLUSIVE, evidence="재조회 N회 실패(payload 미확인)", reason="revisit_failed")

    # diff로 새로 생긴 영역(추가된 줄) 추출
    new_region = diff_new_region(before, after)
    if not new_region:
        return _mk_finding(family, case_result, POTENTIAL_LOW, evidence="diff 새 영역 없음(잔재)")

    # 추가된 줄(새 영역)만 judge_xss에 넘김 (마커로 payload 유일 -> 새 줄에 잡힘)
    raw = judge_xss(new_region, payload)
    if not raw.vulnerable:
        return _mk_finding(family, case_result, POTENTIAL_LOW, raw=raw, evidence="새 영역에 실행가능 반사 없음")

    # 이 case 직후의 재조회 스냅샷을 렌더링해 실행 확인 (지금 다시 열면 덮어쓰는 필드는 마지막 case 값만 남음)
    hv = headless.confirm_via_render(
        after,
        url=case_result.get("revisit_url_used") or case["url"],
        headers=case_result.get("revisit_headers") or {"content-type": "text/html; charset=utf-8"},
        exec_token=_expected_token(case),
    )
    if not hv.ok:  # navigate 검증 실패 -> 확인 불가 (POTENTIAL_HIGH/LOW로 확정 금지)
        return _mk_finding(family, case_result, INCONCLUSIVE, raw=raw, hv=hv, reason=hv.reason)
    # 저장 확인(diff)됨 + 반사 확인 -> 실행되면 HIGH, 실행 미확인이면 MEDIUM(취약 신호 관찰)
    return _mk_finding(family, case_result, POTENTIAL_HIGH if hv.executed else POTENTIAL_MEDIUM, raw=raw, hv=hv)


# mutation case 1건에 대한 raw 판정 + (필요시) headless 확인
def judge_case(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    technique = family["technique"]
    payload = case.get("payload") or ""

    if case_result.get("send_status") == "error":  # 요청 자체가 실패한 case는 판정 불가
        reason = case_result.get("reason") or "attack_request_failed"  # 전송 단계 사유 그대로
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
            reason=reason,
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
                exec_token=_expected_token(case),
            )
        else:  # 원래 URL, 응답 헤더(CSP, Content-Type) 그대로 render
            headless_verdict = headless.confirm_via_render(
                case_result.get("response_body") or "",
                url=case["url"], headers=case_result.get("response_headers"),
                exec_token=_expected_token(case),
            )

    final_status = _final_status(headless_checked, headless_verdict, raw_verdict.vulnerable)
    hv_reason = headless_verdict.reason if headless_verdict else None
    if final_status == INCONCLUSIVE:
        reason, reason_note = _inconclusive_reason(case_result, hv_reason or "browser_failed")
    else:  # 판정은 났지만 귀속 불가 경고창이 있었던 경우만 사유 기록
        reason, reason_note = hv_reason, None

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
        final_status=final_status,
        # 쿼리 값은 서버로 전송되므로, 응답에 반사됐다면 JS(DOM)가 아니라 서버 반사로 발화한 것
        # (fragment는 서버로 안 가서 해당 없음, technique은 생성 추적용으로 dom 유지)
        server_reflected=technique == _DOM_TECHNIQUE and case.get("body_type") == "query"
                         and raw_verdict.vulnerable,
        reason=reason,
        reason_note=reason_note,
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
