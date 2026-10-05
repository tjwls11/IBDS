"""
ver2 오케스트레이터.
"""

import io
import json
import os
import sys
from dataclasses import asdict, replace
from urllib.parse import urljoin

for _stream in (sys.stdout, sys.stderr):
    if isinstance(_stream, io.TextIOWrapper):
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")

from collector.main_collector import run_collection
from scan.mutation.discovery import measure_dynamic_markers, run_discovery
from scan.mutation.request_builder import (
    FRAGMENT_LOCATION, build_fragment_points, generate_dom_fragment_families,
    generate_sqli_families, generate_stored_xss_families, generate_xss_families,
)
from scan.mutation.scan_point import build_scan_points
from scan.normalize.param_filter import has_destructive_action
from scan.requester import requester
from scan.models import CaseResult, FamilyResult, RequestFamily, ScanPoint
from scan.progress import PipelineProgress
from utilities.file_utils import append_jsonl, load_json
from analyzer import xss_detector
from analyzer.xss.headless import HeadlessSession
from analyzer.xss.revisit import probe_sink, new_run_marker_factory, refetch, is_same_host
from analyzer.sqli_detector import analyze_family

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")


# 전송 불명(delivery_unknown) case의 판정 대체 기록 — 확정본상 전송 실패는 inconclusive
def _delivery_unknown_finding(family: RequestFamily, case_id: str) -> dict:
    return {
        "family_id": family.family_id, "target_id": family.target_id,
        "param": family.param, "vuln_type": family.vuln_type, "technique": family.technique,
        "case_id": case_id, "location": family.location, "value_index": family.value_index,  # 지점 식별용
        "final_status": "inconclusive", "check_status": "incomplete", "reason": "delivery_unknown",
        "stage": "request", "evidence": "전송 실패로 서버 처리 여부 불명 (POST류라 재시도 안 함)",
    }


# family id와 그 case id들에 접미사 부착 (같은 지점의 family를 출력 위치별로 여러 세트 만들 때 id 충돌 방지)
def _suffix_family_id(family: RequestFamily, suffix: str) -> None:
    old = family.family_id
    family.family_id = old + suffix
    for case in [family.baseline, *family.mutations]:
        case.case_id = case.case_id.replace(old, family.family_id, 1)


# 저장 출력 위치 탐색(sweep)용 수집된 GET 주소 목록 (파괴적 액션 타겟 제외)
def _sweep_urls(targets: list[dict]) -> list[str]:
    urls: list[str] = []
    for target in targets:
        if has_destructive_action(target.get("params", {})):
            continue
        url = (target.get("url") or "").split("#", 1)[0]
        if (target.get("method") or "").upper() == "GET" and url and url not in urls:
            urls.append(url)
    return urls


# ScanPoint 하나를 value_type에 따라 sqli, xss_stored, xss_reflected 경로로 라우팅
def _route_scan_point(sp: ScanPoint, target: dict, zap, marker_factory=None, findings_path: str | None = None,
                      sweep_urls: list[str] | None = None) -> list[RequestFamily]:
    if has_destructive_action(target.get("params", {})):
        return []   # 파괴적 액션 있는 타겟은 검사 안함

    if sp.location == FRAGMENT_LOCATION:  # 파라미터 없는 GET 페이지: DOM hash 검사만 (Discovery·stored·SQLi 대상 아님)
        return generate_dom_fragment_families(sp, target)

    families: list[RequestFamily] = []

    try:
        discovery = run_discovery(sp, target, zap) # 특수문자가 반사되는 것들만 filtering.
        families.extend(generate_xss_families(sp, target, discovery)) # discovery에서 살아남은 것들 중에  xss_stored 가 아닌 것들만 extend로 풀어서 넣음

        # form 파라미터에만 마커 반사 확인 -  마커가 저장/반사되면 stored XSS family 생성
        if marker_factory is not None and sp.location == "form":
            marker = marker_factory(sp.name)
            probe_result = None
            probe_err = None
            try:
                probe_result = probe_sink(sp, target, marker, requester, zap, sweep_urls=sweep_urls)
            except Exception as e:  # probe_sink 호출만 격리 — 같은 param 의 reflected/SQLi 는 정상 진행
                probe_err = str(e)
                print(f"[WARN] probe_sink 실패, stored XSS 스킵: target={sp.target_id} param={sp.name} - {e}")

            if probe_result is not None and probe_result.sink_confirmed:
                # 출력 위치마다 stored family 세트 하나 — 기본 재방문 주소 + sweep으로 찾은 추가 위치
                sinks = [(probe_result.revisit_url, probe_result.revisit_source)]
                sinks += [(url, "sweep") for url in probe_result.extra_sinks]
                for sink_idx, (revisit_url, source) in enumerate(sinks):
                    stored = generate_stored_xss_families(sp, target)
                    for f in stored:    # sink 확인된 param 의 stored family 에만 프로브 결과 부착
                        if sink_idx:    # 추가 위치 세트는 family/case id를 구분
                            _suffix_family_id(f, f"_sink{sink_idx}")
                        f.sink_confirmed = probe_result.sink_confirmed
                        f.revisit_url = revisit_url
                        f.revisit_source = source
                        f.probe_marker = probe_result.probe_marker
                    families.extend(stored)
            elif findings_path:     # sink 미확인(마커 미반사) or 프로브 오류 -> inconclusive
                if probe_err is not None:
                    sink_note = f"판정 불가 - 프로브 오류: {probe_err}"
                else:
                    sink_note = "판정 불가 - 마커 재조회 확인 실패"
                append_jsonl(findings_path, {
                    "target_id": sp.target_id,
                    "param": sp.name,
                    "vuln_type": "xss",       # 새 결과 계약: probe 기록도 다른 판정과 동일한 필드로 통일
                    "technique": "stored",
                    "location": sp.location,        # 지점 식별용
                    "value_index": sp.value_index,
                    "stage": "probe",
                    "final_status": "inconclusive",
                    "probe_marker": marker,
                    "revisit_url": probe_result.revisit_url if probe_result is not None else None,
                    "sink_note": sink_note,
                })
        else:
            families.extend(generate_stored_xss_families(sp, target))
    except Exception as e:
        if findings_path:
            append_jsonl(findings_path, {
                    "target_id": sp.target_id,
                    "param": sp.name,
                    "stage": "xss_prepare",
                    "status": "error",
                    "error": str(e),
            })
        print(f"[WARN] XSS 준비 단계 실패: target={sp.target_id} param={sp.name} - {e}")

    # SQLi 
    try : 
        dynamic_markers, baseline_match_ratio = measure_dynamic_markers(sp, target, zap)
        families.extend(generate_sqli_families(sp, target, dynamic_markers, baseline_match_ratio))
    except Exception as e:
            if findings_path:
                append_jsonl(findings_path, {
                        "target_id": sp.target_id,
                        "param": sp.name,
                        "stage": "sqli_prepare",
                        "status": "error",
                        "error": str(e),
                })
            print(f"[WARN] SQLi 준비 단계 실패 : target={sp.target_id} param={sp.name} - {e}")

    return families


# 공격 전 스냅샷
def _revisit_before(family, case, requester, zap, target):
    try:
        return refetch(
            family.revisit_url, target.get("cookies"), None, requester, zap,
            target=target, max_retry=1,  # 재시도 없이 딱 1회만 GET 요청
        ), None
    except Exception as e:
        note = "공격 전 스냅샷 실패"
        print(f"[WARN] 공격 전 스냅샷 실패: family={family.family_id} case={case.case_id} - {e}")
        return None, note


# 공격 후 재조회
def _revisit_after_fields(revisit_url, family, case, requester, zap, target, revisit_before, before_note):
    try:
        revisit_after = refetch(
            revisit_url, target.get("cookies"), case.payload, requester, zap,
            target=target,
        )
    except Exception as e:  # 공격 후 재조회 실패 -> 반사 여부도 확인 불가, 사유만 기록
        after_note = "공격 후 재조회 실패 — 반사 여부 확인 불가"
        print(f"[WARN] 재조회 후 요청 실패: family={family.family_id} case={case.case_id} - {e}")
        return dict(revisit_note=f"{before_note}; {after_note}" if before_note else after_note)

    fields = dict(                              # CaseResult에 병합할 revisit 필드 생성
        revisit_status=revisit_after.status,
        revisit_url_used=revisit_url,           # 이번 case가 실제로 조회한 주소
        revisit_attempts=revisit_after.attempts,
        revisit_found=revisit_after.found,      # payload가 after에 반사됐는지
        revisit_body=revisit_after.body,
        revisit_headers=revisit_after.headers,  # headless가 이 스냅샷을 렌더링할 때 사용
    )
    if revisit_before is not None:
        fields["before_revisit_body"] = revisit_before.body
    else:
        # before 없을 경우: revisit_note만 추가로 남겨 judge_case가 diff 불가와 재조회 실패를 구분하도록
        fields["revisit_note"] = before_note
    return fields


# 공격 응답 Location에서 이번 case가 쓸 재방문 주소 추출 (상대경로면 case.url 기준 절대주소로 변환, 없으면 None)
def _resolve_case_revisit_url(sent: dict, case) -> str | None:
    location = sent["response_headers"].get("location")
    if not location:
        return None
    resolved = urljoin(case.url, location)
    return resolved if is_same_host(case.url, resolved) else None  # 범위 밖 목적지 -> 호출부가 family.revisit_url로 폴백


# 로컬 웹 설정의 재방문 주소(A url -> B url)를 target["revisit_url"]에 반영 (resolve_revisit_url이 최우선으로 사용)
def _apply_revisit_overrides(targets: list[dict]) -> None:
    overrides = load_json(_TARGET_CONFIG, default={}).get("revisit_urls") or {}
    if not overrides:
        return
    for target in targets:
        match = overrides.get(target.get("url")) or overrides.get(target.get("base_url"))
        if match:
            target["revisit_url"] = match


# collector -> ScanPoint 라우팅 -> 요청 전송 -> 판정 -> findings.jsonl까지 실행 (on_paths_ready는 결과 경로를 알게 되면 호출하는 콜백)
def run_pipeline(on_paths_ready=None, on_progress=None, should_stop=None, output_dir=None) -> str:
    progress = PipelineProgress(callback=on_progress, stop_requested=should_stop)

    # 수집 실패 전에도 실행 폴더 연결
    def output_ready(out_dir):
        if on_paths_ready is not None:
            on_paths_ready(os.path.join(out_dir, "request_results.jsonl"),
                           os.path.join(out_dir, "findings.jsonl"))

    out_dir, targets_path = run_collection(on_output_ready=output_ready, output_dir=output_dir, should_stop=should_stop)
    with open(targets_path, encoding="utf-8") as f:
        targets = json.load(f)
    _apply_revisit_overrides(targets)
    target_by_id = {f"t{idx}": target for idx, target in enumerate(targets)} # 타겟에 ID 부여 (ex. t0)
    scan_points = build_scan_points(targets)   # 타겟들을 파라미터 단위로 쪼갬.
    scan_points += build_fragment_points(targets, scan_points)  # 스캔 지점 없는 GET 페이지는 DOM hash 검사용 지점 1개
    sweep_urls = _sweep_urls(targets)          # 저장형 출력 위치 탐색 후보 (저장 확인된 form 파라미터에만 사용)
    progress.total = len(scan_points)
    progress.publish()

    results_path = os.path.join(out_dir, "request_results.jsonl")
    findings_path = os.path.join(out_dir, "findings.jsonl")
    if progress.should_stop():
        progress.publish()
        return results_path

    requester.clear_cookie_store()             # 스캔 시작 시 이전 스캔에서 누적된 쿠키 초기화 (origin별로 1회 진행, 캡쳐한 원본 쿠키 안지움)
    zap = requester.get_zap_client()
    marker_factory = new_run_marker_factory()  # 이번 스캔 실행 전체에서 고유 마커를 발급 (ScanPoint당 1개)
    headless = HeadlessSession()               # 최초 headless 대상이 나올 때까지 실제 브라우저는 안 뜸 (lazy)

    total_count = 0

    try:
        for sp in scan_points:
            if progress.should_stop():
                break
            target = target_by_id[sp.target_id]
            try:
                families = _route_scan_point(sp, target, zap, marker_factory=marker_factory, findings_path=findings_path,
                                             sweep_urls=sweep_urls)
            except Exception as e:             # 라우팅(Discovery 포함) 실패는 findings.jsonl에 에러 레코드만 남기고 다음 ScanPoint로 넘김.
                append_jsonl(findings_path, {
                    "target_id": sp.target_id, "param": sp.name,
                    "status": "error", "stage": "route", "error": str(e),
                })
                print(f"[ERROR] ScanPoint 라우팅 실패: target={sp.target_id} param={sp.name} - {e}")
                progress.completed += 1
                progress.publish()
                continue

            if progress.should_stop():
                if not families:
                    progress.completed += 1
                progress.publish()
                break

            # 같은 ScanPoint의 모든 family는 baseline이 완전히 동일한 요청이라 스캔포인트당 한번만 보냄.
            baseline_result: CaseResult | None = None
            if families:
                baseline_case = families[0].baseline
                total_count += 1
                try:
                    sent = requester.send(baseline_case, zap)
                except requester.RequestDeliveryUnknown as e:  # POST류 baseline 전송 불명 — 서버 처리 여부 모름 상태로 구분
                    baseline_result = CaseResult(case=baseline_case, status="error", error=str(e), reason="delivery_unknown")
                    progress.failed += 1
                    progress.publish()
                    print(f"[ERROR] baseline 전송 불명(서버 처리 여부 모름): target={sp.target_id} param={sp.name} - {e}")
                except Exception as e:  # baseline 요청 실패는 이 ScanPoint의 모든 family에 동일하게 반영
                    baseline_result = CaseResult(case=baseline_case, status="error", error=str(e))
                    progress.failed += 1
                    progress.publish()
                    print(f"[ERROR] baseline 요청 실패: target={sp.target_id} param={sp.name} - {e}")
                else:
                    baseline_result = CaseResult(
                        case=baseline_case, status="ok",
                        response_status=sent["response_status"],
                        response_headers=sent["response_headers"],
                        response_body=sent["response_body"],
                        elapsed=sent["elapsed"],
                        effective_cookies=sent["effective_cookies"],
                    )

            for family in families:
                assert baseline_result is not None  # families가 비어있지 않으면 위에서 반드시 채워짐
                # 위에서 보낸 baseline 결과를 family 고유 case_id로 갈아끼워 재사용
                case_results: list[CaseResult] = [replace(baseline_result, case=family.baseline)]

                for case in family.mutations: # 원형 -> 변형 순서로 순회하고 요청 전송.
                    if progress.should_stop():
                        break
                    total_count += 1
                    needs_revisit = bool(     # stored XSS + 마커 반사 확인된 family만 재조회
                        family.technique == "stored" and family.sink_confirmed and family.revisit_url
                    )

                    revisit_before = before_note = None
                    if needs_revisit:  # 공격 요청 전 스냅샷 - 마커로 미리 확인한 재방문 주소 기준으로 변형마다 새로 찍음
                        revisit_before, before_note = _revisit_before(family, case, requester, zap, target)
                        if revisit_before is None:  # 사전 스냅샷 실패 -> 이미 판정 불가로 결과 고정, 공격 요청/사후 재조회 생략
                            case_results.append(CaseResult(case=case, status="ok", revisit_note=before_note))
                            continue

                    try:
                        sent = requester.send(case, zap)
                    except requester.RequestDeliveryUnknown as e:  # 전송 불명 — 판정 대신 전송 사유 남기고 계속 진행
                        progress.failed += 1
                        progress.publish()
                        case_results.append(CaseResult(case=case, status="error", error=str(e), reason="delivery_unknown"))
                        print(f"[ERROR] 전송 불명(서버 처리 여부 모름): family={family.family_id} case={case.case_id} - {e}")
                        continue
                    except Exception as e:  # 개별 요청 실패는 로그만 남기고 계속 진행
                        progress.failed += 1
                        progress.publish()
                        case_results.append(CaseResult(case=case, status="error", error=str(e)))
                        print(f"[ERROR] 요청 실패: family={family.family_id} case={case.case_id} - {e}")
                        continue

                    revisit_fields = {}
                    if needs_revisit:  # 공격 POST 직후 재조회
                        # 프로브가 Location으로 위치를 찾은 경우만 case별 Location 추종, 그 외(유저 지정·sweep 등)는 고정 사용
                        case_revisit_url = ((family.revisit_source == "location" and _resolve_case_revisit_url(sent, case))
                                            or family.revisit_url)
                        if case_revisit_url != family.revisit_url:  # 응답 주소가 이전 주소와 다름 -> 이 변형 전용 새 주소, 이전에 찍은 사전 스냅샷은 무효
                            revisit_before, before_note = None, "이전과 재방문 주소가 다름 (사전 스냅샷 무효)"
                        revisit_fields = _revisit_after_fields(case_revisit_url, family, case, requester, zap, target, revisit_before, before_note)

                    case_results.append(CaseResult(
                        case=case, status="ok",
                        response_status=sent["response_status"],
                        response_headers=sent["response_headers"],
                        response_body=sent["response_body"],
                        elapsed=sent["elapsed"],
                        effective_cookies=sent["effective_cookies"],  # headless가 재현 시 쓸 쿠키값
                        **revisit_fields,
                    ))

                family_result = FamilyResult(
                    family_id=family.family_id, vuln_type=family.vuln_type, technique=family.technique,
                    target_id=family.target_id, param=family.param, attack_id=family.attack_id,
                    baseline=case_results[0], mutations=case_results[1:],
                    location=family.location, value_index=family.value_index,  # 지점 식별용
                    dynamic_markers=family.dynamic_markers,
                    baseline_match_ratio=family.baseline_match_ratio,
                    sink_confirmed=family.sink_confirmed,
                    revisit_url=family.revisit_url,
                    probe_marker=family.probe_marker,
                    sink_note=family.sink_note,
                )
                family_dict = asdict(family_result)
                append_jsonl(results_path, family_dict)

                # SQLi 판정
                if family.vuln_type == "sqli":
                    if baseline_result.reason == "delivery_unknown":  # 기준값 전송 불명 -> 비교 불가, 판정 대신 전송 사유 기록
                        append_jsonl(findings_path, _delivery_unknown_finding(family, family.baseline.case_id))
                        continue
                    if len(case_results) - 1 < len(family.mutations):
                        append_jsonl(findings_path, {
                            "family_id": family.family_id, "target_id": family.target_id,
                            "param": family.param, "vuln_type": family.vuln_type,
                            "technique": family.technique, "final_status": "inconclusive",
                            "location": family.location, "value_index": family.value_index,  # 지점 식별용
                            "stage": "stop", "evidence": "사용자 중단으로 비교 요청 묶음 미완료",
                        })
                        break
                    try:
                        for finding in analyze_family(family_dict):
                            append_jsonl(findings_path, asdict(finding))
                    except Exception as e:
                        print(f"[ERROR] 판정 실패: family={family.family_id} - {e}")
                        append_jsonl(findings_path, {
                            "family_id": family.family_id, "target_id": family.target_id,
                            "param": family.param, "status": "error", "stage": "judge", "error": str(e),
                        })
                    if progress.should_stop():
                        break
                    continue

                # XSS 판정
                for i, result in enumerate(case_results[1:]): # 수행한 요청만 판정 대상
                    if result.reason == "delivery_unknown":  # 전송 불명 case -> 판정 대신 전송 사유 기록 (analyzer 판정과 중복 방지)
                        append_jsonl(findings_path, _delivery_unknown_finding(family, result.case.case_id))
                        continue
                    try:
                        finding = xss_detector.judge_case(family_dict, family_dict["mutations"][i], headless) # 미리 변환해둔 dict 재사용
                        append_jsonl(findings_path, asdict(finding))
                    except Exception as e:
                        print(f"[ERROR] XSS 판정 실패: family={family.family_id} - {e}")
                        append_jsonl(findings_path, {
                            "family_id": family.family_id, "target_id": family.target_id,
                            "param": family.param, "case_id": result.case.case_id,
                            "status": "error", "stage": "judge", "error": str(e),
                        })
                if progress.should_stop():
                    break

            point_complete = not families or (
                family is families[-1] and len(case_results) == len(family.mutations) + 1
            )
            if point_complete:
                progress.completed += 1
            progress.publish()
            if progress.should_stop():
                break

        if progress.completed == progress.total:
            progress.stopped = False
        progress.publish()
        print(f"[RUN] request_results.jsonl -> {results_path} ({total_count - progress.failed}건 성공, {progress.failed}건 실패)")
        print(f"[RUN] findings.jsonl -> {findings_path}")
    finally:
        headless.close()  # 스캔 전체가 끝나면 헤드리스 프로세스 정리

    return results_path


if __name__ == "__main__":
    run_pipeline()
