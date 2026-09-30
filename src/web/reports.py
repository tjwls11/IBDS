import json
import re
from collections import Counter
from pathlib import Path
from utilities.file_utils import load_json
from web.runs import run_metadata
from attack_requests import RULES

_CATEGORY_BY_TECHNIQUE = {rule["technique"]: rule["category"] for rule in RULES}

# 서진 확정본 final_status 어휘 (저장값 -> 화면 라벨)
_STATUS_LABELS = {
    "potential_high": "HIGH Potential",
    "potential_medium": "MEDIUM Potential",
    "potential_low": "LOW Potential",
    "inconclusive": "Inconclusive",
}
# Potential 집계 우선순위 (HIGH > MEDIUM > LOW), inconclusive
_STATUS_ORDER = ["potential_high", "potential_medium", "potential_low", "inconclusive"]
# 구 어휘 -> 신 어휘 (예전 결과 폴더·미갱신 판정기 호환) 다 끝나면 지워주세요
_LEGACY_STATUS = {
    "vulnerable": "potential_high", "vuln": "potential_high",
    "safe": "potential_low", "reflected_only": "potential_low",
    "error_only": "potential_medium",
}


# final_status 저장값을 확정본 어휘로 정규화 (신 어휘는 그대로, 구 어휘는 매핑)
def _normalize_status(status):
    return _LEGACY_STATUS.get(status, status)


# technique -> 결과 상세 옆에 표시할 카테고리 이름
def _technique_category(technique):
    # 정의에 없는 값(레거시 데이터 등)은 technique 이름을 그대로 노출
    return _CATEGORY_BY_TECHNIQUE.get(technique, technique)


# 상단 필터용 대분류: template은 xss와 별개 취급, 나머지는 vuln_type 그대로
def _filter_group(vuln_type, technique):
    return "template" if technique == "template" else vuln_type


# JSONL 레코드 조회와 불완전한 마지막 줄 제외
def read_jsonl(path):
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    yield item
            except json.JSONDecodeError:
                continue


# 판정 파일과 원본 요청의 연결 및 보고서 집계
def build_report(out_dir):
    directory = Path(out_dir)
    targets = load_json(str(directory / "scan_targets.json"), default=[]) or []
    target_info = {f"t{i}": t for i, t in enumerate(targets)}
    families, failed_cases, errors, error_keys = {}, set(), [], set()

    # 동일 오류의 중복 집계 방지
    def add_error(item):
        stage = item.get("stage", "request")
        case_id = item.get("case_id")
        if stage == "baseline":
            match = re.match(r"^(.*__occ\d+)_", case_id or item.get("family_id") or "")
            case_id = match.group(1) if match else None
        elif not case_id and not item.get("family_id"):
            errors.append(item)
            return
        else:
            case_id = case_id or item.get("family_id")
        key = (item.get("target_id"), item.get("param"), stage, case_id, item.get("error"))
        if key not in error_keys:
            error_keys.add(key)
            errors.append(item)

    for family in read_jsonl(directory / "request_results.jsonl"):
        fid = family.get("family_id")
        if not fid:
            continue
        baseline = family.get("baseline") or {}
        original = baseline.get("case") or {}
        target = target_info.get(family.get("target_id"), {})
        families[fid] = {"url": target.get("url") or original.get("url"),
                         "method": target.get("method") or original.get("method"),
                         "vuln_type": family.get("vuln_type"), "technique": family.get("technique")}
        for result in [baseline, *(family.get("mutations") or [])]:
            if result.get("status") != "error":
                continue
            case = result.get("case") or {}
            failed_cases.add((fid, case.get("case_id")))
            add_error({"target_id": family.get("target_id"), "param": family.get("param"),
                       "family_id": fid, "case_id": case.get("case_id"),
                       "url": families[fid]["url"], "stage": "baseline" if result is baseline else "request",
                       "error": result.get("error") or "요청 실패"})

    groups, counts, filter_groups = {}, Counter(), set()
    for finding in read_jsonl(directory / "findings.jsonl"):
        fid = finding.get("family_id")
        info = families.get(fid, {})
        target_id, param = finding.get("target_id"), finding.get("param")
        target = target_info.get(target_id, {})
        url = target.get("url") or info.get("url") or finding.get("url") or ""
        method = target.get("method") or info.get("method") or finding.get("method") or ""
        if finding.get("status") == "error":
            add_error({**finding, "url": url})
            continue
        if (fid, finding.get("case_id")) in failed_cases:
            continue
        status = _normalize_status(finding.get("final_status"))
        if not status or target_id is None or param is None:
            continue
        technique = finding.get("technique") or info.get("technique")
        vuln_type = finding.get("vuln_type") or info.get("vuln_type")
        # 서버 반사로 발화한 DOM 쿼리 결과는 Reflected로 표시 (technique은 dom 유지)
        category = ("reflected (DOM 쿼리 payload)" if finding.get("server_reflected")
                    else _technique_category(technique) if technique else None)
        item = {**finding, "final_status": status, "technique": technique,
                "category": category,
                "vuln_type": vuln_type,
                "evidence": finding.get("evidence") or finding.get("sink_note") or
                            (finding.get("raw_verdict") or {}).get("evidence") or ""}
        
        location = finding.get("location") 
        value_index = finding.get("value_index")
        key = (target_id, method, param, location, value_index)
        group = groups.setdefault(key, {"url": url, "method": method, "param": param,
                                        "location": location, "value_index": value_index,
                                        "target_id": target_id, "items": []})
        group["items"].append(item)
        counts[status] += 1
        group_name = _filter_group(vuln_type, technique)
        item["filter_group"] = group_name
        filter_groups.add(group_name)
    # 확정본 우선순위대로 상태 나열 (목록에 없는 값은 뒤에 사전순)
    statuses = [s for s in _STATUS_ORDER if s in counts] + sorted(s for s in counts if s not in _STATUS_ORDER)
    return {"groups": list(groups.values()), "errors": errors, "counts": dict(counts),
            "error_count": len(errors), "statuses": statuses,
            "status_labels": {s: _STATUS_LABELS.get(s, s) for s in statuses},  # 화면 표시용 라벨
            "filter_groups": [g for g in ("xss", "sqli", "template") if g in filter_groups],
            "meta": run_metadata(directory)}
