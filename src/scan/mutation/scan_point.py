"""
변형기 1단계
normalize 단계(scan/normalize/target.py)에서 이미 걸러진 scannable_params를 받아서
파라미터 위치를 query/form/json으로 정규화한 ScanPoint를 타겟마다 생성
"""

from __future__ import annotations

from scan.models import ScanPoint
from scan.normalize.param_filter import custom_headers


# int() 변환 가능 여부로 value_type("number" 또는 "string") 판정
def _is_numeric(value: str) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


# param_location을 query/form/json으로 정규화 (body -> form, 나머지는 그대로 통과)
def _normalize_location(location: str) -> str:
    return "form" if location == "body" else location


# 이름표와 내용물이 서로를 가리키는 쌍(A=foo, foo=A)이 있을 경우, 그중 사용자가 입력한 글자로 만들어진 이름표를 공격 지점으로 만듦
def _name_points(params: dict) -> list[tuple[str, int]]:
    names = list(params)
    chosen: dict[str, int] = {}
    for q in names:
        for occurrence, p in enumerate(params[q]):
            if p in params and p != q and q in params[p]:  # q의 값이 p의 이름이고 p의 값이 q의 이름 (상호 참조)
                later = q if names.index(q) > names.index(p) else p  # 상호 참조 쌍은 본문에서 뒤에 오는 쪽을 택함 (JS가 숨은 입력을 폼 끝에 붙이는 경우), 틀리면 양쪽 모두로 확장
                chosen.setdefault(later, occurrence if later == q else params[p].index(q))
    return list(chosen.items())


# 타겟 목록에서 스캔 가능한 파라미터만 추출해 ScanPoint 목록으로 변환 (값 지점 + 커스텀 헤더 지점 + 이름 지점)
def build_scan_points(targets: list[dict]) -> list[ScanPoint]:
    scan_points: list[ScanPoint] = []

    for idx, target in enumerate(targets):
        target_id = f"t{idx}"
        params = target.get("params") or {}
        raw_scannable = target.get("scannable_params")
        scannable = set(params.keys() if raw_scannable is None else raw_scannable)
        location = _normalize_location(target.get("param_location", "query"))
        method = (target.get("method") or "").upper()

        for name, values in params.items():
            if name not in scannable:
                continue

            for idx, value in enumerate(values):
                scan_points.append(ScanPoint(
                    target_id=target_id,
                    name=name,
                    location=location,
                    original_value=str(value),
                    value_type="number" if _is_numeric(value) else "string",
                    value_index=idx,
                    method=method,
                ))

        for name, value in custom_headers(target.get("headers")).items():  # 헤더 지점: 이름=헤더이름, 값=헤더값
            scan_points.append(ScanPoint(
                target_id=target_id, name=name, location="header", original_value=value,
                value_type="number" if _is_numeric(value) else "string", value_index=0, method=method,
            ))

        if location == "form":
            for name, occurrence in _name_points(params):  # 이름 지점: 이름 자체가 공격 대상이라 원본값도 이름
                scan_points.append(ScanPoint(
                    target_id=target_id, name=name, location="name", original_value=name,
                    value_type="number" if _is_numeric(name) else "string", value_index=occurrence, method=method,
                ))

    return scan_points
