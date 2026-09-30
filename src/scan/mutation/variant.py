from __future__ import annotations
import urllib.parse
from scan.models import MutationCase


# URL 쿼리스트링에서 param_name의 value_index번째 occurrence 값을 new_value로 교체 (다중값 파라미터 대응)
def _mutate_query(url: str, param_name: str, value_index: int, new_value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    occurrence = 0
    result = []
    for k, v in params:
        if k == param_name:
            result.append((k, new_value) if occurrence == value_index else (k, v))
            occurrence += 1
        else:
            result.append((k, v))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(result)))


# 폼 바디(x-www-form-urlencoded)에서 param_name의 value_index번째 occurrence 값을 new_value로 교체 (다중값 파라미터 대응)
def _mutate_form(body: str, param_name: str, value_index: int, new_value: str) -> str:
    params = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
    occurrence = 0
    result = []
    for k, v in params:
        if k == param_name:
            result.append((k, new_value) if occurrence == value_index else (k, v))
            occurrence += 1
        else:
            result.append((k, v))
    return urllib.parse.urlencode(result)


# location("form"/"query"/"json")을 body_type("form" or "query")으로 판정
def _body_type(location: str) -> str:
    return "form" if location == "form" else "query"


def _inject_fragment(url: str, payload: str) -> str:
    base = url.split("#", 1)[0]
    return f"{base}#{payload.lstrip('#')}"


# 원본 target 요청 그대로의 baseline MutationCase 생성
def build_baseline_case(target: dict, location: str, case_id: str) -> MutationCase:
    return MutationCase(
        case_id=case_id,
        step="baseline",
        method=target.get("method", "GET").upper(),
        url=target.get("url", target.get("base_url", "")),
        headers=dict(target.get("headers") or {}),
        cookies=dict(target.get("cookies") or {}),
        body_type=_body_type(location),
        body=target.get("request_body") or "",
    )


# param_name의 value_index번째 occurrence 위치에 payload를 삽입한 mutation MutationCase 생성 (다중값 파라미터 대응)
def build_mutation_case(
    target: dict,
    location: str,
    param_name: str,
    original_value: str,
    payload: str,
    step: str,
    case_id: str,
    value_index: int = 0,
    inject_fragment: bool = False,
) -> MutationCase:
    method = target.get("method", "GET").upper()
    base_url = target.get("base_url", "")
    url = target.get("url", base_url)
    body = target.get("request_body") or ""
    body_type = _body_type(location)

    if inject_fragment:  # DOM 계열: 파라미터 값이 아니라 URL fragment로 주입 (location.hash용)
        mutated_url = _inject_fragment(url, payload)
        mutated_body = body
        body_type = "fragment"  # 소스 구분 — Finding.location으로 그대로 전달
    elif body_type == "form":
        mutated_url = url
        mutated_body = _mutate_form(body, param_name, value_index, payload)
    else:
        mutated_url = _mutate_query(url, param_name, value_index, payload)
        mutated_body = body

    return MutationCase(
        case_id=case_id,
        step=step,
        method=method,
        url=mutated_url,
        headers=dict(target.get("headers") or {}),
        cookies=dict(target.get("cookies") or {}),
        body_type=body_type,
        body=mutated_body,
        payload=payload,
        original_value=original_value,
    )
