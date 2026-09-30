from __future__ import annotations

from dataclasses import dataclass


# findings.jsonl 한 줄에 대응하는 판정 결과. XSS(case 단위)·SQLi(family 단위) 공용 스키마.
@dataclass
class Finding:
    vuln_type: str                 # "xss" | "sqli"
    family_id: str
    target_id: str
    param: str
    attack_id: str
    technique: str
    case_id: str
    method: str | None             # 요청 HTTP 메서드
    url: str | None                # 요청 URL (어느 엔드포인트가 걸렸는지)
    location: str | None           # param 위치 (query/body 등, = case body_type)
    value_index: int | None        # 같은 이름 파라미터의 occurrence 순번 (#25 지점 식별 계약)
    payload: str | None
    raw_verdict: dict              # {vulnerable, confidence, evidence} (XSS는 judge_xss asdict)
    headless_checked: bool         # headless 대상이었는지 (SQLi는 항상 False)
    headless_verdict: dict | None  # headless 결과 (asdict), 대상 아니면 None
    final_status: str              # "potential_high" | "potential_medium" | "potential_low" | "inconclusive"
    server_reflected: bool = False # DOM 쿼리 소스인데 서버가 payload를 응답에 반사함 (실제로는 Reflected XSS)
