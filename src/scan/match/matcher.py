from __future__ import annotations

from dataclasses import dataclass, field

from ..models import MatchedRule, ScanPoint
from .exec_token import inject_exec_token, new_exec_token

# 룰 스키마
@dataclass
class AttackRule:
    attack_id: str                              
    vuln_type: str                              
    technique: str                             
    sequence: list[str]                         
    payload_templates: dict[str, list[str]]     
    allowed_locations: list[str] = field(default_factory=list)   
    allowed_value_types: list[str] = field(default_factory=list) 

# dict 하나를 AttackRule로 변환
def rule_from_dict(item: dict) -> AttackRule:
    return AttackRule(
        attack_id=item["attack_id"],
        vuln_type=item["vuln_type"],
        technique=item["technique"],
        sequence=list(item.get("sequence", [])),
        payload_templates=dict(item.get("payload_templates", {})),
        allowed_locations=list(item.get("allowed_locations", [])),
        allowed_value_types=list(item.get("allowed_value_types", [])),
    )


# 매칭 판정
def _is_applicable(point: ScanPoint, rule: AttackRule) -> bool:

    if rule.allowed_locations and point.location not in rule.allowed_locations:
        return False
    if rule.allowed_value_types and point.value_type not in rule.allowed_value_types:
        return False
    return True


#치환 — step별 (payload 목록, 같은 순서의 실행 토큰 목록) 반환
def _render_templates(
    payload_templates: dict[str, list[str]],
    original_value: str,
) -> tuple[dict[str, list[str]], dict[str, list[str | None]]]:

    rendered: dict[str, list[str]] = {}
    tokens: dict[str, list[str | None]] = {}
    for step, templates in payload_templates.items():
        rendered[step], tokens[step] = [], []
        for tmpl in templates:
            # {value} 치환 후 dialog 인자를 payload마다 새 실행 토큰으로 치환 (dialog 없는 payload는 토큰 None)
            token = new_exec_token()
            payload = inject_exec_token(tmpl.replace("{value}", str(original_value)), token)
            rendered[step].append(payload)
            tokens[step].append(token if token in payload else None)
    return rendered, tokens

def match_and_render(
    point: ScanPoint,
    rules: list[AttackRule],
) -> list[MatchedRule]:

    matched: list[MatchedRule] = []
    for rule in rules:
        if not _is_applicable(point, rule):
            continue
        rendered, tokens = _render_templates(rule.payload_templates, point.original_value)
        matched.append(MatchedRule(
            attack_id=rule.attack_id,
            vuln_type=rule.vuln_type,
            technique=rule.technique,
            sequence=list(rule.sequence),
            rendered_payloads=rendered,
            rendered_tokens=tokens,
        ))
    return matched
