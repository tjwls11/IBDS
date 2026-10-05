"""XSS 실행 식별 토큰 (#7)

우리가 주입한 payload가 발화한 dialog와, 대상 페이지가 원래 띄우는 dialog를 구분하기 위한
고유 숫자 nonce. payload의 dialog 호출 인자를 이 토큰으로 치환하고(inject_exec_token),
headless는 dialog 메시지에 이 토큰이 담긴 경우에만 실행으로 인정한다.

숫자 nonce인 이유: payload가 따옴표 컨텍스트('-alert(1)-' 등)를 쓰더라도 따옴표 중첩이
생기지 않아 문법이 깨지지 않는다. payload(case)마다 새로 생성한다 — 스캔 전체가 하나를 공유하면
저장형 등으로 페이지에 남은 다른 case의 payload가 터져도 이번 case의 실행으로 오인한다.
"""
from __future__ import annotations

import re
import secrets

# dialog 호출: alert/prompt/confirm 의 인자만 치환한다.
# \b(단어경계)를 쓰지 않는 이유: 이중 URL 인코딩 payload(%253Ealert(1)...)처럼 alert 앞이
# 단어문자인 경우에도 인자를 잡아야 하기 때문. payload에서 alert/prompt/confirm은 사실상 호출뿐이다.
_DIALOG_PAREN = re.compile(r"(alert|prompt|confirm)\s*\(([^)]*)\)")
_DIALOG_TEMPLATE = re.compile(r"(alert|prompt|confirm)\s*`([^`]*)`")


# 10자리 숫자 — 호출마다 새로 생성. 페이지가 우연히 같은 값을 alert할 확률은 무시 가능.
def new_exec_token() -> str:
    return str(1_000_000_000 + secrets.randbelow(9_000_000_000))


def inject_exec_token(payload: str, token: str) -> str:
    # (0) 간접 호출(setTimeout(alert,0,{token}) / onerror=alert,{token} / alert&lpar;{token}&rpar; 등)은
    #     정규식으로 인자를 못 잡으므로 룰에 명시한 {token} 자리를 직접 치환한다.
    payload = payload.replace("{token}", token)
    # (1) paren 호출은 alert(token) 으로, (2) 백틱(template literal) 호출은 백틱을 보존한 채
    #     alert`token` 으로 치환한다. 백틱 형태는 paren 차단 우회 목적이라 호출 문법을 유지한다.
    payload = _DIALOG_PAREN.sub(lambda m: f"{m.group(1)}({token})", payload)
    payload = _DIALOG_TEMPLATE.sub(lambda m: f"{m.group(1)}`{token}`", payload)
    return payload
