import re

# CSRF/토큰 계열 파라미터 이름 키워드 (scan 대상에서 제외)
NOSCAN_KEYWORDS = frozenset({
    "token", "csrf", "_wpnonce", "nonce",
    "viewstate", "__requestverificationtoken",
})

# 토큰처럼 생긴거
_HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{16,}$')

# 폼 제출/액션 값 (control 파라미터)
_CONTROL_ACTION_WORDS = frozenset({
    "submit", "login", "search", "change", "update", "delete",
    "create", "register", "logout", "reset", "cancel", "sign",
    "upload", "clear", "add", "remove",
})

# 기존 상태 파괴 액션 값
_DESTRUCTIVE_ACTION_WORDS = frozenset({
    "clear", "delete", "reset", "remove", "logout", "logoff", "signout",
})


# 값을 소문자 토큰 집합으로 분해 + 인접 토큰 쌍 이어붙임 (단어매칭용. "Log Out"→logout / "log-off"→logoff)
def _phrases(value: str) -> set[str]:
    tok = [t for t in re.split(r"[\s+_-]+", (value or "").strip().lower()) if t]  # '공백(\s)', '+', '-', '_' 분리
    return set(tok) | {a + b for a, b in zip(tok, tok[1:])} 


# 값에 control 액션 단어가 있으면 control 파라미터로 판정
def is_control_param(value: str) -> bool:
    return bool(_phrases(value) & _CONTROL_ACTION_WORDS)


# 16자 이상 hex 문자열이면 보안 토큰(세션 ID 등)으로 판정
def is_security_token(value: str) -> bool:
    return bool(_HEX_TOKEN_RE.match((value or "").strip()))


# 글자(버튼·링크 문구 등)에 파괴적 액션 단어가 있으면 True (토큰 단위 일치라 "Log Out"·"delete user"도 잡음)
def is_destructive_text(text: str) -> bool:
    return bool(_phrases(text) & _DESTRUCTIVE_ACTION_WORDS)


# params 값 중 파괴적 액션 단어가 하나라도 있으면 True
def has_destructive_action(params: dict) -> bool:
    for value in params.values():
        candidates = value if isinstance(value, (list, tuple)) else [value]  # 스칼라·리스트 양쪽 허용
        if any(_phrases(v) & _DESTRUCTIVE_ACTION_WORDS for v in candidates):
            return True
    return False
