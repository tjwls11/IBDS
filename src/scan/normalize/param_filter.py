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


# 브라우저·프레임워크가 기본으로 붙이는 표준 헤더 (이 밖의 헤더만 앱 JS가 만든 커스텀 헤더로 봄)
_STANDARD_HEADERS = frozenset({
    "host", "user-agent", "accept", "accept-language", "accept-encoding", "content-type", "content-length",
    "origin", "referer", "connection", "priority", "cache-control", "pragma", "te", "dnt", "cookie",
    "authorization", "upgrade-insecure-requests", "x-requested-with", "if-modified-since", "if-none-match", "range",
})


# 앱 JS가 붙인 커스텀 헤더(표준·인증·토큰 계열 제외) -> {이름: 값}
def custom_headers(headers: dict) -> dict[str, str]:
    result = {}
    for key, value in (headers or {}).items():
        low = key.lower()
        if low in _STANDARD_HEADERS or low.startswith("sec-") or any(word in low for word in NOSCAN_KEYWORDS):
            continue
        result[key] = str(value)
    return result


# 글자(버튼, 링크 문구 등)에 파괴적 액션 단어가 있으면 True (토큰 단위 일치)
def is_destructive_text(text: str) -> bool:
    return bool(_phrases(text) & _DESTRUCTIVE_ACTION_WORDS)


# params 값 중 파괴적 액션 단어가 하나라도 있으면 True
def has_destructive_action(params: dict) -> bool:
    for value in params.values():
        candidates = value if isinstance(value, (list, tuple)) else [value]  # 스칼라·리스트 양쪽 허용
        if any(_phrases(v) & _DESTRUCTIVE_ACTION_WORDS for v in candidates):
            return True
    return False
