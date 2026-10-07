import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from scan.normalize.importer import _parse_response_status, _parse_headers_block
from scan.models import MutationCase
from collector.zap_collector import ZapCollector

_THIS_DIR = os.path.dirname(os.path.abspath(__file__)) 
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_THIS_DIR)))
_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")

_SEND_MAX_RETRIES = 2
_SEND_RETRY_DELAY_SECS = 0.5
_HISTORY_RESET_EVERY = 1000  # ZAP 기록 저장소 비우는 주기(전송 건수), 저장소 용량 초과로 ZAP이 죽는 것 방지
_RETRY_SAFE_METHODS = frozenset({"GET", "HEAD"})

# ZAP 세션 새로 시작해 누적 기록 삭제, 실패해도 전송 흐름은 계속 진행
def _reset_zap_history(zap) -> None:
    try:
        zap.core.new_session(overwrite=True)
    except Exception as e:
        print(f"[WARN] ZAP 기록 비우기 실패, 계속 진행: {e}")


# 실제로 ZAP에 보낸 HTTP 요청 수 — 재시도·재조회·probe까지 모든 전송이 _send_once를 거치므로 여기서 한곳에서 센다
_send_count = 0


# 누적 전송 수 조회 (호출부가 시도 전후 차이로 시도당 요청 수를 구함)
def get_send_count() -> int:
    return _send_count


# 전송 카운터 초기화 (스캔 실행 시작 시 1회)
def reset_send_count() -> None:
    global _send_count
    _send_count = 0


class RequestDeliveryUnknown(RuntimeError):
    """POST처럼 서버에 뭔가 등록·수정하는 요청이 전송 도중 실패한 경우.

    서버가 이미 처리했는데 응답만 못 받았을 수도 있다. 이때 다시 보내면 게시글이
    중복 생성될 수 있으므로, 재시도하지 않고 '서버가 처리했는지 알 수 없음' 상태로 올린다.
    오케스트레이터는 isinstance로 이 예외를 잡아 case_id·method·reason으로 결과에
    일반 error와 다른 상태(reason='delivery_unknown')를 남긴다. 메시지 문자열 파싱 없이
    구분할 수 있도록 구조화 필드를 노출한다.
    """

    reason = "delivery_unknown"

    def __init__(
        self,
        message: str,
        *,
        case_id: str | None = None,
        method: str | None = None,
        original_error: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.case_id = case_id
        self.method = method
        self.original_error = original_error

def _is_retry_safe(method: str) -> bool:
    return method.strip().upper() in _RETRY_SAFE_METHODS


# site(origin)별 최신 쿠키 저장소, target이 아닌 origin 단위 공유.
# 키를 (name, path)로 둬서 같은 이름·다른 경로 쿠키가 서로 덮어쓰지 않도록 한다.
_cookie_store: dict[str, dict[tuple[str, str], str]] = {}

# 삭제된 쿠키 표식(tombstone) — 서버가 지운 (name, path)를 origin별로 기억한다.
# _get_cookies가 수집 당시 case.cookies로 되살리는 "재부활"을 막는 용도.
_deleted_cookies: dict[str, set[tuple[str, str]]] = {}


# 쿠키 저장소 초기화, 스캔 시작 시 1회 호출
def clear_cookie_store() -> None:
    _cookie_store.clear()
    _deleted_cookies.clear()


# config 기반 ZAP 클라이언트 생성, 기존 세션/컨텍스트는 서버 쪽 상태라 그대로 유지됨
def get_zap_client():
    return ZapCollector.from_config(_ZAP_CONFIG).zap


# URL에서 "scheme://netloc" 추출, http/https 구분용
def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid absolute URL: {url}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


# 요청 URL에서 경로 추출 (없으면 "/")
def _request_path(url: str) -> str:
    return urlparse(url).path or "/"


# Set-Cookie의 default-path 계산 (RFC 6265 §5.1.4): 경로가 "/"로 시작 안 하거나
# 첫 글자 뒤에 "/"가 없으면 "/", 아니면 마지막 "/" 앞까지.
def _default_path(req_path: str) -> str:
    if not req_path.startswith("/") or req_path.count("/") <= 1:
        return "/"
    return req_path[: req_path.rfind("/")] or "/"


# RFC 6265 §5.1.4 path-match: 쿠키 경로가 요청 경로를 포함하는지
def _path_matches(cookie_path: str, req_path: str) -> bool:
    if cookie_path == req_path:
        return True
    if req_path.startswith(cookie_path):
        return cookie_path.endswith("/") or req_path[len(cookie_path):].startswith("/")
    return False


# Set-Cookie 한 줄 파싱 -> (name, value, path, is_deletion).
# 삭제 지시 판단: 빈 값 / Max-Age<=0 / 과거 Expires 중 하나라도 해당.
def _parse_set_cookie(set_cookie: str, req_path: str) -> tuple[str, str, str, bool] | None:
    parts = [p.strip() for p in set_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    name, value = name.strip(), value.strip()
    if not name:
        return None

    path = ""
    max_age: int | None = None
    expires_past = False
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "path" and val:
            path = val
        elif key == "max-age":
            try:
                max_age = int(val)
            except ValueError:
                max_age = None
        elif key == "expires" and val:
            try:
                exp = parsedate_to_datetime(val)
                if exp is not None:
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    expires_past = exp <= datetime.now(timezone.utc)
            except (TypeError, ValueError):
                expires_past = False

    if not path:
        path = _default_path(req_path)
    is_deletion = (value == "") or (max_age is not None and max_age <= 0) or expires_past
    return name, value, path, is_deletion


# case origin의 현재 쿠키 조회, 최초 접근 시 수집 당시 쿠키로 초기화.
# 요청 경로에 path-match 되는 쿠키만 골라 name->value 로 돌려준다(같은 이름이면 더 구체적인 경로 우선).
def _get_cookies(case: MutationCase) -> dict[str, str]:
    origin = _origin(case.url)
    req_path = _request_path(case.url)
    stored = _cookie_store.setdefault(origin, {})
    tombstones = _deleted_cookies.setdefault(origin, set())

    for name, value in case.cookies.items():  # 수집 당시 쿠키로 시딩 — 단, 삭제 표식은 되살리지 않음
        key = (name, "/")
        if key not in stored and key not in tombstones:
            stored[key] = value

    selected: dict[str, str] = {}
    best_path: dict[str, str] = {}  # name -> 채택된 경로 (더 긴=구체적 경로가 이김)
    for (name, path), value in stored.items():
        if not _path_matches(path, req_path):
            continue
        if name not in best_path or len(path) > len(best_path[name]):
            selected[name] = value
            best_path[name] = path
    return selected


# 응답 원문에서 Set-Cookie 라인 추출, dict 변환 시 동일 이름 헤더 유실 방지
def _iter_set_cookie_values(response_header: str):
    for line in response_header.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "set-cookie":
            yield value.strip()


# 응답의 Set-Cookie를 저장소에 반영. (name, path) 단위로 저장/삭제하고,
# 삭제(빈 값·Max-Age<=0·과거 Expires)면 tombstone에 남겨 재부활을 막는다.
def _update_cookies_from_response(origin: str, response_header: str, req_path: str) -> None:
    stored = _cookie_store.setdefault(origin, {})
    tombstones = _deleted_cookies.setdefault(origin, set())
    for set_cookie in _iter_set_cookie_values(response_header):
        parsed = _parse_set_cookie(set_cookie, req_path)
        if parsed is None:
            continue
        name, value, path, is_deletion = parsed
        key = (name, path)
        if is_deletion:
            stored.pop(key, None)
            tombstones.add(key)          # 이후 시딩으로도 되살아나지 않도록 표식
        else:
            stored[key] = value
            tombstones.discard(key)      # 서버가 다시 세팅하면 표식 해제(정상 재로그인 등)


# MutationCase + cookies -> raw HTTP 요청 텍스트 재조립
def _build_raw_request(case: MutationCase, cookies: dict[str, str]) -> str:
    lines = [f"{case.method} {case.url} HTTP/1.1"] # 요청 라인에 절대 URL 사용 
    body_bytes = case.body.encode() if case.body else b""
    for k, v in case.headers.items():
        if k.lower() == "content-length":
            continue  # 실제 body 길이로 재계산
        lines.append(f"{k}: {v}")
    if body_bytes:
        lines.append(f"Content-Length: {len(body_bytes)}")
    if cookies:  # importer가 헤더에서 빼놓은 cookie, Cookie 헤더로 재조립
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        lines.append(f"Cookie: {cookie_str}")

    request_text = "\r\n".join(lines) + "\r\n\r\n"
    if case.body:
        request_text += case.body
    return request_text


def _send_once(raw_request: str, zap) -> tuple[dict, float]:
    global _send_count
    _send_count += 1
    if _send_count % _HISTORY_RESET_EVERY == 0:  # 수집 단계 기록은 이미 파일로 저장돼 있어 스캔 중에는 비워도 됨
        _reset_zap_history(zap)
    started = time.perf_counter()
    result = zap.core.send_request(request=raw_request, followredirects=False)
    elapsed = time.perf_counter() - started
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):     # [{...}] 형태 아니면 원인 파악 위해 실제 응답값 그대로 예외 메시지에 포함
        raise RuntimeError(f"ZAP send_request 실패, 응답: {result!r}")
    return result[0], elapsed


# case를 현재 쿠키로 전송, 응답의 Set-Cookie 반영 후 결과 dict 리턴
def send(case: MutationCase, zap) -> dict:
    origin = _origin(case.url)
    cookies = _get_cookies(case)
    raw_request = _build_raw_request(case, cookies)
    retry_safe = _is_retry_safe(case.method)
    max_attempts = (_SEND_MAX_RETRIES + 1) if retry_safe else 1

    last_error: Exception | None = None
    msg = elapsed = None
    for attempt in range(max_attempts):
        if attempt > 0:
            time.sleep(_SEND_RETRY_DELAY_SECS)
        try:
            msg, elapsed = _send_once(raw_request, zap)
            break
        except Exception as e:
            last_error = e
    else:
        if not retry_safe:
            raise RequestDeliveryUnknown(
                f"{case.method} {case.case_id} 전송 실패, 서버 처리 여부 불명 (POST류라 재시도 안 함): {last_error}",
                case_id=case.case_id, method=case.method, original_error=last_error,
            ) from last_error
        raise last_error or RuntimeError("ZAP send_request 재시도 모두 실패")

    response_header = msg.get("responseHeader", "")

    _update_cookies_from_response(origin, response_header, _request_path(case.url))  # 다음 요청부터 갱신된 쿠키 사용

    return {
        "case_id": case.case_id,
        "response_status": _parse_response_status(response_header),
        "response_headers": _parse_headers_block(response_header),
        "response_body": msg.get("responseBody", ""),
        "elapsed": elapsed,
        "effective_cookies": cookies,  # headless 재현 시 실제 전송 쿠키 복원용
    }