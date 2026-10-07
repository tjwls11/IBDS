"""
Playwright 기반 headless 확인부
raw HTTP 판정으로는 안 보이는 실제 실행 여부를 확인함
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, Browser, Playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

_DROP_ON_FULFILL = {"content-encoding", "content-length", "transfer-encoding"}  # fulfill 시 제외할 응답 헤더
_SETTLE_STEP_MS = 500  # dialog가 이 시간 동안 새로 안 뜨면 다 뜬 것으로 봄 (지연 실행 payload 대비 대기)
_SETTLE_MAX_MS = 5000  # 대기 상한 — 저장형 payload가 쌓인 페이지(게시판 등)는 dialog가 줄줄이 떠서 한 번 대기로는 뒤쪽 것을 놓침


# 페이지 로드 후 dialog가 더 이상 안 뜰 때까지 대기 (상한 있음)
def _wait_dialogs_settle(page, dialog_messages: list[str]) -> None:
    waited = 0
    while waited < _SETTLE_MAX_MS:
        before = len(dialog_messages)
        page.wait_for_timeout(_SETTLE_STEP_MS)
        waited += _SETTLE_STEP_MS
        if len(dialog_messages) == before:
            return


# 실행으로 인정할 dialog 메시지 선택 - exec_token이 담긴 메시지만 우리 payload 발화로 인정
def _pick_executed(messages: list[str], exec_token: str | None) -> str | None:
    if not messages or exec_token is None:  # 식별값 없는 시도는 dialog가 떠도 이번 시도 발화로 귀속 불가
        return None
    for msg in messages:
        if exec_token in msg:
            return msg
    return None


# 실행으로 인정하지 않은 dialog의 근거 문구
def _unmatched_evidence(messages: list[str], exec_token: str | None) -> str:
    if exec_token is None:
        return f"식별값 없는 시도라 dialog 실행 미인정: {messages[0]}"
    return f"우리 토큰 없는 dialog 무시(페이지 자체): {messages[0]}"


# 실행으로 인정하지 않은 dialog의 사유 코드 - 토큰 없는 시도만 이번 시도와 구분 불가
def _unmatched_reason(exec_token: str | None) -> str | None:
    return "state_unclear" if exec_token is None else None


# 브라우저 확인 실패 사유 코드
def _failure_reason(e: Exception) -> str:
    return "browser_timeout" if isinstance(e, PlaywrightTimeoutError) else "browser_failed"


@dataclass
class HeadlessVerdict:  # headless 확인 1건의 결과
    executed: bool    # alert 등 dialog가 실제로 발생했는지
    method: str       # "render"(재렌더링) 또는 "navigate"(실제 재요청)
    evidence: str     # 짧은 근거 텍스트
    ok: bool = True   # 검증 자체가 수행됐는지. 렌더/네비 실패나 미지원이면 False -> 상위에서 inconclusive
    reason: str | None = None  # 실패 또는 귀속 불가 사유 코드 (browser_timeout, browser_failed, state_unclear)


class HeadlessSession:
    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    # 최초 호출 시에만 브라우저 프로세스를 띄움
    def _ensure_browser(self) -> Browser:
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.firefox.launch(headless=True)    # 파이어 폭스 브라우저 띄움
        return self._browser

    # 브라우저/Playwright 프로세스 정리
    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
        if self._playwright is not None:
            self._playwright.stop()
        self._browser = None
        self._playwright = None

    # 이미 받은 response_body를 그대로 렌더링만 함, 재요청 없음
    # url+headers가 있으면 그 URL의 응답인 것처럼 fulfill -> 실제 origin, CSP 헤더/Content-Type 적용
    def confirm_via_render(self, response_body: str, url: str | None = None,
                           headers: dict[str, str] | None = None,
                           exec_token: str | None = None) -> HeadlessVerdict:
        browser = self._ensure_browser()
        page = browser.new_page()
        dialog_messages: list[str] = []

        def _on_dialog(dialog):  # dialog 발생 시 메시지 기록 후 닫기 (None 반환 — page.on 시그니처)
            dialog_messages.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", _on_dialog)
        try:
            if url and headers is not None:
                # 저장된 본문은 이미 디코딩된 문자열 → 인코딩/길이 헤더는 빼야 브라우저가 다시 디코딩하다 깨지지 않음
                fulfill_headers = {k: v for k, v in headers.items() if k.lower() not in _DROP_ON_FULFILL}
                served = False

                # 첫 메인 문서 요청만 저장된 응답으로 대체, 나머지(하위 리소스, 재이동)는 전부 차단
                # 재요청 없음 유지 + 느린 리소스 타임아웃과 사이트 자체 alert 오탐 방지
                def _serve_once(route):
                    nonlocal served
                    if not served and route.request.is_navigation_request():
                        served = True
                        route.fulfill(status=200, headers=fulfill_headers, body=response_body or "")
                    else:
                        route.abort()

                page.route("**/*", _serve_once)
                page.goto(url, timeout=5000)
            else:
                page.set_content(response_body or "", timeout=5000)
            _wait_dialogs_settle(page, dialog_messages)
        except Exception as e:
            if not dialog_messages:  # 이미 발화한 뒤의 타임아웃(느린 하위 리소스 등)은 발화로 인정
                return HeadlessVerdict(executed=False, method="render", evidence=f"렌더링 실패: {e}", ok=False,
                                       reason=_failure_reason(e))
        finally:
            page.close()
        hit = _pick_executed(dialog_messages, exec_token)
        if hit is not None:
            return HeadlessVerdict(executed=True, method="render", evidence=f"dialog fired: {hit}")
        if dialog_messages:  # dialog는 떴지만 이번 시도 발화로 인정 불가 → 실행 아님
            return HeadlessVerdict(executed=False, method="render",
                                   evidence=_unmatched_evidence(dialog_messages, exec_token),
                                   reason=_unmatched_reason(exec_token))
        return HeadlessVerdict(executed=False, method="render", evidence="dialog 없음")

    # 실제 URL로 navigate, 쿠키 주입 후 alert 발생 여부 확인 (GET만)
    def confirm_via_navigate(self, url: str, cookies: dict[str, str], method: str,
                             exec_token: str | None = None) -> HeadlessVerdict:
        if method != "GET":  # TODO : POST 폼 재현은 추후구현
            return HeadlessVerdict(executed=False, method="navigate", evidence="POST navigate 미지원", ok=False,
                                   reason="browser_failed")

        browser = self._ensure_browser()  # 브라우저 실행 실패는 loudly 전파 — try 밖에 유지
        context = None
        try:
            context = browser.new_context(ignore_https_errors=True)  # 자체 서명 인증서 대상 허용
            if cookies:
                hostname = urlparse(url).hostname
                context.add_cookies([
                    {"name": name, "value": value, "domain": hostname, "path": "/"}
                    for name, value in cookies.items()
                ])
            page = context.new_page()
            dialog_messages: list[str] = []

            def _on_dialog(dialog):  # dialog 발생 시 메시지 기록 후 닫기 (None 반환 — page.on 시그니처)
                dialog_messages.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.goto(url, timeout=10000)
            _wait_dialogs_settle(page, dialog_messages)
        except Exception as e:
            return HeadlessVerdict(executed=False, method="navigate", evidence=f"navigate 실패: {e}", ok=False,
                                   reason=_failure_reason(e))
        finally:
            if context is not None:
                context.close()
        hit = _pick_executed(dialog_messages, exec_token)
        if hit is not None:
            return HeadlessVerdict(executed=True, method="navigate", evidence=f"dialog fired: {hit}")
        if dialog_messages:  # dialog는 떴지만 이번 시도 발화로 인정 불가 -> 실행 아님
            return HeadlessVerdict(executed=False, method="navigate",
                                   evidence=_unmatched_evidence(dialog_messages, exec_token),
                                   reason=_unmatched_reason(exec_token))
        return HeadlessVerdict(executed=False, method="navigate", evidence="dialog 없음")