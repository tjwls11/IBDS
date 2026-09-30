"""
Playwright 기반 headless 확인부
raw HTTP 판정으로는 안 보이는 실제 실행 여부를 확인함
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, Browser, Playwright

_DROP_ON_FULFILL = {"content-encoding", "content-length", "transfer-encoding"}  # fulfill 시 제외할 응답 헤더


# 실행으로 인정할 dialog 메시지 선택 - exec_token이 주어지면 그 토큰이 담긴 메시지만 우리 payload 발화로 인정한다.
def _pick_executed(messages: list[str], exec_token: str | None) -> str | None:
    if not messages:
        return None # 토큰 없는 dialog는 페이지가 원래 띄운 것으로 보고 무시
    if exec_token is None:
        return messages[0]
    for msg in messages:
        if exec_token in msg:
            return msg
    return None # exec_token=None이면 첫 메시지

@dataclass
class HeadlessVerdict:  # headless 확인 1건의 결과
    executed: bool    # alert 등 dialog가 실제로 발생했는지
    method: str       # "render"(재렌더링) 또는 "navigate"(실제 재요청)
    evidence: str     # 짧은 근거 텍스트
    ok: bool = True   # 검증 자체가 수행됐는지. 렌더/네비 실패·미지원이면 False -> 상위에서 inconclusive


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
    # url+headers가 있으면 그 URL의 응답인 것처럼 fulfill -> 실제 origin·CSP 헤더/Content-Type 적용
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

                # 첫 메인 문서 요청만 저장된 응답으로 대체, 나머지(하위 리소스·재이동)는 전부 차단
                # 재요청 없음 유지 + 느린 리소스 타임아웃·사이트 자체 alert 오탐 방지
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
            page.wait_for_timeout(500)  # 지연 실행 payload 대비 짧은 대기
        except Exception as e:
            if not dialog_messages:  # 이미 발화한 뒤의 타임아웃(느린 하위 리소스 등)은 발화로 인정
                return HeadlessVerdict(executed=False, method="render", evidence=f"렌더링 실패: {e}", ok=False)
        finally:
            page.close()
        hit = _pick_executed(dialog_messages, exec_token)
        if hit is not None:
            return HeadlessVerdict(executed=True, method="render", evidence=f"dialog fired: {hit}")
        if dialog_messages:  # dialog는 떴지만 우리 토큰 아님 → 페이지 자체 것으로 보고 실행 아님
            return HeadlessVerdict(executed=False, method="render",
                                   evidence=f"우리 토큰 없는 dialog 무시(페이지 자체): {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="render", evidence="dialog 없음")

    # 실제 URL로 navigate, 쿠키 주입 후 alert 발생 여부 확인 (GET만)
    def confirm_via_navigate(self, url: str, cookies: dict[str, str], method: str,
                             exec_token: str | None = None) -> HeadlessVerdict:
        if method != "GET":  # TODO : POST 폼 재현은 추후구현
            return HeadlessVerdict(executed=False, method="navigate", evidence="POST navigate 미지원 (ver1 범위 밖)", ok=False)

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
            page.wait_for_timeout(500)
        except Exception as e:
            return HeadlessVerdict(executed=False, method="navigate", evidence=f"navigate 실패: {e}", ok=False)
        finally:
            if context is not None:
                context.close()
        hit = _pick_executed(dialog_messages, exec_token)
        if hit is not None:
            return HeadlessVerdict(executed=True, method="navigate", evidence=f"dialog fired: {hit}")
        if dialog_messages:  # dialog는 떴지만 우리 토큰 아님 -> 페이지 자체 것으로 보고 실행 아님
            return HeadlessVerdict(executed=False, method="navigate", 
                                   evidence=f"우리가 발급한 토큰이 없는 dialog 무시(페이지 자체): {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="navigate", evidence="dialog 없음")