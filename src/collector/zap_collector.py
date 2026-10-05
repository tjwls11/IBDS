import re
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit

from zapv2 import ZAPv2  # type: ignore

from scan.normalize.param_filter import is_destructive_text
from utilities.file_utils import load_json

SESSION_NAME = "IBDSSession"
CONTEXT_NAME = "IBDSContext"
_AJAX_BROWSERS = 2  # Ajax Spider 헤드리스 브라우저 병렬 수 (메모리·대상 서버 부담 완화)
_AJAX_MAX_CRAWL_DEPTH = 5  # Ajax Spider 최대 탐색 깊이 (ZAP 기본 10)
_AJAX_MAX_CRAWL_STATES = 2000  # Ajax Spider 최대 탐색 상태 수 (ZAP 기본 0 = 무제한, 무한 탐색 방지용 상한)
_AJAX_LIMIT_MARGIN_SECS = 5  # 제한시간 직전(이 초 이내) 종료는 시간 제한에 걸린 것으로 간주
_DANGER_ELEMENT_WORDS = [  # 클릭 시 상태 변경 가능성이 있는 요소의 글자 (Ajax Spider 제외용)
    "logout", "log out", "sign out", "delete", "remove", "reset", "drop", "purge",
    "flush", "truncate", "wipe", "destroy", "로그아웃", "삭제", "초기화",
]
_DANGER_ELEMENT_TAGS = ["a", "button"]  # 위험 글자를 검사할 요소 태그


# HTML에서 누르면 상태가 바뀔 수 있는 컨트롤(링크, 버튼 글자, input 버튼 value) 중 위험 단어가 든 것을 (태그, 글자)로 수집
class _ControlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found: set[tuple[str, str]] = set()
        self._tag = None  # 글자를 모으는 중인 a/button
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("a", "button"):
            self._tag, self._buf = tag, []
        elif tag == "input" and (attrs.get("type") or "").lower() in ("button", "submit", "reset", "image"):
            value = (attrs.get("value") or "").strip()
            if value and is_destructive_text(value):
                self.found.add(("input", value))

    def handle_data(self, data):
        if self._tag:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == self._tag:
            text = " ".join("".join(self._buf).split())  # 공백 정리
            if text and is_destructive_text(text):
                self.found.add((tag, text))
            self._tag = None


# ZAP 수집 인프라 래퍼
class ZapCollector:
    def __init__(self, host="127.0.0.1", port=8081, api_key="changeme"):
        proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        self.zap = ZAPv2(proxies=proxies, apikey=api_key)

    @classmethod
    def from_config(cls, config_path):
        cfg = load_json(config_path, default={})
        return cls(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 8081),
            api_key=cfg.get("api_key", "changeme"),
        )


    # target origin(scheme+host+port) 밖 트래픽을 프록시 단에서 전역 제외
    # 매번 실행시 초기화됨.
    def restrict_to_target_domain(self, target_url: str):
        origin = f"{urlsplit(target_url).scheme}://{urlsplit(target_url).netloc}" # target_url에 path가 있어도 origin 기준
        regex = f"^(?!{re.escape(origin)}(?:$|[/?#])).*$"   # origin 뒤에 경계문자가 와야 같은 origin으로 인정

        self.zap.core.clear_excluded_from_proxy() # refresh
        print(f"[ZAP] 전역 제외 초기화 완료")

        self.zap.core.exclude_from_proxy(regex=regex)
        print(f"[ZAP] 전역 제외(target 외부 origin): {regex}")


    # Context 생성 + target include 등록
    def setup_context(self, target_url: str, name=CONTEXT_NAME) -> str:
        context_id = self.zap.context.new_context(contextname=name)
        include_regex = f"{re.escape(target_url.rstrip('/'))}(?:$|[/?#].*)" # target_url을 이스케이프 & 경로 뒤에 경계문자를 둬서 /app이 /application까지 포함하는 것을 방지
        self.zap.context.include_in_context(contextname=name, regex=include_regex)
        print(f"[ZAP] Context 생성: {name} (id={context_id}), include: {include_regex}")
        return context_id


    # logout/reset/delete 등 위험 URL을 Spider와 Context에서 제외, Spider 실행 전 필수 호출
    def exclude_danger_urls(self, patterns: list[str], name=CONTEXT_NAME):
        for pattern in patterns:
            self.zap.spider.exclude_from_scan(pattern)  # 일반 Spider용
            self.zap.context.exclude_from_context(contextname=name, regex=pattern)  # Ajax Spider(inscope)도 적용받도록 Context에도 등록
        print(f"[ZAP] Context 위험 URL 제외 {len(patterns)}건 등록")


    # Ajax Spider가 누르지 않을 위험 요소(로그아웃/삭제 등 글자를 가진 링크, 버튼) 등록
    # messages(일반 Spider가 모은 HTML)에서 토큰 기준으로 찾은 위험 요소는 그 글자 그대로, 고정 단어 목록은 JS가 만드는 요소 대비로 함께 등록
    def exclude_danger_elements(self, messages=(), name=CONTEXT_NAME) -> int:
        count = 0
        controls: set[tuple[str, str]] = set()
        for msg in messages:
            if "html" not in (msg.get("responseHeader") or "").lower():  # HTML 응답만 분석
                continue
            parser = _ControlParser()
            parser.feed(msg.get("responseBody") or "")
            controls |= parser.found
        for tag, text in controls:  # ZAP은 글자가 정확히 같아야 제외하므로 찾은 글자를 그대로 등록
            if tag == "input":
                self.zap.ajaxSpider.add_excluded_element(contextname=name, description=f"danger-found-input-{text}", element="input", attributename="value", attributevalue=text)
            else:
                self.zap.ajaxSpider.add_excluded_element(contextname=name, description=f"danger-found-{tag}-{text}", element=tag, text=text)
            count += 1
        print(f"[ZAP] 수집된 HTML에서 위험 요소 {len(controls)}건 발견")
        for word in _DANGER_ELEMENT_WORDS:
            for tag in _DANGER_ELEMENT_TAGS:
                for text in {word, word.capitalize(), word.upper()}:  # 대소문자 표기 차이 대응
                    self.zap.ajaxSpider.add_excluded_element(contextname=name, description=f"danger-{tag}-{text}", element=tag, text=text)
                    count += 1
            for text in {word, word.capitalize(), word.upper()}:  # input 버튼은 글자가 value 속성에 있어 속성으로 등록
                self.zap.ajaxSpider.add_excluded_element(contextname=name, description=f"danger-input-{text}", element="input", attributename="value", attributevalue=text)
                count += 1
        print(f"[ZAP] Ajax Spider 위험 요소 제외 {count}건 등록")
        return count


    # ZAP 메시지 히스토리에서 인증 성공 요청에 실린 쿠키(name=value) 수집.
    def _auth_cookies(self, target_url: str) -> dict:
        cookies = {}
        try:
            msgs = self.zap.core.messages(baseurl=target_url, count=500)
            
        except Exception as e:
            print(f"[SESSION] 메시지 조회 실패, 쿠키 자동 수집 건너뜀: {e}")
            return cookies
        
        for m in msgs:
            status = m.get("responseHeader", "").split("\r\n", 1)[0] # 헤더 첫줄 확인
            if " 2" not in status:  # 2xx 응답만 확인
                continue

            for line in m.get("requestHeader", "").split("\r\n"): 
                if not line.lower().startswith("cookie:"):
                    continue

                for part in line.split(":", 1)[1].split(";"):
                    if "=" not in part:
                        continue

                    k, v = part.split("=", 1) 
                    k, v = k.strip(), v.strip() 
                    if v and v.lower() != "deleted":
                        cookies[k] = v
        return cookies


    # 프록시가 캡처한 기존 세션 활성화, 없으면 anonymous로 진행
    def capture_session(self, target_url: str):
        site = urlsplit(target_url).netloc

        auth_cookies = self._auth_cookies(target_url)  # 마지막 2xx 요청이 쓰던 쿠키
        print(f"[SESSION] 인증 쿠키 감지: {auth_cookies}")

        cap_sess = self.zap.httpsessions.sessions(site)

        if not cap_sess:
            print("[SESSION] 세션 없음, anonymous 진행")
            return
        for i, entry in enumerate(cap_sess): # 캡쳐된 세션 확인 
            cks = ", ".join(f"{k}={v['value']}" for k, v in entry['session'][1].items())
            print(f"\n[SESSION]  [{i}] {entry['session'][0]} | msgs={entry['session'][2]} | {cks}\n")  # DEBUG: 캡처된 세션 전체 확인

        name = cap_sess[0]['session'][0]  # 최근 세션이라고 가정 (값은 어차피 아래에서 덮음)
        try:
            self.zap.httpsessions.set_active_session(site, name)
            for ck, val in auth_cookies.items():  # set_session_token_value가 토큰 등록 + 값 설정 동시 처리
                self.zap.httpsessions.set_session_token_value(site, name, ck, val) 
            print(f"[SESSION] active={name}, 주입={auth_cookies}")

        except Exception as e:
            print(f"[SESSION] 세션 설정 실패, anonymous 진행: {e}")
            return

        # DEBUG: 리다이렉트 끝까지 따라가서 최종 지점 확인
        try:
            chain = self.zap.core.access_url(url=target_url, followredirects=True)
            last = chain[-1] if isinstance(chain, list) and chain else {}
            req = (last.get("requestHeader") or "?").splitlines()[0]
            resp = (last.get("responseHeader") or "?").splitlines()[0]
            print(f"[SESSION] 테스트 요청 -> 최종 {req} : {resp}")

        except Exception as e:
            print(f"[SESSION] 테스트 요청 실패: {e}")


    # ZAP 사이트 트리에 target 직접 접근 등록 (Spider 시작 전 준비)
    def access_target(self, target_url: str):
        self.zap.core.access_url(url=target_url, followredirects=True)
        time.sleep(2)  # 사이트 트리 반영 대기


    # Spider 실행, 완료(100%)까지 폴링. timeout_seconds 초과 또는 should_stop() 신호 시 중단 요청
    def run_spider(self, target_url: str, context_name=CONTEXT_NAME, timeout_seconds: int | None = None, should_stop=None):
        try:  # Spider 시작 시점의 세션 상태 — capture_session 이후 유지 여부 확인용
            print(f"\n\n[SPIDER] 시작 시 세션 상태: {self.zap.httpsessions.sessions(urlsplit(target_url).netloc)}\n")

        except Exception as e:
            print(f"[SPIDER] 세션 상태 조회 실패: {e}")

        scan_id = self.zap.spider.scan(url=target_url, recurse=True, contextname=context_name)
        time.sleep(2)
        start = time.time()

        while int(self.zap.spider.status(scan_id)) < 100:
            timed_out = timeout_seconds is not None and time.time() - start >= timeout_seconds
            stop_requested = should_stop is not None and should_stop()

            if timed_out or stop_requested:
                reason = "제한시간 초과" if timed_out else "사용자 중단 요청"
                print(f"\n[SPIDER] {reason}, 중단합니다.")
                self.zap.spider.stop(scanid=scan_id)

                wait_start = time.time()
                while int(self.zap.spider.status(scan_id)) < 100 and time.time() - wait_start < 10: # 중단 확인 대기에도 상한을 둬 무한 대기 방지
                    time.sleep(1)
                break

            print(f"\r[SPIDER] {self.zap.spider.status(scan_id)}%", end="", flush=True)
            time.sleep(2)
        else:
            print("\r[SPIDER] 100% 완료")
            return

        print("\r[SPIDER] 중단됨")


    # Ajax Spider 실행 (SPA/JS 기반 요청 발견용, 선택 실행), timeout_seconds 초과 또는 should_stop() 신호 시 stop 후 결과 반환
    def run_ajax_spider(self, target_url: str, timeout_seconds: int, should_stop=None, random_inputs=False) -> dict:
        ajax = self.zap.ajaxSpider
        ajax.set_option_random_inputs(random_inputs)  # 끄면 페이지에 미리 채워진 기본값 사용 (Benchmark처럼 기본값이 있는 대상에 유리)
        ajax.set_option_click_default_elems(False)  # 기본 요소(a/button) 외에 input[type=button] 등도 클릭해야 JS 전송 요청이 기록됨 (위험 요소는 별도 제외)
        ajax.set_option_number_of_browsers(_AJAX_BROWSERS)  # 병렬 브라우저 수 제한
        ajax.set_option_max_crawl_depth(_AJAX_MAX_CRAWL_DEPTH)  # 탐색 깊이 상한
        ajax.set_option_max_crawl_states(_AJAX_MAX_CRAWL_STATES)  # 탐색 상태 수 상한 (기본 무제한 방지)
        ajax.set_option_max_duration(-(-timeout_seconds // 60) + 1)  # ZAP 쪽 실행시간 상한(분): 우리 제한시간보다 1분 길게 잡아 우리 검사가 먼저 걸리게 함 (ZAP이 먼저 끝나면 "완료"로 오기록됨)
        ajax.scan(url=target_url, inscope=True, contextname=CONTEXT_NAME)  # Context를 명시해야 범위가 정해져 실제로 탐색함 (실험에서 미지정 시 즉시 종료)

        time.sleep(2)
        start = time.time()
        completed = True
        stop_reason = "finished"  # finished(스스로 종료) / timeout(우리 제한시간) / user(사용자 중단) / zap_limit(ZAP 제한에 걸려 종료)

        while self.zap.ajaxSpider.status != "stopped":
            elapsed = time.time() - start
            timed_out = elapsed >= timeout_seconds
            stop_requested = should_stop is not None and should_stop()

            if timed_out or stop_requested:  # 시간 초과 또는 사용자 중단, 실패 아닌 정상 중단
                completed = False
                stop_reason = "timeout" if timed_out else "user"
                self.zap.ajaxSpider.stop()
                reason = f"{timeout_seconds}초 초과" if timed_out else "사용자 중단 요청"
                print(f"\n[AJAX SPIDER] {reason}, 중단 요청")

                wait_start = time.time()
                while self.zap.ajaxSpider.status != "stopped" and time.time() - wait_start < 10: # 중단 확인 대기에도 상한을 둬 무한 대기 방지
                    time.sleep(1)
                break

            print(f"\r[AJAX SPIDER] {self.zap.ajaxSpider.status} ({int(elapsed)}s/{timeout_seconds}s)", end="", flush=True)
            time.sleep(2)

        elapsed_seconds = round(time.time() - start, 1)
        if completed and elapsed_seconds >= timeout_seconds - _AJAX_LIMIT_MARGIN_SECS:  # ZAP이 제한시간 직전에 스스로 끝낸 경우도 미완료로 기록
            completed, stop_reason = False, "zap_limit"
        print(f"\r[AJAX SPIDER] {'완료' if completed else '중단(' + stop_reason + ')'} (경과 {elapsed_seconds}s)")
        return {
            "status": self.zap.ajaxSpider.status,
            "completed": completed,
            "stop_reason": stop_reason,
            "timeout": timeout_seconds,
            "elapsed_seconds": elapsed_seconds,
        }

    # raw 메시지 일부만 조회 (필드 구조 확인용)
    def get_messages_sample(self, base_url: str, count=3):
        return self.zap.core.messages(baseurl=base_url, start=0, count=count)

    # 전체 메시지 조회 (페이지네이션)
    def get_all_messages(self, base_url: str, page_size=200):
        all_msgs, start = [], 0
        
        while True:
            batch = self.zap.core.messages(baseurl=base_url, start=start, count=page_size)
            all_msgs.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size

        return all_msgs