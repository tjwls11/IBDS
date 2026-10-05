from __future__ import annotations
import difflib
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

from scan.mutation.variant import build_mutation_case

try:
    from scan.models import MutationCase, SinkProbeResult
except Exception:
    MutationCase = SinkProbeResult = None

MARKER_PREFIX = "ibds"
REVISIT_MAX_RETRY = 3      # revisit_max_retry
REVISIT_AWAIT_MS = 500     # revisit_await_ms


# 이번 스캔 실행 전체에서 고유 마커 문자열을 발급
class RunMarkerFactory:

    def __init__(self, run_hex: str | None = None):
        self.run_hex: str = run_hex or secrets.token_hex(2)
        self.prefix: str = f"{MARKER_PREFIX}{self.run_hex}"
        self._lock = threading.Lock()
        self._param_index: dict[str, int] = {}
        self._counters: dict[str, int] = {}

    # param 하나에 대해 새 마커 문자열 발급
    def issue(self, param: str) -> str:
        with self._lock:
            if param not in self._param_index:
                self._param_index[param] = len(self._param_index)
                self._counters[param] = 0
            self._counters[param] += 1      # 호출할 때마다 그 param의 카운터 1 증가
            idx = self._param_index[param]
            ctr = self._counters[param]
        return f"{self.prefix}p{idx:02d}n{ctr:04d}"

    # issue()와 동일 동작. marker_factory(param) 형태로 바로 호출하기 위한 래퍼
    def __call__(self, param: str) -> str:
        return self.issue(param)


# RunMarkerFactory 생성 진입점. 스캔 시작 시 1회 호출
def new_run_marker_factory(run_hex: str | None = None) -> RunMarkerFactory:
    return RunMarkerFactory(run_hex=run_hex)


# 재방문 목적지가 원본 target과 같은 host인지 검사 (af.md #8 — 외부 호스트로 인증정보 유출 방지)
def is_same_host(original_url: str, candidate_url: str) -> bool:
    return urlparse(original_url or "").netloc == urlparse(candidate_url or "").netloc


# 재조회 GET용 헤더 구성
def _get_headers_for_revisit(target: dict) -> dict:
    headers = dict(target.get("headers") or {})
    return {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length")} # 원본 요청 헤더에서 POST 전용 헤더(Content-Type/Length) 제거


# 마커 반사 프로브가 어디서 마커 반사를 할지 결정
# 우선순위: 유저가 명시한 revisit_url → 동일 호스트 referer → base_url(그 파라미터가 나온곳) → target_url
def resolve_revisit_url(target: dict) -> str:
    if explicit := target.get("revisit_url"):
        return explicit
    
    target_host = urlparse(target.get("url", "")).netloc
    referer = target.get("headers", {}).get("referer", "")

    if referer and urlparse(referer).netloc == target_host:
        return referer
    
    return target.get("base_url") or target.get("url", "")


# 마커 반사 확인
def _reflect_at(target: dict, url: str, marker: str, requester, zap, case_id: str) -> bool:
    get_case = MutationCase(
        case_id=case_id,
        step="probe_revisit",
        method="GET",
        url=url,
        headers=_get_headers_for_revisit(target),
        cookies=dict(target.get("cookies") or {}),
        body_type="query",
        body="",
    )
    resp = requester.send(get_case, zap)
    return marker in (resp.get("response_body") or "")  # marker 반사 여부만 bool로 확인 (본문 자체는 버림)


_MAX_EXTRA_SINKS = 3  # sweep으로 찾은 추가 출력 위치 상한 (위치마다 stored family 세트가 하나씩 늘어남)


# 반사 확인 - marker로 param 값 교체해 POST 후 revisit_url(실패 시 base_url) GET으로 확인, 저장 확인 시 sweep_urls에서 다른 출력 위치도 탐색
def probe_sink(sp, target: dict, marker: str, requester, zap, sweep_urls: list[str] | None = None):
    param = sp.name
    post_case = build_mutation_case(
        target=target,
        location=sp.location,
        param_name=param,
        original_value=sp.original_value,
        payload=marker,
        step="probe_post",
        case_id=f"probe_{sp.target_id}_{sp.tag}",
        value_index=sp.value_index,
    )
    sent = requester.send(post_case, zap)  # POST 응답 본문은 보지 않음(에코 오판 방지)

    # POST 응답 Location으로 동적 revisit_url 결정 (write.php처럼 매번 새 id가 생기는 경우 대응)
    # 범위 밖(외부 호스트) Location은 따르지 않고 기존 정책(override/referer/base_url)으로 폴백 (af.md #8·#12)
    # 유저가 명시한 revisit_url이 최우선 — PRG(저장 후 자기 자신으로 이동)처럼 Location이 출력 위치가 아닌 경우 대응
    location = (sent.get("response_headers") or {}).get("location")
    location_url = urljoin(post_case.url, location) if location else None
    if target.get("revisit_url"):
        revisit_url, source = target["revisit_url"], "explicit"
    elif location_url and is_same_host(target.get("url", ""), location_url):
        revisit_url, source = location_url, "location"
    else:
        revisit_url, source = resolve_revisit_url(target), "default"
    used_url = revisit_url
    confirmed = _reflect_at(target, revisit_url, marker, requester, zap,
                            case_id=f"probe_{sp.target_id}_{sp.tag}_revisit")

    if not confirmed:
        base_url = target.get("base_url") or ""
        if base_url and base_url != revisit_url:
            if _reflect_at(target, base_url, marker, requester, zap,
                           case_id=f"probe_{sp.target_id}_{sp.tag}_revisit_base"):
                confirmed = True
                used_url, source = base_url, "default"

    # 저장이 확인된 파라미터만 다른 출력 위치 탐색 — 저장 안 되는 대상(반사형 전용 등)엔 요청을 늘리지 않음
    extra_sinks: list[str] = []
    if confirmed and sweep_urls:
        for idx, url in enumerate(sweep_urls):
            if len(extra_sinks) >= _MAX_EXTRA_SINKS:
                break
            if url == used_url or not is_same_host(target.get("url", ""), url):
                continue
            if _reflect_at(target, url, marker, requester, zap,
                           case_id=f"probe_{sp.target_id}_{sp.tag}_sweep{idx}"):
                extra_sinks.append(url)

    return SinkProbeResult(
        param=param,
        revisit_url=used_url,
        sink_confirmed=confirmed,
        inconclusive=not confirmed,
        probe_marker=marker,
        revisit_source=source,
        extra_sinks=extra_sinks,
    )


# refetch() 반환값 (재조회 이후 값)
@dataclass
class RefetchResult:
    body: str               # 재조회 GET 응답 본문 (after 스냅샷)
    status: int | None      # 재조회 응답 상태코드
    attempts: int           # 총 GET 시도 횟수 (첫 GET 포함)
    found: bool             # payload가 응답에서 보였는지
    headers: dict | None = None  # 재조회 응답 헤더 (headless가 스냅샷을 렌더링할 때 CSP·Content-Type 적용)



'''
# 공격 이후 재시도해 확인
POST 공격 후 revisit_url을 재조회해 payload 안 보이면 await_ms만큼 대기 후 max_retry회까지 재시도

payload=None, max_retry=1로 호출하면 재시도 없이 1회만 도는 것을 이용해 공격 전 스냅샷에도 재사용 가능
'''
def refetch(revisit_url, cookies, payload, requester, zap,
            target=None, max_retry=REVISIT_MAX_RETRY, await_ms=REVISIT_AWAIT_MS) -> RefetchResult:

    headers = _get_headers_for_revisit(target or {})
    body, status, attempts, resp_headers = "", None, 0, None
    for attempts in range(1, max_retry + 1):
        if attempts > 1:
            time.sleep(await_ms * (attempts - 1) / 1000)
        get_case = MutationCase(
            case_id=f"refetch_n{attempts}",
            step="revisit_after",
            method="GET",
            url=revisit_url,
            headers=headers,
            cookies=dict(cookies or {}),
            body_type="query",
            body="",
        )
        resp = requester.send(get_case, zap)
        body = resp.get("response_body") or ""
        status = resp.get("response_status")
        resp_headers = resp.get("response_headers")
        if payload and payload in body:
            return RefetchResult(body=body, status=status, attempts=attempts, found=True, headers=resp_headers)
    return RefetchResult(body=body, status=status, attempts=attempts, found=False, headers=resp_headers)


# 공격 전/후 두 본문을 줄 단위로 비교해 새로 추가되거나 바뀐 영역만 추출
def diff_new_region(before_body, after_body):
    before_lines = (before_body or "").splitlines()
    after_lines = (after_body or "").splitlines()
    sm = difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False)
    new_parts = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            new_parts.extend(after_lines[j1:j2])
    return "\n".join(new_parts) if new_parts else None
