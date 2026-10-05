from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ScanPoint:  # RequestTarget에서 공격 대상 파라미터를 하나씩 분리한 것.
    target_id: str       # 어느 RequestTarget에서 나왔는지 연결하는 키
    name: str            # 파라미터 이름 (예: "id", "username")
    location: str        # 파라미터 위치 ("query", "form", "json")
    original_value: str  # 파라미터 원본값 — payload 템플릿의 {value} 자리에 들어감
    value_type: str      # 값 타입 ("string" or "number") — 2번이 룰 매칭 시 사용
    value_index: int = 0  # 같은 이름의 파라미터가 여러 개(다중값)일 때 몇 번째 occurrence인지 (0부터)
    method: str = ""     # HTTP 메서드 — build_scan_points에서 target["method"]로 채움

    @property
    def tag(self) -> str:
        return f"{self.name}__occ{self.value_index}"

    # 지점 식별자 — target_id_location_name__occN 형태, tag 재사용
    @property
    def point_id(self) -> str:
        return f"{self.target_id}_{self.location}_{self.tag}"


@dataclass
class MatchedRule: # 룰 선택 + {value} 치환까지 끝낸 결과물.
    attack_id: str       # 룰 식별자
    vuln_type: str       # 취약점 타입
    technique: str       # 공격 기법 (예: "error", "boolean", "time")
    sequence: list[str]  # step 순서. baseline은 스킵
    rendered_payloads: dict[str, list[str]]  # step별 치환 완료된 payload
    rendered_tokens: dict[str, list[str | None]] = field(default_factory=dict)  # rendered_payloads와 같은 순서의 실행 토큰 (dialog 없는 payload는 None)


@dataclass
class MutationCase: # HTTP 요청 하나를 완전히 표현하는 단위. baseline과 mutation 모두 이 타입
    case_id: str         # 케이스 식별자
    step: str            # 이 케이스의 step (예: "baseline", "error_attack")
    method: str          # HTTP 메서드
    url: str             # 요청 URL — query mutation이면 payload가 URL에 포함
    headers: dict[str, str]  # 요청 헤더
    cookies: dict[str, str]            # 쿠키
    body_type: str                     # 바디 타입 ("query" / "form" / "fragment"=DOM hash 주입)
    body: str                          # 요청 바디 — form mutation이면 payload가 body에 포함
    payload: str | None = None         # 삽입된 payload (baseline은 None)
    original_value: str | None = None  # 원본 파라미터 값 (baseline은 None)
    # boolean 외 케이스는 전부 None -> BOOLEAN이라고 앞에 달아줄것. boolean_pair_id 이런식
    pair_id: str | None = None         # 같은 주입 컨텍스트 비교 단위 식별자
    role: str | None = None            # 요청 역할 ("attack_true" / "attack_false" / "control")
    expected: str | None = None        # baseline 대비 기대 관계 "(approx_baseline" / "differ_baseline")
    repeat_index: int | None = None    # 같은 (pair_id, role) 반복 회차 (동일 조건 재검증용)
    exec_token: str | None = None      # 이 case의 payload에 넣은 XSS 실행 토큰 (case마다 고유, dialog 없는 payload는 None)


@dataclass
class RequestFamily:              # 1파라미터 x 1룰 = 1Family. 분석기가 baseline 대비 응답 차이를 비교하는 단위
    family_id: str                # family 식별자
    target_id: str                # 어느 타겟에서 나온 family인지
    param: str                    # 공격 대상 파라미터 이름
    attack_id: str                # 적용된 룰 식별자
    vuln_type: str                # 취약점 타입 ("sqli" or "xss")
    technique: str                # 공격 기법
    baseline: MutationCase        # 원본 요청 — 응답 비교 기준점
    mutations: list[MutationCase] # payload 교체된 요청 목록
    location: str | None = None   # 파라미터 위치 — ScanPoint에서 그대로 전달됨 (지점 식별용)
    value_index: int | None = None  # 같은 이름 파라미터의 occurrence 순번 — ScanPoint에서 그대로 전달됨
    dynamic_markers: list[tuple[str, str]] = field(default_factory=list)  # boolean SQLi 판정용 — (prefix, suffix) 형태로 이 타겟이 원래 흔들리는 자리를 표시
    baseline_match_ratio: float | None = None  # baseline 2회 요청의 유사도 — 이 타겟의 "정상 기준점" (sqlmap의 matchRatio와 동일한 발상)
    # Phase 1 sink probe 결과 — stored XSS family에만 설정, 나머지는 None -> 이것도 STORED 전용이라고 필드 표시 필요할듯
    sink_confirmed: bool | None = None   # True: 마커 반사 확인 / False: 미확인 / None: 프로브 안 함
    revisit_url: str | None = None       # 재조회 기준점
    revisit_source: str | None = None    # revisit_url을 어디서 얻었는지 ("explicit"/"location"/"default"/"sweep") — "location"일 때만 case별 Location 추종
    probe_marker: str | None = None      # sink_confirmed=True 시 사용한 마커 — 재현·디버깅용
    sink_note: str | None = None         # inconclusive 시 실패 이유


@dataclass
class CaseResult:  # MutationCase 하나를 전송한 결과
    case: MutationCase                                   # 어떤 요청을 보냈는지 (원본 그대로 참조)
    status: str                                          # "ok" 또는 "error"
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    elapsed: float | None = None
    error: str | None = None                             # status="error"일 때 예외 메시지
    reason: str | None = None                            # 실패 사유 코드값(일반 에러와 구분) — 전송 불명 시 "delivery_unknown"
    effective_cookies: dict[str, str] | None = None      # 요청 전송 시점에 실제로 실린 누적 쿠키
    # stored 공격 후 재조회 결과
    before_revisit_body: str | None = None               # 공격 주입 전 본문
    revisit_body: str | None = None                      # 공격 주입 후 재조회 본문
    revisit_headers: dict[str, str] | None = None        # 공격 주입 후 재조회 응답 헤더 (스냅샷 렌더링용)
    revisit_status: int | None = None                    # 재조회 GET 응답 상태코드
    revisit_url_used: str | None = None                  # 실제 재조회한 URL
    revisit_attempts: int | None = None                  # 재시도 횟수
    revisit_found: bool | None = None                    # after 응답에 payload 반사됐는지 (before 실패로 diff 못 해도 기록)
    revisit_note: str | None = None                      # 재조회 특이사항 메모 (예: before 스냅샷 실패로 diff 신뢰 불가)


@dataclass
class FamilyResult:               # RequestFamily 하나를 전송한 결과 (baseline/mutations를 family 단위로 묶음)
    family_id: str                # family 식별자
    vuln_type: str                # 취약점 타입 ("sqli" or "xss")
    technique: str                # 공격 기법
    target_id: str                # 어느 타겟에서 나온 family인지
    param: str                    # 공격 대상 파라미터 이름
    attack_id: str                # 적용된 룰 식별자
    baseline: CaseResult          # baseline 전송 결과
    mutations: list[CaseResult]   # mutation 전송 결과 목록
    location: str | None = None      # RequestFamily에서 그대로 전달됨
    value_index: int | None = None   # RequestFamily에서 그대로 전달됨
    dynamic_markers: list[tuple[str, str]] = field(default_factory=list)  # RequestFamily에서 그대로 전달됨
    baseline_match_ratio: float | None = None  # RequestFamily에서 그대로 전달됨
    # Phase 1 sink probe 결과 — RequestFamily에서 그대로 전달됨
    sink_confirmed: bool | None = None
    revisit_url: str | None = None
    probe_marker: str | None = None            # sink_confirmed=True 시 사용한 마커 (재현, 디버깅용)
    sink_note: str | None = None               # inconclusive 시 실패 이유


@dataclass
class DiscoveryResult:  # XSS family 생성 전 Discovery 단계의 결과
    reflected: bool                        # marker 문자열이 응답에 그대로 반사되는지
    valid_specials: set[str]               # 반사 지점에서 이스케이프 없이 살아남은 특수문자 집합
    injection_context: str | None = None   # marker 반사 위치의 HTML 컨텍스트 (inHTML/inAttr/inAttrUrl/inScript), 억제 컨텍스트·미탐지 시 None


@dataclass
class SinkProbeResult:  # Phase 1 sink 확인 프로브 결과 — stored XSS 재조회 착수 전 저장 여부 확인
    param: str           # 어느 파라미터에 대한 프로브인지
    revisit_url: str     # 마커 반사 확인을 위해 GET 날린 URL
    sink_confirmed: bool # 마커가 revisit_url 응답에 반사됐으면 True → Phase 2 진행
    inconclusive: bool   # 재시도까지 소진했는데도 판단 불가 → safe로 뭉개지 않고 inconclusive 유지
    probe_marker: str    # 이번 프로브에 사용한 마커 — 재현·디버깅용
    revisit_source: str | None = None  # revisit_url 출처 ("explicit"/"location"/"default"/"sweep")
    extra_sinks: list[str] = field(default_factory=list)  # 저장 확인 후 수집 페이지 전체 확인(sweep)으로 찾은 다른 출력 위치 (revisit_url 제외)
