from dataclasses import dataclass
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlsplit


# 절대 HTTP 주소 검증
def validate_url(value: str) -> str:
    value = value.strip()
    try:
        parsed = urlsplit(value)
        parsed.port
        valid = parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
    except ValueError:
        valid = False
    if not valid or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("http:// 또는 https://로 시작하는 올바른 주소를 입력하세요.")
    return value


# 웹 설정 입력 모델
class ConfigPayload(BaseModel):
    target_url: str
    revisit_urls: dict[str, str] = Field(default_factory=dict)
    ajax_spider: bool = False  # Ajax Spider 사용 여부 (JS가 만드는 요청 수집)
    ajax_timeout: int = Field(default=600, ge=60, le=7200)  # Ajax Spider 최대 대기시간(초)
    ajax_random_inputs: bool = False  # 양식 자동 입력 시 무작위 값 사용 여부 (기본 끔: 페이지 기본값 사용)

    @field_validator("target_url")
    @classmethod
    def target_valid(cls, value):
        return validate_url(value)

    @field_validator("revisit_urls")
    @classmethod
    def overrides_valid(cls, values):
        cleaned = {validate_url(k): validate_url(v) for k, v in values.items()}
        if len(cleaned) != len(values):
            raise ValueError("중복된 원본 주소가 있습니다.")
        return cleaned


# 실행 상태와 진행률 모델
@dataclass
class RunState:
    run: str | None = None
    stage: str = "idle"
    running: bool = False
    total: int | None = None
    completed: int = 0
    failed: int = 0
    stopped: bool = False
    stop_requested: bool = False
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
