from pathlib import Path
from utilities.file_utils import load_json, save_json
from web.models import ConfigPayload

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGET_CONFIG = PROJECT_ROOT / "config" / "target_config.json"


# 사용자 설정 조회
def read_config():
    data = load_json(str(TARGET_CONFIG), default={}) or {}
    return {
        "target_url": data.get("target_url", ""), "revisit_urls": data.get("revisit_urls") or {},
        "ajax_spider": bool(data.get("ajax_spider", False)),
        "ajax_timeout": int(data.get("ajax_timeout") or 600),
        "ajax_random_inputs": bool(data.get("ajax_random_inputs", False)),
    }


# 기존 확장 필드를 보존한 사용자 설정 저장
def write_config(payload: ConfigPayload):
    data = load_json(str(TARGET_CONFIG), default={}) or {}
    data.update(payload.model_dump())
    save_json(str(TARGET_CONFIG), data)
