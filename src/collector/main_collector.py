import os
import re
import sys
from datetime import datetime

from utilities.file_utils import load_json, save_json, normalize_base_url
from collector.zap_collector import ZapCollector
from scan.normalize.importer import to_targets

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_ROOT = os.path.dirname(_THIS_DIR)  # src/
_PROJECT_ROOT = os.path.dirname(_SRC_ROOT)  # 리포 루트, src 밖 경로용
sys.path.insert(0, _SRC_ROOT)  # src 루트 패키지 import용

_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")
_DANGER_URL_FILE = os.path.join(_THIS_DIR, "spider_exclude.txt")

_DEFAULT_AJAX_TIMEOUT = 600  # Ajax Spider 최대 대기시간(초) 기본값 (웹 설정값이 있으면 그 값 우선)
_DEFAULT_SPIDER_TIMEOUT = 1800  # 일반 Spider 최대 대기시간(초), Benchmark SQLi/XSS 약 960건 수집 여유분


# 위험 URL 정규식 목록 로드 (빈 줄/주석 제외)
def _load_danger_patterns(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ZAP 메시지에서 요청 URL 추출 (url 필드 우선, 없으면 requestHeader 첫 줄 2번째 토큰)
def _msg_url(msg: dict) -> str:
    url = (msg.get("url") or "").strip()
    if url:
        return url
    first = (msg.get("requestHeader") or "").replace("\r\n", "\n").split("\n", 1)[0] # 첫줄 꺼내기
    parts = first.strip().split(" ") 
    return parts[1] if len(parts) >= 2 else "" # 두번쨰 토큰 꺼내기


# 위험 URL 패턴 매칭 메시지를 프록시 히스토리에서도 제외
def _drop_danger_messages(messages: list[dict], patterns: list[str]) -> tuple[list[dict], list[str]]:
    if not patterns:
        return messages, []
    compiled = [re.compile(p) for p in patterns]
    keep: list[dict] = []
    drop: list[str] = []
    for msg in messages:
        url = _msg_url(msg)
        if url and any(rx.search(url) for rx in compiled):  
            drop.append(url)                             
        else:
            keep.append(msg)                                # url 파싱 실패일 경우 keep으로 넘김
    return keep, drop                                    # 남긴 메시지 리스트, 제외된 URL 리스트


# ZAP 수집 + normalize 실행, (out_dir, scan_targets.json 경로) 반환. 실패 시 예외를 그대로 던짐
def run_collection(on_output_ready=None, output_dir=None, should_stop=None) -> tuple[str, str]:
    target_cfg = load_json(_TARGET_CONFIG, default={})
    target_url = normalize_base_url(target_cfg.get("target_url", ""))
    if not target_url:
        raise ValueError("target_config.json에 target_url이 없습니다.")

    ajax = bool(target_cfg.get("ajax_spider"))  # 웹 설정에서 선택한 경우에만 Ajax Spider 실행, 기본 비활성
    ajax_timeout = int(target_cfg.get("ajax_timeout") or _DEFAULT_AJAX_TIMEOUT)
    ajax_random_inputs = bool(target_cfg.get("ajax_random_inputs", False))  # 양식 자동 입력에 무작위 값 사용, 기본 끔
    danger_patterns = _load_danger_patterns(_DANGER_URL_FILE)

    out_dir = output_dir or os.path.join(_PROJECT_ROOT, "results", datetime.now().strftime("collection_%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    if on_output_ready is not None:
        on_output_ready(out_dir)

    collector = ZapCollector.from_config(_ZAP_CONFIG)
    print(f"[ZAP] 버전: {collector.zap.core.version}")

    collector.restrict_to_target_domain(target_url)
    collector.setup_context(target_url)
    collector.exclude_danger_urls(danger_patterns)  # Spider 실행 전 필수 등록

    collector.access_target(target_url)
    collector.capture_session(target_url)  # 현재 세션 그대로 가져오기

    print(f"[COLLECT] Spider 시작: {target_url}")
    collector.run_spider(target_url, timeout_seconds=_DEFAULT_SPIDER_TIMEOUT, should_stop=should_stop)

    ajax_meta = {
        "ajax_spider_enabled": ajax,
        "ajax_spider_random_inputs": ajax_random_inputs,
        "ajax_spider_status": None,
        "ajax_spider_completed": None,
        "ajax_spider_stop_reason": None,
        "ajax_spider_timeout": ajax_timeout,
        "ajax_spider_elapsed_seconds": None,
    }
    spider_ids: set[str] = set()  # Ajax 실행 전까지 쌓인 메시지 id (출처 구분용)
    if ajax:
        spider_messages = collector.get_all_messages(target_url)
        spider_ids = {str(m.get("id")) for m in spider_messages}
        collector.exclude_danger_elements(spider_messages)  # 일반 Spider가 모은 HTML에서 위험 요소를 찾아 Ajax Spider 제외 등록, 실행 전 필수
        print(f"[COLLECT] Ajax Spider 시작 (최대 {ajax_timeout}초, 무작위 입력 {'켬' if ajax_random_inputs else '끔'}): {target_url}")
        result = collector.run_ajax_spider(target_url, ajax_timeout, should_stop=should_stop, random_inputs=ajax_random_inputs)  # 타임아웃 초과해도 예외 안 던짐
        ajax_meta["ajax_spider_status"] = result["status"]
        ajax_meta["ajax_spider_completed"] = result["completed"]
        ajax_meta["ajax_spider_stop_reason"] = result["stop_reason"]  # finished/timeout/user/zap_limit
        ajax_meta["ajax_spider_elapsed_seconds"] = result["elapsed_seconds"]

    messages = collector.get_all_messages(target_url)                # 프록시 히스토리 
    messages, drop = _drop_danger_messages(messages, danger_patterns)  # 프록시 히스토리에도 위험 패턴 적용
    if drop:
        print(f"[ZAP] 위험 패턴 매칭 {len(drop)}건 프록시 히스토리에서 제외")
        for u in drop:
            print(f"       - {u}")

    print(f"[ZAP] 전체 메시지 {len(messages)}건 수집")
    messages_path = os.path.join(out_dir, "zap_messages.json")
    save_json(messages_path, messages)
    print(f"[ZAP] zap_messages.json -> {messages_path}")

    # 수집된 raw 메시지를 scan target으로 정규화
    targets = to_targets(messages)
    targets_path = os.path.join(out_dir, "scan_targets.json")
    target_dicts = [t.to_dict() for t in targets]
    for d in target_dicts:  # 출처 표시: Ajax 실행 이후 새로 잡힌 요청이면 "ajax", 아니면 "spider"
        d["source"] = "ajax" if ajax and d.get("zap_message_id") not in spider_ids else "spider"
    save_json(targets_path, target_dicts)
    print(f"[ZAP] scan_targets.json -> {targets_path} ({len(targets)}건, Ajax 출처 {sum(d['source'] == 'ajax' for d in target_dicts)}건)")

    meta_path = os.path.join(out_dir, "collection_meta.json")
    save_json(meta_path, ajax_meta)
    print(f"[ZAP] collection_meta.json -> {meta_path}")

    return out_dir, targets_path


# CLI 진입점 — run_collection() 호출, 실패 시 기존과 동일한 형식으로 출력 후 종료
def main():
    try:
        out_dir, targets_path = run_collection()
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] ZAP API 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[COLLECT] 완료: {targets_path}")


if __name__ == "__main__":
    main()
