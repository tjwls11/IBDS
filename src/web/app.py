import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from web.execution import ScanManager
from web.models import ConfigPayload
from web.pdf_report import render_pdf
from web.reports import build_report
from web.runs import latest_out_dir, list_runs, resolve_run_dir
from web.settings import PROJECT_ROOT, read_config, write_config

STATIC = Path(__file__).parent / "static"
manager = ScanManager()


# 서버 시작 시 이전 실행 상태 복구
@asynccontextmanager
async def lifespan(app):
    manager.recover()
    yield
    manager.stop()


app = FastAPI(title="IBDS Local", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# 로컬 주소 검증과 기본 응답 정책
@app.middleware("http")
async def local_only(request: Request, call_next):
    if request.headers.get("host", "").split(":")[0] not in {"127.0.0.1", "localhost", "testserver"}:
        return JSONResponse({"detail": "로컬 주소로 접속하세요."}, status_code=403)
    if request.method == "POST" and request.headers.get("x-ibds-client") != "local-ui":
        return JSONResponse({"detail": "웹 화면에서 요청하세요."}, status_code=403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


# 설정 화면 반환
@app.get("/")
def index_page():
    return FileResponse(STATIC / "index.html")


# 실행 화면 반환
@app.get("/run")
def run_page():
    return FileResponse(STATIC / "run.html")


# 리포트 화면 반환
@app.get("/scan")
def scan_page():
    return FileResponse(STATIC / "scan.html")


# 설정 조회
@app.get("/api/config")
def get_config():
    return read_config()


# 실행 중 변경을 차단한 설정 저장
@app.post("/api/config")
def save_config(payload: ConfigPayload):
    with manager.lock:
        if manager.state.running:
            raise HTTPException(409, "스캔이 끝난 뒤 설정을 변경할 수 있습니다.")
        write_config(payload)
    return {"saved": True}


# 스캔 시작
@app.post("/api/scan/start")
def start_scan():
    try:
        return manager.start()
    except ValidationError:
        raise HTTPException(422, "스캔 설정에서 올바른 타겟 URL을 저장하세요.")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))


# 스캔 중지 요청
@app.post("/api/scan/stop")
def stop_scan():
    return manager.stop()


# 실행 상태 조회
@app.get("/api/scan/status")
def scan_status():
    return manager.snapshot()


# 재접속 시 로그 순번부터 이어 보내는 상태 스트림
@app.get("/api/scan/stream")
async def scan_stream(request: Request):
    async def events():
        run_id, cursor = None, 0
        previous = request.headers.get("last-event-id", "")
        if ":" in previous:
            run_id, raw = previous.rsplit(":", 1)
            cursor = int(raw) if raw.isdigit() else 0
        while not await request.is_disconnected():
            data = manager.snapshot(cursor)
            if data["run"] != run_id:
                data = manager.snapshot()
            run_id, cursor = data["run"], data["cursor"]
            yield f"id: {run_id or 'idle'}:{cursor}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


# 과거 실행 목록 조회
@app.get("/api/scans")
def get_scans():
    return {"runs": list_runs(PROJECT_ROOT)}


# 실행별 집계 보고서 조회
@app.get("/api/results")
def get_results(run: str | None = None):
    directory = resolve_run_dir(PROJECT_ROOT, run) if run else latest_out_dir(PROJECT_ROOT)
    if not directory:
        if run:
            raise HTTPException(404, "실행 기록을 찾을 수 없습니다.")
        return {"groups": [], "errors": [], "counts": {}, "error_count": 0,
                "statuses": [], "filter_groups": [], "meta": {}, "run": None}
    return {**build_report(directory), "run": directory.name}


# 실행별 보고서 PDF 파일 내려받기
@app.get("/api/results/export")
def export_results(run: str):
    directory = resolve_run_dir(PROJECT_ROOT, run)
    if not directory:
        raise HTTPException(404, "실행 기록을 찾을 수 없습니다.")
    body = render_pdf({**build_report(directory), "run": directory.name})
    return Response(body, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="ibds_report_{directory.name}.pdf"'})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=1080)
