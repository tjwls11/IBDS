from html import escape
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

# 화면 report.js와 같은 용어
_VERDICT = {"potential_high": "취약 가능성 높음", "potential_medium": "취약 신호 관찰",
            "inconclusive": "검토 필요", "potential_low": "공격 근거 미확인"}
_ORDER = list(_VERDICT)
_PROGRESS = {"completed": "완료", "partial": "부분 완료", "failed": "실패", "not_run": "미실행"}
_REASON = {"delivery_unknown": "전송 결과 불명", "attack_request_failed": "공격 요청 실패", "baseline_failed": "기준 요청 실패",
           "auth_failed": "인증 실패", "session_expired": "세션 만료", "discovery_failed": "사전 확인 요청 실패",
           "prepare_failed": "준비 단계 실패", "revisit_url_missing": "재조회 주소 없음", "revisit_failed": "재조회 실패",
           "sink_not_confirmed": "저장 위치 미확인", "browser_timeout": "브라우저 시간 초과", "browser_failed": "브라우저 실행 실패",
           "state_unclear": "이번 시도와 구분 불가", "cancelled_by_user": "사용자 중단", "out_of_scope": "범위 밖 이동",
           "not_reached": "앞 단계 실패로 미도달"}
_STAGE = {"completed": "검사 완료", "stopped": "사용자에 의해 중단됨", "failed": "실패로 중단됨",
          "interrupted": "서버 종료로 중단됨", "scanning": "검사 진행 중", "collecting": "요청 수집 중"}
_VULN = {"xss": "XSS", "sqli": "SQLi"}
_TITLE = "IBDS 검사 보고서"
_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI','Malgun Gothic',sans-serif"
_MARGIN = {"top": "20mm", "bottom": "20mm", "left": "18mm", "right": "18mm"}

# 웹 화면의 글꼴과 판정 색을 따르는 A4 인쇄용 스타일
_CSS = """
:root{--ink:#202124;--muted:#69717c;--line:#e3e6ea}
html{font-size:10pt}
body{margin:0;font-family:%s;color:var(--ink);line-height:1.6;word-break:keep-all}
code,pre{font-family:Consolas,'D2Coding',monospace}
h1{font-size:20pt;margin:0 0 8pt;line-height:1.3}
h2{font-size:14pt;margin:26pt 0 10pt;line-height:1.3;break-after:avoid}
h3{font-size:11pt;margin:18pt 0 6pt;break-after:avoid}
h3 .count{font-weight:400;color:var(--muted);margin-left:6pt}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:2pt 14pt;margin:0 0 6pt;color:var(--muted)}
.meta dd{margin:0;color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:0 14pt;margin:4pt 0 10pt}
.kpi{border-top:2px solid currentColor;padding-top:4pt}
.kpi span{display:block;font-size:9pt}
.kpi strong{font-size:18pt;line-height:1.2}
.rates{margin:0;color:var(--muted)}
.rates b{color:var(--ink)}
table{border-collapse:collapse;width:100%%;font-size:9.5pt}
th,td{text-align:left;padding:6pt 10pt 6pt 0;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-weight:700;font-size:9pt;color:var(--muted);border-bottom:1.5px solid var(--ink)}
th,td.nowrap{white-space:nowrap}
thead{display:table-header-group}
tr,pre,.card{break-inside:avoid}
td.url{word-break:break-all}
table.points{table-layout:fixed}
table.points td{word-break:break-all}
td .note{display:block;font-size:8.5pt;color:var(--muted)}
.badge{display:inline-block;padding:1pt 6pt;border-radius:3pt;font-size:8.5pt;font-weight:600;white-space:nowrap}
.potential_high{color:#b83932}.badge.potential_high{background:#fcecea}
.potential_medium{color:#986213}.badge.potential_medium{background:#fff4df}
.inconclusive{color:#706683}.badge.inconclusive{background:#f0edf5}
.potential_low{color:#2d7756}.badge.potential_low{background:#eaf5ef}
.completed{color:#2d7756}.badge.completed{background:#eaf5ef}
.partial{color:#986213}.badge.partial{background:#fff4df}
.failed{color:#b83932}.badge.failed{background:#fcecea}
.not_run,.unknown{color:#586878}.badge.not_run,.badge.unknown{background:#f1f3f6}
.card{padding:10pt 0;border-bottom:1px solid var(--line)}
.card-head{display:flex;align-items:baseline;gap:6pt;flex-wrap:wrap}
.card-head strong{font-size:11pt}
.card-head .url{color:var(--muted);word-break:break-all}
.card code.id{display:block;font-size:8pt;color:var(--muted);margin:1pt 0 4pt}
.card dl{display:grid;grid-template-columns:max-content 1fr;gap:2pt 12pt;margin:4pt 0;font-size:9pt}
.card dt{color:var(--muted)}
.card dd{margin:0;word-break:break-all}
pre{font-size:8.5pt;white-space:pre-wrap;word-break:break-all;margin:6pt 0 0;padding:5pt 7pt;background:#f6f7f9;border-radius:3pt}
.muted{color:var(--muted)}
""" % _FONT


def _e(value):
    return escape("" if value is None else str(value))


def _pct(value):
    return f"{value * 100:.1f}%"


# 판정이나 진행 상태 색 태그
def _badge(status, label):
    cls = status if status in _VERDICT or status in _PROGRESS else "unknown"
    return f'<span class="badge {cls}">{_e(label.get(status, status or "기록 없음"))}</span>'


# 진행 상태 태그와 사유 한 줄
def _progress_cell(status, reason):
    note = f'<span class="note">사유 {_e(_REASON.get(reason, reason))}</span>' if reason else ""
    return f'<td class="nowrap">{_badge(status, _PROGRESS)}{note}</td>'


# 경로와 쿼리만 남긴 요청 주소, 호스트는 머리 정보에 표시
def _path(url):
    parts = urlparse(url or "")
    return parts.path + (f"?{parts.query}" if parts.query else "") if parts.netloc else url or ""


# 취약 가능성 높음, 취약 신호 관찰 지점의 대표 근거 카드, 같은 판정의 나머지 시도는 건수만 표시
def _card(group, item, others):
    browser = item.get("browser")
    facts = [("기법", item.get("category")), ("기대 식별값", item.get("exec_token")),
             ("브라우저 확인", browser and ("실행됨" if browser.get("executed") else "실행 안 됨")
              + (f", {browser['evidence']}" if browser.get("evidence") else "")),
             ("저장 표식", item.get("probe_marker")), ("재조회 주소", item.get("revisit_url")),
             ("근거", item.get("evidence")), ("같은 판정 시도", others and f"{others}건 더")]
    rows = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in facts if v)
    payload = f"<pre>{_e(item['payload'])}</pre>" if item.get("payload") is not None else ""
    note = f'<span class="muted">사유 {_e(_REASON.get(item["reason"], item["reason"]))}</span>' if item.get("reason") else ""
    return (f'<div class="card"><div class="card-head">{_badge(item["final_status"], _VERDICT)}'
            f'{_badge(item.get("progress_status"), _PROGRESS)}<strong>{_e(group["param"])}</strong>'
            f'<span class="url">{_e(group["method"])} {_e(_path(group["url"]))}</span>{note}</div>'
            f'<code class="id">{_e(item.get("case_id"))}</code><dl>{rows}</dl>{payload}</div>')


# build_report 결과를 보고서 HTML로 변환
def render_html(report):
    groups = sorted(report["groups"], key=lambda g: (_ORDER.index(g["final_status"]) if g["final_status"] in _ORDER else 9,
                                                     g["url"], g["param"]))
    meta, rates, counts = report.get("meta") or {}, report.get("rates") or {}, report.get("counts") or {}
    hosts = sorted({urlparse(g["url"]).netloc for g in groups if g["url"]})

    head = [("실행", report["run"]), ("검사 대상", ", ".join(hosts) or "기록 없음"),
            ("검사 시각", f"{meta.get('started_at', '')} ~ {meta.get('finished_at', '')}".strip(" ~")),
            ("실행 상태", _STAGE.get(meta.get("stage"), meta.get("stage")))]
    kpis = "".join(f'<div class="kpi {key}"><span>{_e(label)}</span><strong>{counts.get(key, 0)}</strong></div>'
                   for key, label in _VERDICT.items())
    rates_line = (f"검사 지점 <b>{rates.get('points', len(groups))}개</b>, 완료율 <b>{_pct(rates['completion'])}</b>, "
                  f"검토 필요율 <b>{_pct(rates['inconclusive'])}</b>, 침묵 음성 <b>{rates['silent_negatives']}건</b>, "
                  f"오류 <b>{report.get('error_count', 0)}건</b>") if rates else f"검사 지점 <b>{len(groups)}개</b>"

    # 판정별로 나눈 검사 지점 표
    tables = ""
    for key, label in _VERDICT.items():
        part = [g for g in groups if g["final_status"] == key]
        if not part:
            continue
        rows = "".join(
            f"<tr><td class=\"nowrap\">{_e(_VULN.get(g['vuln_type'], g['vuln_type']))}</td><td>{_e(g['param'])}</td>"
            f"<td class=\"url\">{_e(g['method'])} {_e(_path(g['url']) or g['target_id'])}</td>"
            f"{_progress_cell(g['progress_status'], g['reason'])}</tr>" for g in part)
        tables += (f'<h3><span class="{key}">{_e(label)}</span><span class="count">{len(part)}개</span></h3>'
                   '<table class="points"><thead><tr><th style="width:10%">종류</th><th style="width:20%">파라미터</th>'
                   '<th>요청</th><th style="width:24%">진행 상태</th></tr></thead>'
                   f"<tbody>{rows}</tbody></table>")
    cards = ""
    for g in groups:
        same = [item for item in g["items"] if item.get("final_status") == g["final_status"]]
        if g["final_status"] in ("potential_high", "potential_medium") and same:
            cards += _card(g, same[0], len(same) - 1)
    errors = "".join(f"<tr><td class='nowrap'>{_e(x.get('target_id'))}</td><td>{_e(x.get('param'))}</td><td class='nowrap'>{_e(x.get('stage') or 'request')}</td>"
                     f"<td>{_e(x.get('error'))}</td></tr>" for x in report.get("errors") or [])

    body = [f"<h1>{_TITLE}</h1>",
            '<dl class="meta">' + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in head) + "</dl>",
            "<h2>요약</h2>", f'<div class="kpis">{kpis}</div>', f'<p class="rates">{rates_line}</p>',
            "<h2>1. 검사 지점별 판정</h2>", tables or '<p class="muted">검사 지점 없음</p>',
            "<h2>2. 취약 판정 근거</h2>", cards or '<p class="muted">취약 가능성 높음, 취약 신호 관찰 판정 없음</p>']
    if errors:
        body += ["<h2>3. 오류</h2>",
                 "<table><thead><tr><th>대상</th><th>파라미터</th><th>단계</th><th>원인</th></tr></thead>"
                 f"<tbody>{errors}</tbody></table>"]
    return (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{_TITLE}</title>'
            f"<style>{_CSS}</style></head><body>{''.join(body)}</body></html>")


# 보고서 HTML을 A4 PDF로 출력, 머리말은 제목, 꼬리말은 쪽 번호
def render_pdf(report):
    small = f"font-family:{_FONT};font-size:8pt;color:#69717c;width:100%;padding:0 18mm;"
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            page.set_content(render_html(report), wait_until="load")
            return page.pdf(format="A4", margin=_MARGIN, print_background=True, display_header_footer=True,
                            header_template=f'<div style="{small}">{_TITLE} {_e(report["run"])}</div>',
                            footer_template=f'<div style="{small}text-align:right"><span class="pageNumber"></span> / <span class="totalPages"></span></div>')
        finally:
            browser.close()
