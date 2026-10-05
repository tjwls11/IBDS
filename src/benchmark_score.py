import csv
import json
import os
import re
import sys

_SRC_ROOT = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_ROOT)
sys.path.insert(0, _SRC_ROOT)  # web.runs import용

from web.runs import latest_out_dir

_EXPECTED_CSV = os.path.join(_PROJECT_ROOT, "config", "benchmark_expected.csv")  # expectedresults-1.2.csv를 이 이름으로 복사
_CATEGORIES = ("sqli", "xss")  # 정답표 카테고리 = 판정기 vuln_type
_TEST_RE = re.compile(r"BenchmarkTest(\d{5})")
_STRICT = {"potential_high", "vulnerable", "vuln"}  # 엄격 기준: HIGH만 취약으로 인정 (구 어휘 포함)
_LOOSE = _STRICT | {"potential_medium", "error_only"}  # 완화 기준: MEDIUM까지 취약으로 인정


# 정답표 로드: {테스트번호: (카테고리, 실제취약여부)}, sqli/xss만 유지
def load_expected(path):
    expected = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0].startswith("#"):  # 헤더 주석 제외
                continue
            m = _TEST_RE.search(row[0])
            if m and row[1].strip() in _CATEGORIES:
                expected[m.group(1)] = (row[1].strip(), row[2].strip().lower() == "true")
    return expected


# JSON/JSONL 로드, 없으면 빈 리스트
def _load(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        if path.endswith(".jsonl"):
            return [json.loads(line) for line in f if line.strip() and line.strip().endswith("}")]
        return json.load(f)


# 수집된 지점(scan_targets)과 판정 결과(findings)를 테스트번호 단위로 집계
def load_results(out_dir):
    collected = set()
    for t in _load(os.path.join(out_dir, "scan_targets.json")):
        if not t.get("params"):  # 파라미터 없는 페이지(DOM fragment 검사용, 예: 폼 안내 .html)는 수집 지점 아님
            continue
        m = _TEST_RE.search(t.get("base_url") or t.get("url") or "")
        if m:
            collected.add(m.group(1))

    statuses = {}  # (테스트번호, vuln_type) -> 판정값 집합
    for fd in _load(os.path.join(out_dir, "findings.jsonl")):
        m = _TEST_RE.search(fd.get("url") or "")
        if m and fd.get("family_id"):  # probe 등 family 없는 기록 제외
            statuses.setdefault((m.group(1), fd["vuln_type"]), set()).add(fd.get("final_status"))
    return collected, statuses


# 카테고리별 TP/FN/FP/TN과 TPR, FPR, 점수(TPR-FPR) 계산 (수집된 지점만 대상)
def score(expected, collected, statuses, positive):
    rows = {}
    for cat in _CATEGORIES:
        tests = {n: real for n, (c, real) in expected.items() if c == cat}
        tp = fn = fp = tn = 0
        for n, real in tests.items():
            if n not in collected:
                continue
            hit = bool(statuses.get((n, cat), set()) & positive)
            tp += real and hit
            fn += real and not hit
            fp += (not real) and hit
            tn += (not real) and not hit
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        rows[cat] = dict(expected=len(tests), collected=tp + fn + fp + tn, TP=tp, FN=fn, FP=fp, TN=tn,
                         TPR=round(tpr, 3), FPR=round(fpr, 3), score=round(tpr - fpr, 3))
    return rows


def main():
    if not os.path.exists(_EXPECTED_CSV):
        sys.exit(f"[ERROR] 정답표 없음: {_EXPECTED_CSV}")
    out_dir = latest_out_dir(_PROJECT_ROOT)
    if out_dir is None:
        sys.exit("[ERROR] results/collection_* 폴더 없음")

    expected = load_expected(_EXPECTED_CSV)
    collected, statuses = load_results(str(out_dir))
    print(f"[BENCH] 결과 폴더: {out_dir}")
    for label, positive in (("엄격(HIGH만)", _STRICT), ("완화(HIGH+MEDIUM)", _LOOSE)):
        print(f"\n== {label} ==")
        for cat, r in score(expected, collected, statuses, positive).items():
            print(f"[{cat}] 수집 {r['collected']}/{r['expected']} | TP={r['TP']} FN={r['FN']} FP={r['FP']} TN={r['TN']} "
                  f"| TPR={r['TPR']} FPR={r['FPR']} 점수={r['score']}")


if __name__ == "__main__":
    main()
