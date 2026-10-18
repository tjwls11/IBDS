# Biscan

Biscan은 웹 애플리케이션의 SQL Injection(SQLi)과 Cross-Site Scripting(XSS) 취약점을 점검하고 결과를 보고서로 정리하는 도구입니다.

## 요구 사항

- Python 3.11
- OWASP ZAP 및 ZAP API 접근 정보

## 설치

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

ZAP을 실행하고 저장소 루트의 `config/target_config.json`에 대상 주소를 설정합니다. `zap_setup.ps1`은 ZAP을 구성하고 `config/zap_config.json`과 루트 인증서를 생성합니다. 실제 대상에 허가를 받은 경우에만 스캔하세요.

## 실행

웹 애플리케이션 진입점은 `src/web/app.py`입니다. 저장소 루트에서 다음과 같이 실행합니다.

```powershell
python src\web\app.py
```

브라우저에서 `http://127.0.0.1:1080`을 열고 대상과 스캔 설정을 확인한 뒤 실행합니다. 수집 결과와 보고서는 `results/` 아래 실행별 폴더에 저장됩니다.

## SQLi 판정

SQLi 판정은 단일 규칙을 사용합니다. Boolean 기반 판정은 동적 응답 영역과 반사된 payload를 제거하고, 기준 응답 유사도와 비-SQL 대조 요청의 잡음을 고려해 참/거짓 응답의 분기를 확인합니다. 높은 신뢰도로 판정하려면 여러 pair에서 방향이 일치하고 참·거짓 결과가 반복 재현되어야 합니다. 시간 기반 판정도 기준 및 대조 응답을 비교하고 지연이 반복될 때 높은 신뢰도로 판정합니다. 오류 및 정보 추출 기반 판정은 기준 응답에 없던 데이터베이스 오류 또는 응답에만 나타난 추출 마커를 확인합니다.

## 저장소 구성

- `src/`: 수집, SQLi/XSS 분석, 오케스트레이션, 웹 UI와 보고서
- `config/`: 대상 및 ZAP 설정
- `test/`: 판정 및 기능 테스트
- `examples/`: 입력 예시
- `results/`: 스캔 실행 결과
- `expectedresults-1.2.csv`: OWASP Benchmark 정답 데이터

SQLi E0~E3 단계별 재판정 스크립트는 실험용으로 제거했습니다. 일반 스캔은 위에 설명한 반복 재현을 포함한 SQLi 판정 규칙을 사용합니다.
