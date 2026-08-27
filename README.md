# 금융 AI 보안 실습 챗봇

OWASP LLM 위험을 **취약모드 / 통제모드**로 비교하기 위한 교육용 Streamlit 앱입니다.
실제 금융시스템과 연결되지 않으며 모든 고객·계좌·SQL·계좌정지는 가상 시뮬레이션입니다.

## 포함된 실습

1. Prompt Injection — 시스템 프롬프트 공개 유도
2. Sensitive Information Disclosure — 가상 고객정보 노출/마스킹 비교
3. Improper Output Handling — AI 생성 SQL의 검증 없는 실행 위험
4. Excessive Agency — AI의 계좌정지 Tool 자동 실행 vs 사람 승인

## 로컬 실행

Python 3.11~3.12 권장.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

`.streamlit/secrets.toml.example`을 복사해 `.streamlit/secrets.toml`을 만들고 값을 입력합니다.

```toml
OPENAI_API_KEY = "sk-..."
APP_PASSWORD = "training2026"
MODEL = "gpt-5-mini"
MAX_REQUESTS_PER_SESSION = 12
```

실행:

```bash
streamlit run app.py
```

브라우저에서 보통 `http://localhost:8501`로 접속합니다.

## Streamlit Community Cloud 배포

1. GitHub에 새 저장소를 만들고 이 폴더의 파일을 업로드합니다.
2. `.streamlit/secrets.toml`은 **절대로 GitHub에 올리지 않습니다**. `.gitignore`에 포함되어 있습니다.
3. Streamlit Community Cloud에 GitHub 계정으로 로그인합니다.
4. `Create app` → 저장소 선택 → `app.py` 지정.
5. `Advanced settings` 또는 App settings의 Secrets에 아래 내용을 입력합니다.

```toml
OPENAI_API_KEY = "sk-..."
APP_PASSWORD = "교육당일비밀번호"
MODEL = "gpt-5-mini"
MAX_REQUESTS_PER_SESSION = 12
```

6. Deploy 후 생성된 `https://...streamlit.app` 주소를 외부 PC에서 테스트합니다.
7. 교육 종료 후 앱을 중지하거나 비밀번호/API 키를 교체합니다.

## 30명 교육 권장 운영

- 2인 1조(15조) 권장
- 조별로 4개 미션을 배분한 뒤 취약모드와 통제모드에서 같은 프롬프트를 반복
- 한 세션당 API 호출을 12회로 제한(Secrets에서 변경 가능)
- 실제 개인정보, 실제 사규, 실제 계좌/DB/API는 절대 연결하지 않음

## 강사가 보여줄 핵심

통제모드는 모델을 바꾼 것이 아니라 **애플리케이션 코드에서 실제 권한과 실행조건을 제한**한 것입니다.

- 시스템 프롬프트 비공개
- 계좌번호 마스킹
- SQL SELECT Allowlist
- 고위험 Tool 사람 승인
- 요청/차단 로그

즉, "AI에게 하지 말라고 부탁"하는 것이 아니라 "시스템적으로 못 하게 만드는 것"을 보여주는 실습입니다.
