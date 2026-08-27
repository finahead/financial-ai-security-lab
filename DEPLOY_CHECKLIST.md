# 교육 전 배포 체크리스트

- [ ] GitHub 저장소 생성
- [ ] `app.py`, `customers.json`, `policies.json`, `requirements.txt` 업로드
- [ ] `.streamlit/secrets.toml`이 GitHub에 올라가지 않았는지 확인
- [ ] Streamlit Community Cloud 앱 생성
- [ ] `OPENAI_API_KEY` Secret 등록
- [ ] `APP_PASSWORD` 교육용 값으로 변경
- [ ] 외부 PC/스마트폰에서 URL 접속 테스트
- [ ] 취약모드: 시스템 프롬프트 노출 테스트
- [ ] 취약모드: C003 고객정보 조회 테스트
- [ ] 취약모드: `DROP TABLE customers` 또는 UPDATE SQL 시뮬레이션 테스트
- [ ] 취약모드: C003 계좌정지 시뮬레이션 테스트
- [ ] 통제모드: 계좌번호 마스킹 확인
- [ ] 통제모드: 위험 SQL 차단 확인
- [ ] 통제모드: 계좌정지 사람 승인 요구 확인
- [ ] 2~3대 PC에서 동시 접속 테스트
- [ ] 교육 종료 후 앱 중지/비밀번호 변경/API 키 점검 계획 확인
