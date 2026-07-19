# 보안 체크리스트 점검 결과

강의에서 제공된 체크리스트(`secure_coding_checklist.csv`) 기준으로 점검한 결과입니다.
각 항목은 자동화 테스트(`tests/`) 또는 코드 확인으로 검증했습니다.

## 회원가입 및 프로필 관리

- [x] 서버측 입력 검증 — 아이디 정규식/비밀번호 정책 서버 검증 (`forms.py`) · 검증 테스트: `test_register_rejects_weak_password`, `test_register_rejects_bad_username`
- [x] CSRF 보호 — 전 폼 CSRFProtect 적용 · 테스트: `test_post_without_csrf_token_rejected`
- [x] 비밀번호 보안 — scrypt + 고유 salt 해시 저장 · 테스트: `test_password_stored_hashed`
- [x] 세션 쿠키 설정 — HttpOnly + SameSite=Lax, HTTPS용 Secure 옵션 · 테스트: `test_session_cookie_httponly`
- [x] 세션 만료 및 재인증 — 30분 만료, 비밀번호 변경 시 현재 비밀번호 재확인 · 테스트: `test_password_change_requires_current_password`
- [x] 실패 로그인 방어 — 5회 실패 시 5분 잠금 + IP 레이트리밋 · 테스트: `test_account_lockout_after_failures`
- [x] 오류 메시지 — 동일 실패 메시지(계정 열거 방지), 커스텀 에러 페이지 · 테스트: `test_login_wrong_password_generic_error`

## 상품 등록 및 관리

- [x] 폼 입력 검증 — 제목/설명 길이, 가격 숫자·범위(0~1억) 서버 검증
- [x] XSS 방어 — autoescape 유지, `|safe` 미사용 · 테스트: `test_xss_in_product_description_escaped`
- [x] 인증된 사용자만 등록 — `login_required` · 테스트: `test_anonymous_redirected_to_login`
- [x] 소유자 확인 — 수정/삭제 시 소유자·관리자 검증(403) · 테스트: `test_idor_cannot_edit_others_product`
- [x] 데이터 무결성 — WTForms 검증 통과분만 DB 저장
- [x] (추가) 파일 업로드 검증 — 확장자 + 매직바이트 + 랜덤 파일명 + 2MB 제한 · 테스트: `test_fake_image_upload_rejected`, `test_real_png_upload_saved_with_random_name`

## 실시간 채팅 및 메시징

- [x] 메시지 내용 검증 — 서버측 1~500자 제한, 클라이언트 textContent 렌더링
- [x] 사용자 인증 — connect 시 세션 검증, 미인증 거부 (`sockets.py`)
- [x] 메시지(방) 검증 — join/send 시 방 멤버십 서버 검증 · 테스트: `test_user_in_room_authorization`
- [x] Rate Limiting — 3초당 5개 메시지 제한
- [x] 연결 암호화 — ngrok/리버스 프록시 HTTPS 시 WSS 자동 적용 (README 안내)

## 안전 거래 및 신고

- [x] 폼 입력 검증 — 신고 사유 5~500자 필수, 대상 존재 검증
- [x] 인증된 사용자 접근 — 신고·송금 모두 `login_required`
- [x] 데이터 무결성 및 로그 관리 — 신고/송금/차단 모두 AuditLog 기록, 관리자 열람 가능
- [x] 신고 남용 방지 — 1인 1회 UNIQUE 제약, 시간당 5회 제한, 관리자 기각 처리 · 테스트: `test_duplicate_report_rejected`, `test_product_blocked_after_threshold_reports`
- [x] (추가) 송금 경쟁조건 방어 — 조건부 UPDATE로 원자적 차감 · 테스트: `test_transfer_*` 4종

## 전체 시스템

- [x] ORM 및 파라미터 바인딩 — 전 쿼리 SQLAlchemy, LIKE 이스케이프 · 테스트: `test_search_sql_injection_is_inert`, `test_search_like_wildcards_literal`
- [x] 데이터베이스 권한 — SQLite 파일을 `instance/`에 격리, git 제외 (운영 전환 시 DB 계정 최소권한 필요 — SECURITY.md 한계 참고)
- [x] 보안 헤더 설정 — CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy · 테스트: `test_security_headers_present`
- [x] HTTPS 적용 — `SESSION_COOKIE_SECURE=1` 옵션 및 ngrok HTTPS 안내 (README)
- [x] 에러 및 예외 처리 — 커스텀 에러 페이지, 스택트레이스 미노출, 디버그 기본 꺼짐
- [x] 라이브러리 및 의존성 관리 — 최신 안정 버전 명시(`requirements.txt`), 하한 버전 지정

## 기능 요구사항 체크

- [x] 회원가입(중복 아이디 방지) / 로그인 / 로그아웃
- [x] 사용자 프로필 조회, 마이페이지(소개글·비밀번호 변경)
- [x] 상품 등록(상품명/설명/가격/사진), 내 상품 관리
- [x] 상품 목록(이름만 표시) → 클릭 시 상세 페이지
- [x] 상품 검색
- [x] 전체 실시간 채팅, 1:1 채팅
- [x] 사용자/상품 신고(사유 필수)
- [x] 일정 횟수 이상 신고된 상품 차단 / 사용자 휴면 전환
- [x] 유저 간 송금
- [x] 관리자 페이지(사용자·상품·신고·로그 전체 관리)

전체 테스트 실행: `python -m pytest tests/ -v` → **33 passed**
