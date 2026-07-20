# Tiny Second-hand Shopping Platform

시큐어 코딩 과제로 개발한 중고거래 웹 플랫폼입니다.
Flask + Flask-SocketIO + SQLite 기반이며, 개발 전 과정에서 보안 약점을 제거하는 것을 목표로 했습니다.

## 주요 기능

- **유저 관리**: 회원가입(아이디 중복 방지), 로그인(실패 잠금), 프로필 조회, 마이페이지(소개글·비밀번호 변경)
- **상품 관리**: 상품 등록(상품명·설명·가격·사진), 내 상품 관리(수정·삭제), 상품 목록(이름만 표시)·상세 페이지, 상품명 검색
- **유저 소통**: 실시간 전체 채팅, 1:1 채팅 (Socket.IO)
- **신고/차단**: 사용자·상품 신고(사유 필수), 일정 횟수 이상 신고된 상품 자동 차단, 사용자 자동 휴면 전환
- **송금**: 유저 간 잔액 송금(동시성 안전), 거래 내역
- **관리자**: 사용자(상태·권한), 상품(차단·삭제), 신고 처리, 감사 로그 등 플랫폼 전체 관리

## 환경 설정

**Linux(Ubuntu/WSL) 환경에서 실행하는 것을 전제로 합니다.** Windows 네이티브 환경은 지원 대상이 아닙니다.

miniconda 기준:

```bash
git clone https://github.com/kingsthegarden/tiny-secondhand-shopping-platform.git
cd tiny-secondhand-shopping-platform

conda env create -f environments.yaml
conda activate secure_coding
```

conda 없이 pip만 사용하는 경우:

```bash
pip install -r requirements.txt
```

## 실행 방법

```bash
# 1. 관리자 계정 생성 (최초 1회) — 대화형으로 실행하면 비밀번호 입력 프롬프트가 나타남
flask --app app create-admin admin
# (8자 이상, 영문+숫자 포함)

# 2. 서버 실행
python app.py
# → http://localhost:5000
```

자동 채점 스크립트 등 비대화형(non-interactive) 환경에서는 `--password` 옵션으로 프롬프트 없이 바로 생성할 수 있습니다:

```bash
flask --app app create-admin admin --password 'AdminPass1'
```

- 데이터베이스(SQLite)와 세션 서명 키는 최초 실행 시 `instance/` 아래에 자동 생성됩니다.
- 포트 변경: `PORT=8080 python app.py`

가입 직후에는 상품이 하나도 없어 목록이 비어 보입니다. 둘러보기용 데모 상품을 채워 넣으려면(선택 사항, 반복 실행해도 안전):

```bash
flask --app app seed-demo
```

`demo_seller`라는 판매 전용 계정(비밀번호는 매번 랜덤 생성, 로그인 용도로 쓰이지 않음) 아래에 샘플 상품 6개가 등록됩니다.

외부에서 접속 테스트를 하려면 ngrok을 사용합니다:

```bash
ngrok http 5000
```

HTTPS(ngrok 등) 환경에서는 세션 쿠키에 Secure 플래그를 켜세요:

```bash
SESSION_COOKIE_SECURE=1 python app.py
```

## 테스트

기능 및 보안 테스트 43개가 포함되어 있습니다 (CSRF 보호를 켠 상태 그대로 검증):

```bash
python -m pytest tests/ -v
```

## 프로젝트 구조

```
app.py                  # 실행 진입점
config.py               # 설정(보안 관련 설정 집중)
market/
  __init__.py           # 앱 팩토리, 보안 헤더, 에러 핸들러
  models.py             # DB 모델 (User/Product/Report/ChatMessage/Transfer/AuditLog)
  forms.py              # 입력 검증 + CSRF (Flask-WTF)
  utils.py              # 인증 데코레이터, 레이트리밋, 안전한 파일 업로드
  sockets.py            # 실시간 채팅 (인증·인가·검증 포함)
  routes/               # auth / main / products / users / chat / wallet / reports / admin
  templates/, static/
tests/                  # 기능·보안 테스트
SECURITY.md             # 개발 과정에서 확인한 보안 약점과 조치 내역
CHECKLIST.md            # 보안 체크리스트 및 점검 결과
```

## 보안 문서

- 개발 중 확인·조치한 보안 약점: [SECURITY.md](SECURITY.md)
- 보안 체크리스트 점검 결과: [CHECKLIST.md](CHECKLIST.md)
