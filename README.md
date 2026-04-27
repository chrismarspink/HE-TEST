# HE-TEST — Presidio PII Scanner & Microsoft SEAL Demo

문서 내부의 개인정보(PII) 를 감지하고, Microsoft SEAL 동형암호로 암호화된 상태에서 검색·연산까지 수행해 볼 수 있는 로컬 웹 데모입니다.

세 개의 탭으로 구성되어 있습니다.

| 탭 | 설명 | 사용 라이브러리 |
| --- | --- | --- |
| **PII Scanner** | 파일 드래그앤드롭 → 정규식 + 키워드 룰로 PII / 민감정보 감지 | Microsoft Presidio (또는 lite 버전: 순수 Python regex) |
| **SEAL Demo**   | BFV/CKKS 스킴으로 벡터 암호화 → 암호문 상태로 +, −, ×, square, negate → 복호화 | node-seal (브라우저 WASM) |
| **RRN Search (HE)** | 문서 안의 주민등록번호를 **복호화 없이** 동형연산으로 검색 (Exact / Pattern) | node-seal |

📖 **`/docs`** 페이지 — 서버 실행 후 [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs) — 동형암호 개념, 키 4종의 역할/보호 레벨, 노이즈 예산, 패턴 매칭 트릭을 정리한 설명 페이지.

추가 기능:

- **사용자 정의 룰** (`custom_patterns.yaml`) — 정규식·키워드 인식기 자유롭게 추가
- **키 / 암호문 직렬화** — Public/Secret/Relin Key 와 Encryption Parameters, Ciphertext 를 base64 로 보고/복사/다운로드
- **RRN 검색 묶음 다운로드** — 모든 후보 ct + 서버 결과 ct + 메타를 JSON 한 파일로 저장

---

## 1. 시작하기 — Python 환경

> **권장 Python 버전: 3.11 또는 3.12**
>
> Python 3.13/3.14 는 spaCy 의존성(`blis`)이 prebuilt wheel 을 제공하지 않아 컴파일 실패하는 경우가 많습니다.
> 3.13/3.14 사용자는 [3-B 의 lite 버전](#3-b-lite-버전-app_litepy--python-31x--유지) 을 사용하세요.

### 1-A. Python 3.12 설치 (Windows)

**winget 사용 (권장):**
```powershell
winget install -e --id Python.Python.3.12
```

또는 https://www.python.org/downloads/release/python-3128/ 에서 64-bit installer 를 받아 **"Add python.exe to PATH"** 체크 후 설치.

설치 확인:
```powershell
py -0
py -3.12 --version
```

### 1-B. 저장소 받기

```powershell
git clone https://github.com/chrismarspink/HE-TEST.git
cd HE-TEST
```

---

## 2. 의존성 설치 & 실행 (Presidio 풀버전)

### 2-A. 가상환경 생성 + 활성화

PowerShell:
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> `Activate.ps1` 실행 정책 오류가 나면 한번만:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

활성화 확인 — 프롬프트가 `(.venv)` 로 시작하고 다음이 3.12 출력:
```powershell
python -c "import sys; print(sys.version)"
```

### 2-B. 패키지 설치

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2-C. 서버 실행

```powershell
python app.py
```

브라우저에서 http://127.0.0.1:5000 접속.

---

## 3. lite 버전 (spaCy/Presidio 없이) — Python 3.13/3.14 또는 빠른 실행용

spaCy 컴파일 문제를 우회하고 싶다면 [`app_lite.py`](app_lite.py) 를 사용합니다. 정규식·키워드 룰 기반 PII 스캐너 + SEAL/RRN 탭 그대로 동작 (단 Presidio 의 NER 기반 PERSON/LOCATION/ORG 자동 감지는 제외).

### 3-A. 의존성 설치

```powershell
py -3.12 -m venv .venv     # 또는 py -3.14
.\.venv\Scripts\Activate.ps1
pip install -r requirements_lite.txt
```

### 3-B. 실행

```powershell
python app_lite.py
```

브라우저에서 http://127.0.0.1:5000

---

## 4. 사용자 정의 룰 추가 (PII Scanner)

[custom_patterns.yaml](custom_patterns.yaml) 을 열어 룰을 추가/수정한 뒤,

- 서버 재시작 **또는**
- 웹 UI 의 **"Reload Patterns"** 버튼

으로 반영됩니다.

### 정규식 기반 인식기

```yaml
pattern_recognizers:
  - name: MY_TICKET_ID
    supported_entity: MY_TICKET_ID
    supported_language: en
    patterns:
      - name: ticket
        regex: '\bTKT-\d{6}\b'
        score: 0.9
    context: [ticket, 티켓]
```

### 키워드 기반(deny-list) 인식기

```yaml
deny_list_recognizers:
  - name: SECRET_PROJECTS
    supported_entity: SECRET_PROJECT
    supported_language: en
    deny_list: [ProjectAlpha, 프로젝트사일런스]
    score: 0.95
```

기본 포함 룰: 한국 주민등록번호 / 휴대폰 / 사업자등록번호 / 여권, AWS Access Key, 일반 시크릿 후보, 내부 프로젝트명 / VIP 명단.

---

## 5. SEAL 탭 사용법

탭 클릭 시 자동으로 node-seal WASM 을 unpkg CDN 에서 로드합니다 (네트워크 필요).

1. **Scheme / poly_modulus_degree** 선택 후 **Initialize / Reset**
   - BFV: 정수 벡터, 정확 연산 (덧/뺄/곱/제곱/부호반전)
   - CKKS: 실수 벡터, 근사 연산
2. **Vector A / B** 입력 후 각각 **Encrypt**
3. 연산 종류 선택 → **Compute on Ciphertexts** (서버는 비밀키 없이 동형연산만 수행)
4. **Decrypt Result** → 복호화하여 평문 결과와 비교 (✓ MATCH / ✗ MISMATCH)

오른쪽 카드:
- **키** — Encryption Parameters / Public Key / Secret Key / Relin Keys 를 base64 로 보고, 복사하고, `.b64.txt` 로 다운로드
- **암호문** — ctA / ctB / Result 를 같은 방식으로 처리
- **로그** — 각 단계 타이밍과 noise budget(진단)

> ⚠ **Secret Key** 는 데모 용으로만 표시합니다. 실서비스에서는 **절대 외부로 유출 금지**.

---

## 6. RRN Search (HE) 탭 사용법

문서 내부의 주민등록번호를 **복호화 없이** 검사합니다.

### Exact match
- 클라이언트가 `\d{6}-?[1-4]\d{6}` 로 후보 추출 → BFV 암호화
- 서버: `(ct − Plain(target))²` (깊이 1)
- 클라이언트: 슬롯 0..12 합 = 0 → MATCH

### Pattern match
- 클라이언트가 13자리 시퀀스를 모두 후보로 추출 (성별자리 검증 X) → BFV 암호화
- 서버: `((ct−1)(ct−2)) × ((ct−3)(ct−4))` 다항식 동형 평가 (깊이 2)
- 클라이언트: 슬롯 6 (성별자리) 값 = 0 → 유효한 RRN 형식

> 이 탭은 곱셈 깊이 2 를 안전하게 처리하기 위해 자동으로 `poly_modulus_degree = 8192` 컨텍스트를 사용합니다.

**Download bundle (JSON)** 버튼으로 모든 후보 ct + 서버 결과 ct + Encryption Parameters/Public Key/Relin Keys 를 한 JSON 으로 받을 수 있습니다.

---

## 7. 디렉토리 구조

```
HE-TEST/
├─ app.py                  # Flask + Presidio 서버 (Python 3.11/3.12)
├─ app_lite.py             # spaCy 없는 lite 버전 (Python 3.10~3.14)
├─ custom_patterns.yaml    # 사용자 정의 룰
├─ requirements.txt        # Presidio 풀버전 의존성
├─ requirements_lite.txt   # lite 버전 의존성
├─ sample.txt              # 테스트용 PII 문서
├─ templates/
│  └─ index.html           # 3-탭 UI (PII Scanner / SEAL / RRN Search)
└─ README.md
```

---

## 8. API (Flask)

| Method | Path                | 설명 |
| ------ | ------------------- | ---- |
| GET    | `/`                 | 3-탭 UI |
| POST   | `/api/analyze`      | `file` (multipart) + `score_threshold` 받아 PII 분석 |
| GET    | `/api/recognizers`  | 활성화된 인식기 목록 / 지원 엔티티 |
| POST   | `/api/reload`       | `custom_patterns.yaml` 재로드 |

SEAL/RRN 탭은 모두 **브라우저 WASM** 으로 동작 — 키/평문/암호문이 서버로 전송되지 않습니다.

---

## 9. 자주 묻는 문제

**Q. SEAL 탭에서 "node-seal 라이브러리를 불러오지 못했습니다" 오류**
→ 사내 네트워크가 unpkg.com 을 차단할 수 있습니다. 다음 중 하나로 해결:
- `templates/index.html` 의 `<script src="https://unpkg.com/...">` 를 jsDelivr 로 변경
  ```html
  <script src="https://cdn.jsdelivr.net/npm/node-seal@5.1.5/throws_wasm_web_umd.js"></script>
  ```
- 또는 `npm i node-seal` 후 `node_modules/node-seal/throws_wasm_web_umd.js` 와 `*.wasm` 을 `static/seal/` 로 복사하고 src 를 `/static/seal/...` 로 변경

**Q. RRN Pattern match 모드에서 진짜 RRN 인데 INVALID 가 뜸**
→ 노이즈 예산 부족. 자동으로 `poly_modulus_degree=8192` 로 재초기화되어야 합니다. SEAL 탭에서 `Initialize / Reset` 클릭 후 다시 시도. 로그의 `noise budget` 이 10 bits 미만이면 더 큰 poly_deg 가 필요합니다.

**Q. spaCy 설치 시 `blis` 컴파일 실패 (Python 3.13/3.14)**
→ Python 3.12 가상환경을 사용하거나 `requirements_lite.txt` + `app_lite.py` 사용.

---

## 10. 라이선스 / 책임 한계

이 코드는 **데모/학습 목적** 입니다. 실제 운영 환경에 적용하려면:

- 비밀키는 절대 화면에 노출되지 않도록 분리 (현재는 데모 편의로 표시)
- HE 파라미터 (poly_modulus_degree, plain_modulus, security level) 를 위협 모델에 맞게 재검토
- Presidio 의 한국어 NER 정확도 한계 고려 — 자연어 인명/주소는 별도 모델 권장
- RRN 후보 검색은 정규식 추출에 의존 — 띄어쓰기/특수문자가 끼어든 변형은 보강 필요
