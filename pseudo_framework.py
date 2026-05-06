"""
파일/문서 가명화·익명화 PoC 프레임워크.

표준 기반:
  - ISO/IEC 20889:2018  Privacy enhancing data de-identification terminology
                        and classification of techniques
  - ISO/IEC 27559:2022  Privacy enhancing data de-identification framework
용어 기반:
  - W3C DPV 2.0 (Data Privacy Vocabulary) — dpv-pd:* compact IRI

규제 매트릭스:
  - KR  개인정보보호법 + 개인정보보호위원회 가명정보 처리 가이드라인
  - JP  個人情報保護法 (APPI) + 仮名加工情報・匿名加工情報の作成基準
  - US  HIPAA Safe Harbor (45 CFR §164.514(b)(2)) + CCPA/CPRA + NIST SP 800-188
  - EU  GDPR Art. 4(5), Recital 26 + EDPB Guidelines 01/2025 + WP29 Op. 05/2014

본 모듈은 PII Scanner 의 검출 결과(findings)를 입력으로 받아,
ISO 20889 의 기법 카탈로그에 따라 변환을 적용하고
관할별 준수 여부를 판정합니다 (PoC — 실 운영 시 법무 검토 필수).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple


# =========================================================================
# DPV 매핑 — PII Scanner entity_type → DPV 2.0 personal data category
# =========================================================================
# 형식: entity_type → (dpv_concept, 해설)
DPV_CATEGORY: Dict[str, Tuple[str, str]] = {
    "KR_RRN":            ("dpv-pd:NationalIdentificationNumber", "직접식별자: 한국 주민등록번호"),
    "KR_PASSPORT":       ("dpv-pd:PassportNumber",                "직접식별자: 한국 여권번호"),
    "KR_PHONE":          ("dpv-pd:TelephoneNumber",               "직접식별자: 한국 휴대폰"),
    "KR_BIZ_NO":         ("dpv-pd:Identifier",                    "법인 식별자 (사업자등록번호)"),
    "KR_ADDRESS":        ("dpv-pd:HomeAddress",                   "준식별자: 한국 주소"),
    "EMAIL_ADDRESS":     ("dpv-pd:EmailAddress",                  "직접식별자: 이메일"),
    "PHONE_NUMBER":      ("dpv-pd:TelephoneNumber",               "직접식별자: 일반 전화번호"),
    "CREDIT_CARD":       ("dpv-pd:CreditCardNumber",              "민감/금융: 신용카드"),
    "US_SSN":            ("dpv-pd:NationalIdentificationNumber",  "직접식별자: 미국 SSN"),
    "URL":               ("dpv-pd:URL",                           "준식별자(가능): URL"),
    "IP_ADDRESS":        ("dpv-pd:IPAddress",                     "준식별자/Tracking"),
    "IBAN_CODE":         ("dpv-pd:BankAccount",                   "민감/금융: IBAN"),
    "VIP_PERSON":        ("dpv-pd:Name",                           "직접식별자: 자연인 이름"),
    "INTERNAL_PROJECT":  ("dpv:NonPersonalData",                  "내부 코드명 (PII 아님)"),
    "AWS_ACCESS_KEY":    ("dpv:NonPersonalData",                  "비밀: 자격증명"),
    "GENERIC_API_KEY":   ("dpv:NonPersonalData",                  "비밀: 자격증명 후보"),
}


# =========================================================================
# 관할별 규제 매트릭스
# =========================================================================
# 각 관할에서 entity_type 을 어떻게 분류하는지(direct/quasi/sensitive/secret)
JURISDICTION: Dict[str, Dict] = {
    "KR": {
        "name": "대한민국",
        "law": "개인정보보호법 §2·§28-2~7 · 가명정보 처리 가이드라인 (PIPC)",
        "url": "https://www.pipc.go.kr/",
        "notes": (
            "직접식별자는 가명화 시 비가역적 변환 필요. 추가정보(매핑 키 등)는 "
            "별도 분리 보관. 준식별자 조합으로 재식별 가능성이 낮아야 함 "
            "(k-익명성·l-다양성 등 적정성 검토). 익명정보는 어떤 추가정보로도 "
            "복원 불가능해야 함 (§2 제1호의2)."
        ),
        "direct":   ["KR_RRN", "KR_PASSPORT", "EMAIL_ADDRESS", "PHONE_NUMBER", "KR_PHONE", "VIP_PERSON", "US_SSN"],
        "quasi":    ["KR_ADDRESS", "KR_BIZ_NO", "IP_ADDRESS", "URL"],
        "sensitive":["CREDIT_CARD", "IBAN_CODE"],
        "secret":   ["AWS_ACCESS_KEY", "GENERIC_API_KEY"],
    },
    "JP": {
        "name": "日本",
        "law": "個人情報保護法 (APPI) §2·§16-2·§35-2 · PPC『仮名加工情報・匿名加工情報の作成基準』",
        "url": "https://www.ppc.go.jp/",
        "notes": (
            "個人識別符号(マイナンバー·旅券番号·指紋データ 등)는 仮名加工 시 "
            "삭제 또는 復元できない方法で置き換え. 仮名加工情報는 추가정보 "
            "별도 관리 시 식별 가능. 匿名加工情報는 復元不可能 + 加工方法 정보 "
            "보존 필요."
        ),
        "direct":   ["KR_RRN", "KR_PASSPORT", "EMAIL_ADDRESS", "PHONE_NUMBER", "KR_PHONE", "VIP_PERSON", "US_SSN"],
        "quasi":    ["KR_ADDRESS", "IP_ADDRESS", "KR_BIZ_NO"],
        "sensitive":["CREDIT_CARD", "IBAN_CODE"],
        "secret":   ["AWS_ACCESS_KEY", "GENERIC_API_KEY"],
    },
    "US": {
        "name": "United States",
        "law": "HIPAA Safe Harbor (45 CFR §164.514(b)(2)) · CCPA/CPRA · NIST SP 800-188",
        "url": "https://www.hhs.gov/hipaa/",
        "notes": (
            "HIPAA Safe Harbor 18가지 식별자 모두 제거/일반화 — 이름·주소 "
            "(앞 3자리 ZIP 만 가능, 인구 ≥20,000), 모든 날짜(연도만), 전화·팩스·"
            "이메일·SSN·계정·인증서·차량·기기·URL·IP·생체정보·사진. CCPA "
            "deidentified data 는 'cannot reasonably identify' + 기술·계약 통제."
        ),
        "direct":   ["KR_RRN", "KR_PASSPORT", "EMAIL_ADDRESS", "PHONE_NUMBER", "KR_PHONE", "VIP_PERSON", "US_SSN", "URL", "IP_ADDRESS", "CREDIT_CARD", "IBAN_CODE"],
        "quasi":    ["KR_ADDRESS", "KR_BIZ_NO"],
        "sensitive":[],
        "secret":   ["AWS_ACCESS_KEY", "GENERIC_API_KEY"],
    },
    "EU": {
        "name": "European Union",
        "law": "GDPR Art. 4(5), Recital 26 · EDPB Guidelines 01/2025 on Pseudonymisation · WP29 Op. 05/2014",
        "url": "https://edpb.europa.eu/",
        "notes": (
            "Pseudonymisation = 추가정보를 별도로 보관하고 기술·조직적 조치로 "
            "재식별을 차단(Art 4(5)). Anonymisation = 어떤 합리적 수단으로도 "
            "재식별 불가능 (Recital 26). Special categories(Art 9: 건강·생체·"
            "민족 등) 은 추가 보호. Singling-out, linkability, inference 3개 "
            "리스크가 모두 제거되어야 익명."
        ),
        "direct":   ["KR_RRN", "KR_PASSPORT", "EMAIL_ADDRESS", "PHONE_NUMBER", "KR_PHONE", "VIP_PERSON", "US_SSN", "IP_ADDRESS"],
        "quasi":    ["KR_ADDRESS", "KR_BIZ_NO", "URL"],
        "sensitive":["CREDIT_CARD", "IBAN_CODE"],
        "secret":   ["AWS_ACCESS_KEY", "GENERIC_API_KEY"],
    },
}


# =========================================================================
# 권장 기법 (ISO/IEC 20889 분류 인용)
# =========================================================================
TECHNIQUE: Dict[str, Tuple[str, str, str]] = {
    # entity → (technique_id, ISO 20889 인용, DPV 표현)
    "KR_RRN":           ("tokenize_random",        "ISO 20889 §8.4 Tokenization (random) — 직접식별자, 매핑 키는 분리 보관",          "dpv:Pseudonymisation+dpv:Tokenisation"),
    "KR_PASSPORT":      ("tokenize_random",        "ISO 20889 §8.4 Tokenization",                                                      "dpv:Pseudonymisation+dpv:Tokenisation"),
    "KR_PHONE":         ("mask_partial",           "ISO 20889 §7.5 Masking — 앞 3 / 뒤 4 유지",                                         "dpv:DataMasking"),
    "PHONE_NUMBER":     ("mask_partial",           "ISO 20889 §7.5 Masking",                                                            "dpv:DataMasking"),
    "EMAIL_ADDRESS":    ("hash_local_keep_domain", "ISO 20889 §8.4 Cryptographic — local 부분 HMAC-BLAKE2b, 도메인 유지",               "dpv:Pseudonymisation+dpv:Encryption"),
    "KR_ADDRESS":       ("generalize_to_city",     "ISO 20889 §7.2 Generalization — 시·도 단위까지 일반화 (HIPAA SH §164.514(b)(2)(i)(B) 와 정합)", "dpv:Generalisation"),
    "CREDIT_CARD":      ("mask_pan",               "PCI-DSS Req 3.4 — 앞 6 / 뒤 4 유지, 중간 마스킹",                                   "dpv:DataMasking"),
    "US_SSN":           ("tokenize_random",        "직접식별자 → 비가역 토큰",                                                          "dpv:Pseudonymisation+dpv:Tokenisation"),
    "IBAN_CODE":        ("mask_partial",           "ISO 20889 §7.5 Masking — 국가코드+체크디지트 유지, 계좌부 중간 마스킹",            "dpv:DataMasking"),
    "VIP_PERSON":       ("pseudonym_consistent",   "ISO 20889 §8.4 Pseudonymisation — 동일인 일관 매핑(HMAC)",                          "dpv:Pseudonymisation"),
    "AWS_ACCESS_KEY":   ("suppress",               "비밀 자격증명 — 즉시 회전(rotate) + 완전 제거",                                     "dpv:Erasure"),
    "GENERIC_API_KEY":  ("suppress",               "비밀 후보 — 보수적 완전 제거",                                                       "dpv:Erasure"),
    "INTERNAL_PROJECT": ("tokenize_random",        "내부 코드명 — 외부 노출 시 무작위 토큰",                                             "dpv:Pseudonymisation"),
    "KR_BIZ_NO":        ("mask_partial",           "법인 ID — 부분 마스킹 (전체 비식별 시에는 토큰화)",                                  "dpv:DataMasking"),
    "URL":              ("generalize_url",         "ISO 20889 §7.2 — 호스트만 유지, 경로/쿼리 제거",                                    "dpv:Generalisation"),
    "IP_ADDRESS":       ("ip_truncate",            "ISO 20889 §7.2 — IPv4 마지막 옥텟 절단 (/24)",                                      "dpv:Generalisation"),
}


# =========================================================================
# 데이터 클래스
# =========================================================================
@dataclass
class EntityRecord:
    index: int
    entity_type: str
    original: str
    start: int
    end: int
    score: float
    dpv_concept: str
    dpv_note: str
    technique: str
    technique_note: str
    technique_dpv: str
    transformed: str
    classifications: Dict[str, str]   # {jurisdiction: 'direct'|'quasi'|'sensitive'|'secret'|'unmapped'}


@dataclass
class ComplianceVerdict:
    jurisdiction: str
    name: str
    law: str
    url: str
    notes: str
    treatment_level: str          # 'pseudonymization' | 'anonymization'
    counts: Dict[str, int]        # direct/quasi/sensitive/secret
    untreated: List[str]
    verdict: str                  # 'compliant' | 'partial' | 'insufficient'
    rationale: str
    requirements_met: List[str]
    requirements_pending: List[str]


# =========================================================================
# 변환기 (ISO 20889 기법별)
# =========================================================================
class Pseudonymizer:
    """변환 기법 모음. salt 와 매핑 테이블은 인스턴스 내에 보관 — 실 운영 시
    이 매핑이 'additional information' (GDPR Art 4(5)) 에 해당하므로 별도 KMS·HSM
    보관 권장. PoC 에서는 메모리 내."""

    def __init__(self, salt: Optional[bytes] = None, anonymize: bool = False):
        self.salt = salt or secrets.token_bytes(16)
        self.anonymize = anonymize  # True 면 일관성 매핑도 끔
        self.consistent: Dict[Tuple[str, str], str] = {}
        self._counter: Dict[str, int] = {}

    def transform(self, entity_type: str, value: str) -> Tuple[str, str, str, str]:
        """반환: (변환문, technique_id, ISO 20889 노트, DPV 표현)"""
        tech_id, note, dpv = TECHNIQUE.get(
            entity_type,
            ("suppress", "기본 정책 — 미지정 엔티티는 보수적으로 제거", "dpv:Erasure"),
        )
        method = getattr(self, f"_{tech_id}", self._suppress)
        return method(entity_type, value), tech_id, note, dpv

    # ---- 기법 구현 ----
    def _suppress(self, et, v):
        return "[REDACTED]"

    def _tokenize_random(self, et, v):
        if not self.anonymize:
            key = (et, v)
            if key in self.consistent:
                return self.consistent[key]
        n = self._counter.get(et, 0) + 1
        self._counter[et] = n
        token = f"<{et}_{n:04d}>"
        if not self.anonymize:
            self.consistent[(et, v)] = token
        return token

    def _pseudonym_consistent(self, et, v):
        if self.anonymize:
            # 익명화: 동일성도 보존하지 않음 → 매번 임의 값
            return f"<PERSON_{secrets.token_hex(3).upper()}>"
        key = (et, v)
        if key in self.consistent:
            return self.consistent[key]
        h = hmac.new(self.salt, v.encode("utf-8"), hashlib.blake2b).hexdigest()[:8]
        token = f"<PERSON_{h.upper()}>"
        self.consistent[key] = token
        return token

    def _mask_partial(self, et, v):
        digit_pos = [i for i, c in enumerate(v) if c.isdigit()]
        if len(digit_pos) < 7:
            return self._suppress(et, v)
        keep_front, keep_back = 3, 4
        masked = set(digit_pos[keep_front : len(digit_pos) - keep_back])
        return "".join("*" if i in masked else c for i, c in enumerate(v))

    def _mask_pan(self, et, v):
        digit_pos = [i for i, c in enumerate(v) if c.isdigit()]
        if len(digit_pos) < 13:
            return self._suppress(et, v)
        masked = set(digit_pos[6 : len(digit_pos) - 4])
        return "".join("*" if i in masked else c for i, c in enumerate(v))

    def _hash_local_keep_domain(self, et, v):
        if "@" not in v:
            return self._suppress(et, v)
        local, domain = v.split("@", 1)
        h = hmac.new(self.salt, local.encode("utf-8"), hashlib.blake2b).hexdigest()[:8]
        return f"user-{h}@{domain}"

    _KR_PROVINCES = (
        "서울", "부산", "대구", "인천", "광주", "대전", "울산", "세종",
        "경기", "강원", "충북", "충남", "전북", "전남", "경북", "경남", "제주",
    )

    def _generalize_to_city(self, et, v):
        for p in self._KR_PROVINCES:
            if v.startswith(p):
                return f"{p} (이하 일반화)"
        return self._suppress(et, v)

    def _ip_truncate(self, et, v):
        m = re.match(r"(\d+)\.(\d+)\.(\d+)\.\d+", v)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.0/24"
        return self._suppress(et, v)

    def _generalize_url(self, et, v):
        m = re.match(r"(https?://[^/]+)", v, flags=re.IGNORECASE)
        if m:
            return f"{m.group(1)}/[…]"
        return v


# =========================================================================
# 분류 / 평가 함수
# =========================================================================
def classify_entity(entity_type: str, jurisdictions: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for j in jurisdictions:
        rules = JURISDICTION.get(j)
        if not rules:
            out[j] = "unmapped"
            continue
        if entity_type in rules.get("direct", []):
            out[j] = "direct"
        elif entity_type in rules.get("quasi", []):
            out[j] = "quasi"
        elif entity_type in rules.get("sensitive", []):
            out[j] = "sensitive"
        elif entity_type in rules.get("secret", []):
            out[j] = "secret"
        else:
            out[j] = "unmapped"
    return out


def _requirements_per_jurisdiction(j: str, level: str) -> List[str]:
    """관할/처리수준별 핵심 요구사항 체크리스트."""
    common = [
        "직접식별자 모두 변환/제거",
        "민감정보(금융·건강 등) 마스킹/제거",
        "비밀 자격증명 완전 제거",
    ]
    by_level = {
        "pseudonymization": [
            "추가정보(매핑·키) 별도 분리 보관",
            "재식별 시도 방지 기술·조직적 조치",
        ],
        "anonymization": [
            "추가정보를 포함한 어떤 합리적 수단으로도 재식별 불가",
            "준식별자 조합 재식별 위험 검증 (k-익명성 등)",
            "결과의 분포·일반화 수준 통계적 검증",
        ],
    }
    j_specific = {
        "KR": ["가명정보 적정성 검토(가명정보 처리 가이드라인)"] if level == "pseudonymization"
              else ["적정성 평가 + 추가정보 폐기"],
        "JP": ["仮名加工情報の安全管理措置 (APPI §35-2)"] if level == "pseudonymization"
              else ["匿名加工情報の作成方法等の公表 (APPI §43)"],
        "US": ["HIPAA Safe Harbor 18 식별자 항목 모두 처리",
               "Expert Determination 트랙 시 통계 전문가 검증"],
        "EU": ["EDPB 01/2025 — singling-out / linkability / inference 3개 위험 평가",
               "Art 32 적절한 보안조치"],
    }
    return common + by_level[level] + j_specific.get(j, [])


def evaluate_compliance(
    entities: List[EntityRecord],
    jurisdictions: List[str],
    treatment_level: str,
) -> List[ComplianceVerdict]:
    out: List[ComplianceVerdict] = []
    for j in jurisdictions:
        rules = JURISDICTION.get(j)
        if not rules:
            continue

        counts = {"direct": 0, "quasi": 0, "sensitive": 0, "secret": 0, "unmapped": 0}
        untreated: List[str] = []
        for e in entities:
            cls = e.classifications.get(j, "unmapped")
            counts[cls] = counts.get(cls, 0) + 1
            if cls in ("direct", "secret", "sensitive") and e.transformed == e.original:
                untreated.append(e.entity_type)

        reqs = _requirements_per_jurisdiction(j, treatment_level)

        # 단순 휴리스틱 판정 (PoC)
        if untreated:
            verdict = "insufficient"
            rationale = (
                f"미처리 직접/민감/비밀 항목 존재: {', '.join(sorted(set(untreated)))} — "
                f"{rules['name']} 기준 {treatment_level} 미충족."
            )
            met = ["검출/분류 완료"]
            pending = ["미처리 항목 변환"] + reqs
        elif treatment_level == "anonymization":
            # 익명: 준식별자 다수 잔존 시 부분 (수동 검증 필요)
            quasi_n = counts.get("quasi", 0)
            if quasi_n >= 2:
                verdict = "partial"
                rationale = (
                    f"준식별자 {quasi_n}개 — 조합 재식별 위험. "
                    "k-익명성·l-다양성·t-근접성 등 정량 검증 필요."
                )
                met = [
                    "직접·민감·비밀 모두 변환",
                    "PII 검출·분류·DPV 매핑 완료",
                ]
                pending = [
                    "준식별자 조합에 대한 재식별 위험 정량 평가",
                    "추가정보(매핑) 폐기 절차",
                ]
            else:
                verdict = "compliant"
                rationale = (
                    "직접·민감·비밀 모두 변환되었고 준식별자 일반화 적용. "
                    "단 PoC 휴리스틱 — 실 운영 시 통계적 적정성 검토 필수."
                )
                met = [
                    "직접·민감·비밀 모두 변환",
                    "준식별자 일반화/제거",
                    "DPV 매핑 + 관할 분류 명세화",
                ]
                pending = [
                    "추가정보(매핑) 폐기 또는 분리 폐기 증빙",
                    "통계적 재식별 위험 평가 보고서",
                ]
        else:
            # 가명화 — 추가정보 분리 보관 전제로 일단 compliant
            verdict = "compliant"
            n_treated = counts["direct"] + counts["sensitive"] + counts["secret"]
            rationale = (
                f"직접·민감·비밀 {n_treated}건 모두 변환 완료. 매핑 테이블은 "
                "본 PoC 가 메모리에 보관 — 실 운영 시 KMS/HSM 분리 보관 필요."
            )
            met = [
                "직접식별자 모두 변환/제거",
                "민감정보 마스킹/제거",
                "비밀 자격증명 완전 제거",
                "DPV 매핑 + 처리 흐름 문서화",
            ]
            pending = [
                "매핑 테이블의 별도 보관 (KMS·HSM)",
                "재식별 시도 방지 기술·조직적 조치 (Art 32 / APPI 安全管理)",
                "(KR) 가명정보 적정성 검토",
            ]
            # KR 만의 가이드라인 적정성 검토 강조
            if j == "KR":
                pending.append("가명정보 처리 가이드라인 §III-3 적정성 검토위원회 의사록")

        out.append(ComplianceVerdict(
            jurisdiction=j,
            name=rules["name"],
            law=rules["law"],
            url=rules["url"],
            notes=rules["notes"],
            treatment_level=treatment_level,
            counts={k: v for k, v in counts.items() if k != "unmapped"},
            untreated=sorted(set(untreated)),
            verdict=verdict,
            rationale=rationale,
            requirements_met=met,
            requirements_pending=pending,
        ))
    return out


# =========================================================================
# 메인 진입점 — 텍스트 + findings → 변환 텍스트 + 평가
# =========================================================================
def run(
    text: str,
    findings: List[Dict],
    jurisdictions: List[str],
    treatment_level: str,
    salt: Optional[bytes] = None,
) -> Dict:
    """text 와 PII Scanner findings 를 받아 변환 + 평가 결과를 반환."""
    if treatment_level not in ("pseudonymization", "anonymization"):
        treatment_level = "pseudonymization"
    valid = [j for j in jurisdictions if j in JURISDICTION]
    if not valid:
        valid = list(JURISDICTION.keys())

    pz = Pseudonymizer(salt=salt, anonymize=(treatment_level == "anonymization"))

    # 위치 오름차순 정렬 후 비겹침 선택
    sorted_findings = sorted(findings, key=lambda f: (f["start"], -f.get("score", 0)))
    chosen = []
    last_end = -1
    for f in sorted_findings:
        if f["start"] >= last_end:
            chosen.append(f)
            last_end = f["end"]

    records: List[EntityRecord] = []
    for i, f in enumerate(chosen):
        et = f["entity_type"]
        original = f["text"]
        dpv_concept, dpv_note = DPV_CATEGORY.get(et, ("dpv:NonPersonalData", "DPV 매핑 없음"))
        transformed, tech_id, tech_note, tech_dpv = pz.transform(et, original)
        classifications = classify_entity(et, valid)
        records.append(EntityRecord(
            index=i + 1,
            entity_type=et,
            original=original,
            start=f["start"],
            end=f["end"],
            score=float(f.get("score", 0)),
            dpv_concept=dpv_concept,
            dpv_note=dpv_note,
            technique=tech_id,
            technique_note=tech_note,
            technique_dpv=tech_dpv,
            transformed=transformed,
            classifications=classifications,
        ))

    # 끝→앞 으로 치환 (인덱스 유지)
    out_text = text
    for r in sorted(records, key=lambda r: r.start, reverse=True):
        out_text = out_text[: r.start] + r.transformed + out_text[r.end :]

    verdicts = evaluate_compliance(records, valid, treatment_level)

    return {
        "treatment_level": treatment_level,
        "jurisdictions": valid,
        "original_text": text,
        "transformed_text": out_text,
        "entities": [asdict(r) for r in records],
        "verdicts": [asdict(v) for v in verdicts],
        # 매핑 테이블 (PoC 시연용 — 실 운영 시 절대 응답에 포함 금지)
        "mapping_demo": [
            {"entity_type": k[0], "original": k[1], "token": v}
            for k, v in pz.consistent.items()
        ],
    }
