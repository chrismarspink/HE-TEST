"""
Microsoft Presidio 기반 PII / 민감정보 감지 로컬 웹 서버.

실행:
    python app.py
브라우저에서 http://127.0.0.1:5000 접속 후 파일을 드래그-앤-드롭하면
감지된 엔티티 목록과 위치, 신뢰도, 매치 텍스트를 확인할 수 있습니다.

custom_patterns.yaml 을 수정하여 사용자 정의 패턴/룰을 자유롭게 추가할 수 있습니다.
"""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path
from typing import List

import yaml
from flask import Flask, jsonify, render_template, request
from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("presidio-app")

BASE_DIR = Path(__file__).resolve().parent
PATTERN_FILE = BASE_DIR / "custom_patterns.yaml"

# ---------------------------------------------------------------------------
# Presidio Analyzer 초기화
# ---------------------------------------------------------------------------

# spaCy 모델은 가벼운 en_core_web_sm 을 기본으로 사용한다.
# 더 정확한 NER 이 필요하면 en_core_web_lg 로 변경하세요.
NLP_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}


def load_custom_recognizers(path: Path) -> List[PatternRecognizer]:
    """custom_patterns.yaml 을 읽어 PatternRecognizer 목록을 만든다."""
    if not path.exists():
        log.warning("custom_patterns.yaml not found: %s", path)
        return []

    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    recognizers: List[PatternRecognizer] = []

    for item in cfg.get("pattern_recognizers", []) or []:
        patterns = [
            Pattern(name=p["name"], regex=p["regex"], score=float(p["score"]))
            for p in item.get("patterns", [])
        ]
        rec = PatternRecognizer(
            supported_entity=item["supported_entity"],
            name=item["name"],
            supported_language=item.get("supported_language", "en"),
            patterns=patterns,
            context=item.get("context"),
        )
        recognizers.append(rec)
        log.info("Loaded pattern recognizer: %s (%d patterns)", rec.name, len(patterns))

    for item in cfg.get("deny_list_recognizers", []) or []:
        rec = PatternRecognizer(
            supported_entity=item["supported_entity"],
            name=item["name"],
            supported_language=item.get("supported_language", "en"),
            deny_list=item.get("deny_list", []),
            deny_list_score=float(item.get("score", 1.0)),
        )
        recognizers.append(rec)
        log.info(
            "Loaded deny-list recognizer: %s (%d terms)",
            rec.name,
            len(item.get("deny_list", [])),
        )

    return recognizers


def build_analyzer() -> AnalyzerEngine:
    """기본 Presidio 인식기 + custom_patterns.yaml 의 사용자 정의 인식기를 합쳐 엔진 생성."""
    provider = NlpEngineProvider(nlp_configuration=NLP_CONFIG)
    nlp_engine = provider.create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=["en"])

    for rec in load_custom_recognizers(PATTERN_FILE):
        registry.add_recognizer(rec)

    return AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["en"],
    )


analyzer: AnalyzerEngine = build_analyzer()

# ---------------------------------------------------------------------------
# 파일 → 텍스트 추출
# ---------------------------------------------------------------------------

def extract_text(filename: str, raw: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext in {".txt", ".log", ".csv", ".json", ".md", ".yaml", ".yml", ".xml", ".html"}:
        for enc in ("utf-8", "cp949", "euc-kr", "latin-1"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")

    if ext == ".pdf":
        from pypdf import PdfReader  # lazy import
        reader = PdfReader(io.BytesIO(raw))
        return "\n".join((p.extract_text() or "") for p in reader.pages)

    if ext == ".docx":
        from docx import Document  # lazy import
        doc = Document(io.BytesIO(raw))
        parts = [p.text for p in doc.paragraphs]
        for tbl in doc.tables:
            for row in tbl.rows:
                for cell in row.cells:
                    parts.append(cell.text)
        return "\n".join(parts)

    # fallback: 텍스트로 시도
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/docs")
def docs():
    return render_template("docs.html")


@app.route("/api/recognizers", methods=["GET"])
def list_recognizers():
    """현재 활성화된 인식기 목록과 지원 엔티티를 반환."""
    recs = analyzer.registry.recognizers
    out = []
    for r in recs:
        out.append(
            {
                "name": r.name,
                "supported_entities": list(r.supported_entities),
                "supported_language": r.supported_language,
            }
        )
    return jsonify(
        {
            "recognizer_count": len(out),
            "supported_entities": sorted(
                {e for r in recs for e in r.supported_entities}
            ),
            "recognizers": out,
        }
    )


@app.route("/api/reload", methods=["POST"])
def reload_patterns():
    """custom_patterns.yaml 을 다시 읽어 분석기를 재구성한다."""
    global analyzer
    try:
        analyzer = build_analyzer()
        return jsonify({"ok": True, "message": "Patterns reloaded."})
    except Exception as e:  # noqa: BLE001
        log.exception("reload failed")
        return jsonify({"ok": False, "message": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"ok": False, "message": "file field is required"}), 400

    f = request.files["file"]
    raw = f.read()
    score_threshold = float(request.form.get("score_threshold", 0.3))

    try:
        text = extract_text(f.filename or "uploaded", raw)
    except Exception as e:  # noqa: BLE001
        log.exception("extract_text failed")
        return jsonify({"ok": False, "message": f"failed to read file: {e}"}), 400

    results = analyzer.analyze(
        text=text,
        language="en",
        score_threshold=score_threshold,
    )

    findings = []
    for r in results:
        snippet = text[r.start : r.end]
        findings.append(
            {
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(float(r.score), 3),
                "text": snippet,
                "recognizer": (
                    r.recognition_metadata.get("recognizer_name")
                    if r.recognition_metadata
                    else None
                ),
            }
        )

    findings.sort(key=lambda x: (x["start"], -x["score"]))

    summary: dict[str, int] = {}
    for f_ in findings:
        summary[f_["entity_type"]] = summary.get(f_["entity_type"], 0) + 1

    return jsonify(
        {
            "ok": True,
            "filename": f.filename,
            "char_count": len(text),
            "score_threshold": score_threshold,
            "summary": summary,
            "findings": findings,
            "text": text,
        }
    )


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    log.info("Starting server on http://%s:%s", host, port)
    app.run(host=host, port=port, debug=False)
