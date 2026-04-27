from __future__ import annotations

from pathlib import Path


class ExampleStringAnalyzer:
    def analyze(self, input_path: str, **_kwargs):
        path = Path(input_path)
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        hits = [keyword for keyword in ("password", "token", "secret") if keyword in text.lower()]
        return {
            "metadata": {"section": "example_strings", "analyzer": self.__class__.__name__, "source": str(path)},
            "findings": {"hits": hits},
            "summary": {"hit_count": len(hits)},
            "risk_indicators": [
                {"severity": "medium", "title": "Credential-like keyword found", "details": f"Detected '{keyword}' in {path.name}."}
                for keyword in hits
            ],
        }