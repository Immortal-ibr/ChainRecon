from __future__ import annotations

from pathlib import Path


class ExampleStringAnalyzer:
    def analyze(self, input_path: str, **_kwargs):
        path = Path(input_path)
        text_suffixes = {".txt", ".json", ".xml", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".log", ".properties"}
        files = []
        if path.is_dir():
            for item in path.rglob("*"):
                if len(files) >= 1000:
                    break
                if not item.is_file() or item.suffix.lower() not in text_suffixes:
                    continue
                try:
                    if item.stat().st_size <= 2_000_000:
                        files.append(item)
                except OSError:
                    continue
        elif path.exists():
            files = [path]
        hits = []
        for file_path in files:
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            for keyword in ("password", "token", "secret"):
                if keyword in text:
                    hits.append({"keyword": keyword, "path": str(file_path)})
        return {
            "metadata": {"section": "example_strings", "analyzer": self.__class__.__name__, "source": str(path)},
            "findings": {"hits": hits},
            "summary": {"hit_count": len(hits)},
            "risk_indicators": [
                {"severity": "medium", "title": "Credential-like keyword found", "details": f"Detected '{hit['keyword']}' in {Path(hit['path']).name}."}
                for hit in hits
            ],
        }
