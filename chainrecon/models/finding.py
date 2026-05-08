"""Standardised finding / vulnerability dataclass used across all analyzers."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """CVSS-inspired severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) < order.index(other)


class Category(Enum):
    """Broad finding categories for grouping and filtering."""

    CRYPTO = "crypto"
    NETWORK = "network"
    AUTH = "authentication"
    STORAGE = "storage"
    PERMISSIONS = "permissions"
    CONFIG = "configuration"
    TLS = "tls"
    PRIVACY = "privacy"
    IOT = "iot"
    OTHER = "other"


@dataclass
class Finding:
    """A single security finding produced by any ChainRecon analyzer."""

    title: str
    description: str
    severity: Severity
    category: Category
    source: str  # e.g. "apk_analyzer", "traffic_analyzer", "ssl_analyzer"

    # Optional enrichment
    recommendation: str = ""
    evidence: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Auto-populated
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Reconstruct a Finding from a dict (e.g. loaded from JSON)."""
        data = dict(data)  # shallow copy
        data["severity"] = Severity(data["severity"])
        data["category"] = Category(data["category"])
        return cls(**data)


@dataclass
class FindingCollection:
    """Ordered collection of findings with convenience helpers."""

    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: Category) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def by_source(self, source: str) -> List[Finding]:
        return [f for f in self.findings if f.source == source]

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for sev in Severity:
            c = len(self.by_severity(sev))
            if c:
                counts[sev.value] = c
        return counts

    def sorted_by_severity(self) -> List[Finding]:
        """Return findings ordered from critical -> info."""
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def to_list(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self.findings]

    @classmethod
    def from_list(cls, items: List[Dict[str, Any]]) -> "FindingCollection":
        return cls(findings=[Finding.from_dict(d) for d in items])

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)
