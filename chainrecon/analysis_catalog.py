"""Evidence types and the offline analyzers that accept them."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceType:
    kind: str
    label: str
    analyzer: str | None
    description: str


EVIDENCE_TYPES = (
    EvidenceType("apk", "Android APK", "apk", "Inspect package metadata and app artifacts."),
    EvidenceType("firmware", "Firmware image", "firmware", "Identify, extract, and inventory an image."),
    EvidenceType("flash_dump", "Flash dump", "firmware", "Identify and inspect a raw flash image."),
    EvidenceType("frida_log", "Frida log", "frida_log", "Parse recorded instrumentation events."),
    EvidenceType("frida_summary", "Frida summary", None, "Keep a prior session summary as evidence."),
    EvidenceType("scan_xml", "Nmap XML scan", "scan", "Parse hosts and services from Nmap XML."),
    EvidenceType("pcap", "Packet capture (PCAP/PCAPNG)", "traffic", "Inspect captured network traffic."),
    EvidenceType("uart_log", "UART log", None, "Keep serial output as evidence for manual review."),
    EvidenceType("other", "Other file", None, "Keep an additional source file as evidence."),
    EvidenceType("legacy_result", "Imported legacy result", None, "A version 1 result imported with its original findings."),
)

BY_KIND = {item.kind: item for item in EVIDENCE_TYPES}
ANALYZER_KINDS = {
    analyzer: frozenset(item.kind for item in EVIDENCE_TYPES if item.analyzer == analyzer)
    for analyzer in {item.analyzer for item in EVIDENCE_TYPES if item.analyzer is not None}
}
IMPORT_OPTIONS = [(item.label, item.kind) for item in EVIDENCE_TYPES if item.kind != "legacy_result"]


def analyzer_for_kind(kind: str) -> str | None:
    """Return the built-in analyzer for this evidence classification, if any."""
    evidence_type = BY_KIND.get(kind)
    return evidence_type.analyzer if evidence_type else None
