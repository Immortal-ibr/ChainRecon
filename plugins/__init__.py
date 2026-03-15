"""Plugin exports and registry helpers for ChainRecon."""

from plugins.csv_export import CsvExportPlugin
from plugins.html_report import HtmlReportPlugin
from plugins.json_report import JsonReportPlugin

PLUGIN_REGISTRY = {
    JsonReportPlugin.name: JsonReportPlugin,
    HtmlReportPlugin.name: HtmlReportPlugin,
    CsvExportPlugin.name: CsvExportPlugin,
}


def get_plugin(name: str):
    try:
        return PLUGIN_REGISTRY[name.lower()]()
    except KeyError as exc:
        raise ValueError(f"Unsupported report plugin: {name}") from exc


__all__ = ["JsonReportPlugin", "HtmlReportPlugin", "CsvExportPlugin", "get_plugin"]
