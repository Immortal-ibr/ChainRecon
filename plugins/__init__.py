"""Plugin exports and registry helpers for ChainRecon."""

from plugins.csv_export import CsvExportPlugin
from plugins.html_report import HtmlReportPlugin
from plugins.json_report import JsonReportPlugin
from plugins.xlsx_report import XlsxReportPlugin

PLUGIN_REGISTRY = {
    JsonReportPlugin.name: JsonReportPlugin,
    HtmlReportPlugin.name: HtmlReportPlugin,
    CsvExportPlugin.name: CsvExportPlugin,
    XlsxReportPlugin.name: XlsxReportPlugin,
}


def get_plugin(name: str):
    try:
        return PLUGIN_REGISTRY[name.lower()]()
    except KeyError as exc:
        raise ValueError(f"Unsupported report plugin: {name}") from exc


__all__ = ["JsonReportPlugin", "HtmlReportPlugin", "CsvExportPlugin", "XlsxReportPlugin", "get_plugin"]
