# ChainRecon Directory Structure

- scripts/: Bash scripts for setup, network configuration, and data collection
- analysis/: Python modules for traffic, SSL/TLS, and vulnerability analysis
- analysis/traffic.py: Packet capture parser for DNS, HTTP, TLS SNI, protocol, IP, and conversation analysis
- analysis/ssl_analyzer.py: SSL/TLS certificate, cipher, and JA3-style analysis helpers
- analysis/scanner.py: Nmap parsing plus optional Shodan enrichment and IoT service correlation
- analysis/report_generator.py: Aggregates analyzer outputs and delegates rendering to plugins
- reports/: Output and generated reports (CSV, TXT, etc.)
- plugins/: User-customizable Python plugins for report generation and data translation
- plugins/base.py: Abstract plugin contract for report outputs
- plugins/json_report.py: JSON report renderer
- plugins/html_report.py: HTML report renderer
- plugins/csv_export.py: CSV export renderer
- tests/: Unit and integration tests for Python analysis modules and plugins
- tests/test_analysis.py: Analyzer unit tests with mocked packet, SSL, and Nmap data
- tests/test_plugins.py: Plugin output tests
- tests/test_report.py: Report generator tests
- tests/test_cli.py: CLI dispatch and aggregation tests

Other files:
- README.md: Project overview and usage
- requirements.txt: Python dependencies for analysis modules
- chainrecon.py: Python CLI entry point for analysis and reporting
- Recon script.sh: Main Bash entry point for setup and data collection
