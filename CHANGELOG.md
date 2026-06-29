# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-30

### Added
- Initial public release
- 473 tools across 46 AlertLogic API modules
- Full IRIS v3 incident response workflow (list, get, elaborate, note, complete, reopen)
- SQL-based log search via AlertLogic Search v2
- SOAR playbook management (33 tools)
- Asset management and topology (cloud + Azure)
- Vulnerability and remediation management
- User and role management
- AIMS Bearer token authentication with auto-refresh
- Streamable HTTP, SSE, and stdio MCP transport support
- Built-in SOC playbooks: IR start guide, threat hunt, MITRE ATT&CK guide
- Multi-account MSSP support via incidents_list_partner and per-tool account_id
- Ticket management (create/update/comment/close)
- IOC watchlist management
- Scan scheduling and result retrieval
