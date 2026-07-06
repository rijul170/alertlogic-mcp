# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-06

### Added
- Safety gating: `ALERTLOGIC_MCP_READONLY` registers only read tools; destructive
  tools (deletes, SOAR playbook execution, scan launches, ...) are now suppressed
  by default and require explicit opt-in via `ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE`
- MCP `readOnlyHint`/`destructiveHint` annotations on every tool
- Unit test suite (`tests/`) and GitHub Actions CI

### Fixed
- README installation instructions pointed at a placeholder repository URL

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
