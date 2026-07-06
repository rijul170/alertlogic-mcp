<div align="center">

# AlertLogic MCP Server

**Bring the full AlertLogic MDR platform into your AI assistant.**

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the complete AlertLogic API surface as structured tools any MCP-compatible client (Claude Desktop, Claude Code, Cursor, …) can call directly — enabling AI-powered security operations, incident response, and threat hunting at MSSP scale.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP%20Protocol-2024--11--05-1f6feb)](https://modelcontextprotocol.io)
[![Tools](https://img.shields.io/badge/tools-473%2B-FF6B00)](#module-overview)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![GitHub Stars](https://img.shields.io/github/stars/rijul170/alertlogic-mcp?style=social)](https://github.com/rijul170/alertlogic-mcp)

</div>

> **For incident responders:** Query Alert Logic MDR incidents, elaborate raw log evidence, kick off SOAR playbooks, and search logs with SQL — all through Claude. Designed for MSSP-scale multi-account operations.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Claude Code Integration](#claude-code-integration-http-mode)
- [Claude Desktop Integration](#claude-desktop-integration-stdio-mode)
- [Module Overview](#module-overview)
- [SOC Quick Start](#soc-quick-start)
- [Built-in SOC Playbooks](#built-in-soc-playbooks)
- [Multi-Account MSSP Usage](#multi-account-mssp-usage)
- [Security Notes](#security-notes)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This MCP server wraps the AlertLogic MDR platform API and exposes it as 473+ structured tools that any MCP-compatible AI client can call directly. It covers the full AlertLogic API surface — incident response, SQL-based log search, SOAR playbook automation, asset management, vulnerability analysis, user and credential management, billing, and more — organized into 46 domain modules. Auth, retries, pagination, token management, and JSON shaping are handled server-side; your AI client simply calls the tool by name.

---

## Features

- **Incident Response** — List, get, elaborate (raw log evidence), complete, reopen, add notes, and add feedback to incidents. Friendly-ID lookup included.
- **SQL Log Search** — Submit AlertLogic log search queries in SQL, poll status, retrieve results, and release sessions.
- **SOAR Playbook Automation** — List, get, execute, and monitor SOAR playbooks; manage inquiries, triggers, and execution state.
- **Asset Topology** — Query the full asset inventory, declare and remove assets, set properties, and retrieve topology graphs for any deployment.
- **Vulnerability Management** — List exposures by severity, retrieve per-asset vulnerabilities, search the vulnerability knowledge base, and manage remediation items.
- **User & Access Key Management** — Full CRUD on users, roles, access keys, MFA settings, and password resets across accounts.
- **Multi-Account MSSP Support** — Per-tool `account_id` override and bulk cross-account operations (bulk deployments, bulk health checks, partner incidents).
- **Built-in SOC Playbooks** — Six tools that surface pre-written IR guides, threat-hunt workflows, MITRE ATT&CK mappings, and tool reference guides directly in-context.
- **Tickets & Watchlist** — Create, update, and close tickets; manage the alerting watchlist.
- **Cloud & Azure Explorer** — Browse cloud resource topology across AWS and Azure environments.
- **Analytics Engine** — Access AE content, rules, analytics, tags, tuning, and publication across multiple AE subsystems.
- **Infrastructure Operations** — Manage environments, scan schedules, scan results, network controls, ingest sources, and log integrations.

---

## Architecture

```
+--------------------+      stdio / streamable-HTTP (MCP)     +--------------------------------+
|   MCP Client       | <-------------------------------------> |   AlertLogic MCP Server        |
| (Claude Desktop,   |                                        |   (this repo, main.py)         |
|  Claude Code, …)   |                                        |                                |
+--------------------+                                        |  46 modules (~473 tools):      |
                                                              |  incidents, soc, soar,         |
                                                              |  assets, vuln, users, …        |
                                                              |         |                      |
                                                              |   base.py (HTTP, AIMS auth,    |
                                                              |   token cache, retries)        |
                                                              +----------+---------------------+
                                                                         |
                                                                         v  HTTPS + AIMS Bearer token
                                                              +-----------------------------+
                                                              |   AlertLogic MDR Platform   |
                                                              |   api.cloudinsight....com   |
                                                              +-----------------------------+
```

**Transport**: The server supports three MCP transports selectable via `MCP_TRANSPORT`:
- `stdio` (default) — launched on demand by your MCP client; no network port opened.
- `streamable-http` — persistent HTTP server; suitable for Claude Code and remote clients.
- `sse` — Server-Sent Events transport for SSE-capable clients.

**Authentication**: AlertLogic uses AIMS Bearer token auth. The server exchanges your `access_key_id:secret_key` API key for a short-lived Bearer token on first use, caches it, and re-authenticates automatically when the token expires — no manual token rotation required.

**`base.py`** centralizes HTTP method helpers (`_get`, `_post`, `_put`, `_delete`), per-service URL routing (Account-Topology service, global service, `_at`-prefixed routes), error translation, and the AIMS token cache.

---

## Prerequisites

- Python 3.10 or newer
- `uv` (recommended) or `pip`
- An AlertLogic account with API access enabled
- An AlertLogic API key (access key ID + secret key; see [Configuration](#configuration))

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/rijul170/alertlogic-mcp.git
cd alertlogic-mcp

# 2. Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Or with uv (faster):
uv venv
uv pip install -r requirements.txt

# 3. Configure credentials
cp .env.example .env
$EDITOR .env                        # fill in the required variables (see below)
```

---

## Configuration

All configuration is via environment variables, loaded from `.env` at startup.

### Required variables

| Variable                  | Description                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------------- |
| `ALERTLOGIC_API_KEY`      | API key in `access_key_id:secret_key` format (see below for how to create one)                 |
| `ALERTLOGIC_BASE_URL`     | API base URL — `https://api.cloudinsight.alertlogic.com` (US) or `https://api.cloudinsight.alertlogic.co.uk` (UK) |
| `ALERTLOGIC_ACCOUNT_ID`   | Your AlertLogic account ID (visible in the console URL and account settings)                    |

### Optional variables

| Variable                  | Default        | Description                                              |
| ------------------------- | -------------- | -------------------------------------------------------- |
| `MCP_TRANSPORT`           | `stdio`        | Transport: `stdio`, `sse`, or `streamable-http`          |
| `MCP_HOST`                | `127.0.0.1`    | Bind host (HTTP transports only)                         |
| `MCP_PORT`                | `8000`         | Bind port (HTTP transports only)                         |
| `ALERTLOGIC_MCP_READONLY` | _(off)_        | Set to `true` to register only read tools — write and destructive tools are never exposed to the AI client |
| `ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE` | _(off)_ | Destructive tools (deletes, SOAR playbook execution, scan launches, ...) are suppressed by default. Set to `true` to arm all of them, or a comma-separated list of tool names to arm selectively |

### Optional service URL overrides

These default to AlertLogic's standard endpoints. Override only if you have a custom deployment:

```dotenv
ALERTLOGIC_GLOBAL_BASE_URL=https://api.global-services.global.alertlogic.com
ALERTLOGIC_AETUNER_BASE_URL=https://aetuner.mdr.global.alertlogic.com
ALERTLOGIC_CONNECTORS_BASE_URL=https://connectors.mdr.global.alertlogic.com
ALERTLOGIC_RESPONDER_BASE_URL=https://api.responder.alertlogic.com
```

### Creating an API key

1. Sign in to the AlertLogic console.
2. Navigate to **Manage → Users**, select your user, then open **Access Keys → Create**.
3. Copy the **Access Key ID** and **Secret Key**.
4. Combine them as `access_key_id:secret_key` (with the colon) and set that as `ALERTLOGIC_API_KEY`.

---

## Claude Code Integration (HTTP mode)

Start the server in HTTP mode:

```bash
MCP_TRANSPORT=streamable-http python main.py
```

Then register it in your Claude Code project or user MCP config (`.claude/settings.json` or `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "alertlogic-mcp": {
      "type": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Or via the CLI:

```bash
claude mcp add --transport http alertlogic-mcp http://localhost:8000/mcp
```

---

## Claude Desktop Integration (stdio mode)

Edit `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%AppData%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "alertlogic-mcp": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["/absolute/path/to/alertlogic-mcp/main.py"]
    }
  }
}
```

> Use absolute paths. Tilde (`~`) is not expanded by Claude Desktop. Point `command` at the venv Python, not the system Python.

Restart Claude Desktop. AlertLogic tools will appear in the tool picker.

---

## Module Overview

46 modules, ~473 tools, organized by domain:

### Incident Response

| Module           | Tools | Key operations                                                                          |
| ---------------- | :---: | --------------------------------------------------------------------------------------- |
| `incidents_mcp`  | 11    | List, get, friendly-ID lookup, complete, reopen, add notes, add feedback, list partner incidents |
| `soc`            | 14    | Submit/poll/release SQL log searches, list exposures, get health summary                |
| `soc_playbooks`  | 6     | Built-in IR guide, threat-hunt workflow, MITRE mapping, tool guides (see below)         |

### Asset Management

| Module           | Tools | Key operations                                                                          |
| ---------------- | :---: | --------------------------------------------------------------------------------------- |
| `assets`         | 15    | Query assets, get topology, declare/batch-declare/remove assets, set properties         |
| `assets_manager` | 5     | Higher-level asset management and grouping                                              |
| `cloud_explorer` | 12    | Browse AWS cloud resource topology by deployment                                        |
| `azure_explorer` | 13    | Browse Azure resource topology by deployment                                            |

### SOAR

| Module | Tools | Key operations                                                                                    |
| ------ | :---: | ------------------------------------------------------------------------------------------------- |
| `soar` | 33    | List/get playbooks and actions, create/get/query executions, manage inquiries and triggers        |

### Vulnerabilities & Compliance

| Module               | Tools | Key operations                                                        |
| -------------------- | :---: | --------------------------------------------------------------------- |
| `vulnerability`      | 10    | List exposures by severity, get per-asset exposures                   |
| `vulnerabilities_kb` | 9     | Query the vulnerability knowledge base (CVE details, CVSS, remediation) |
| `compliance`         | 4     | List remediation items, conclude/dispose/undispose remediations       |

### Users & Authentication

| Module        | Tools | Key operations                                                                        |
| ------------- | :---: | ------------------------------------------------------------------------------------- |
| `users`       | 30    | Full CRUD on users, roles, access keys, MFA, and password resets                     |
| `auth`        | 6     | AIMS token management, list managed accounts, account ID enumeration                 |
| `credentials` | 10    | IAM role and Azure AD credential CRUD, scan credentials, decrypted retrieval         |
| `themis`      | 3     | Credential validation and verification                                                |

### Infrastructure & Deployments

| Module             | Tools | Key operations                                                              |
| ------------------ | :---: | --------------------------------------------------------------------------- |
| `deployments`      | 5     | List, get, create, update, delete deployments                               |
| `environments`     | 10    | Manage AlertLogic environments and environment configuration                |
| `network_controls` | 15    | Exclusion CRUD, asset checks, tag/host whitelist management                 |
| `scan_scheduler`   | 13    | Create, update, and manage scan schedules per deployment                    |
| `scan_result`      | 4     | Retrieve and analyze scan results                                           |

### Analytics Engine

| Module      | Tools | Key operations                                                              |
| ----------- | :---: | --------------------------------------------------------------------------- |
| `aecontent` | 11    | Manage AE content (detection content library)                               |
| `aefr`      | 23    | AE flat-rule management                                                     |
| `aerta`     | 13    | AE real-time analytics management                                           |
| `aetag`     | 23    | AE tag and correlation rule management                                      |
| `aepublish` | 1     | Publish AE analytics updates                                                |
| `aemanual`  | 2     | Manual AE analytics operations                                              |
| `kalm`      | 5     | AE knowledge and analytics lifecycle management                             |

### Ticketing & Watchlist

| Module             | Tools | Key operations                                          |
| ------------------ | :---: | ------------------------------------------------------- |
| `tickets`          | 8     | Create, get, update, list, and close tickets            |
| `watchlist_module` | 7     | Manage the alerting watchlist (add, remove, query items) |

### Operations & Platform

| Module                | Tools | Key operations                                                         |
| --------------------- | :---: | ---------------------------------------------------------------------- |
| `account_management`  | 7     | Account details, lookup by name, parent/child relationships, topology  |
| `policies`            | 2     | List and inspect policies                                              |
| `billing`             | 12    | List and inspect subscriptions, entitlements, and billing data         |
| `common`              | 22    | Herald notifications, subscriptions, webhook/email connectors, endpoints |
| `ingest_module`       | 6     | Manage log ingest sources and ingest configuration                     |
| `logging_integration` | 17    | Log source CRUD, source types, collection management                   |
| `otis`                | 7     | On-demand threat intelligence search                                   |
| `notify`              | 2     | Notification dispatch                                                  |
| `search_stylist`      | 2     | Log search query formatting and suggestion                             |
| `informant`           | 2     | Informant service queries                                              |
| `strawboss`           | 10    | Strawboss job and schedule management                                  |
| `tacoma`              | 12    | Tacoma service operations                                              |
| `album`               | 10    | Evidence and artifact management                                       |
| `usage_module`        | 4     | Account usage statistics and reporting                                 |
| `bulk_ops`            | 2     | Cross-account bulk operations (bulk deployments, bulk health checks)   |
| `suggestions`         | 10    | AI-assisted search and investigation suggestions                       |
| `seceng`              | —     | Security Engineering: Cargo schedules/executions, AETuner analytics/tuning |

---

## SOC Quick Start

Once connected, try these prompts in Claude:

```
Show me all open critical incidents from the last 24 hours
```

```
Get the elaborations (raw log evidence) for incident INC-12345
```

```
Search logs for SSH login failures from 10.0.0.5 in the last hour using SQL
```

```
Add a note to incident INC-12345: Confirmed malicious, escalating to customer
```

```
List all deployments and their health status across all accounts
```

```
Show me the top 10 critical vulnerabilities for host web-prod-01
```

```
Run the SOC IR playbook to walk me through incident response steps
```

---

## Built-in SOC Playbooks

The `soc_playbooks` module provides six tools that surface curated, in-context operational guides — no external documentation lookups required:

| Tool                        | Contents                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `soc_ir_start`              | End-to-end incident response workflow: triage checklist, scoping steps, containment criteria, evidence collection, and documentation requirements |
| `soc_threat_hunt`           | Hypothesis-driven threat-hunting playbook: IOC-based hunts, TTP-based hunts, and log query templates for common attack patterns |
| `soc_mitre_attack_guide`    | MITRE ATT&CK tactic/technique reference mapped to AlertLogic detection types and recommended search queries |
| `soc_alertlogic_tool_guide` | Quick reference for AlertLogic MCP tools organized by investigation task (triage, scoping, evidence, containment) |
| `soc_log_query_templates`   | Ready-to-run SQL log query templates for common SOC scenarios: auth failures, lateral movement, C2 beaconing, data exfiltration, and more |
| `soc_summary`               | Executive-ready incident summary template and field-population guidance                    |

These tools are designed to be called at the start of an investigation to load relevant context before querying live data.

---

## Multi-Account MSSP Usage

The server is designed for MSSP environments where a single API key manages multiple child accounts:

**Partner incident listing** — `incidents_list_partner` returns incidents across all managed accounts in a single call, with account ownership labels.

**Per-tool account override** — Most tools accept an optional `account_id` parameter. Pass a child account's ID to scope any query to that account without changing your `.env` configuration:

```
Get all open incidents for account <child-account-id>
```

**Bulk operations** — `bulk_list_deployments` fans out a deployments query across all managed accounts and returns aggregated results. `bulk_health_check` does the same for health status.

**Account topology** — `aims_get_account_topology` and `aims_list_accounts_by_relationship` map the parent/child account hierarchy, useful for scoping operations before running them.

> **Tenant isolation**: When working across multiple accounts, always confirm the target account before running write operations (containment, note-adding, ticket creation). The server does not enforce cross-tenant guards beyond what the AlertLogic API provides.

---

## Security Notes

- **Read-only mode**: Set `ALERTLOGIC_MCP_READONLY=true` to register only read tools at startup. Write and destructive tools are never exposed to the AI client, regardless of what is asked.
- **Destructive operation gating**: Even with writes enabled, destructive tools (user/asset deletes, SOAR playbook execution, scan launches, key revocation, ...) are suppressed by default. Arm them explicitly via `ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE` — the recommended approach is a comma-separated list of specific tool names rather than `true`:

  ```bash
  # Enable only incident completion workflow deletes
  ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE=user_delete,playbook_execute
  ```

- Every tool carries MCP `readOnlyHint`/`destructiveHint` annotations so compliant clients can apply their own confirmation policies.
- **Never commit `.env`.** It is excluded by `.gitignore`; only `.env.example` (with placeholders) is tracked.
- Treat `ALERTLOGIC_API_KEY` like a password. Rotate it immediately if you suspect exposure (chat logs, screen shares, lost device).
- **AIMS token handling**: The server exchanges your API key for a short-lived Bearer token on first use and caches it in memory. The token is refreshed automatically on expiry. The raw `secret_key` is not logged or transmitted after the initial AIMS authentication call.
- In `stdio` mode, the server opens no network port. In `streamable-http` or `sse` mode, bind to `127.0.0.1` (the default) unless you specifically need remote access, in which case add appropriate network controls.
- `base.py` does not log request bodies, response bodies, or credential material. If you fork and add logging, take care to exclude token and secret values.
- This repository ships no credentials of any kind.

---

## Testing

A standalone smoke-test script exercises a representative cross-section of tools without going through an MCP client:

```bash
python smoke_test.py
```

This verifies credential validity, network reachability, and base configuration before wiring the server into your MCP client.

---

## Troubleshooting

<details>
<summary><b>"Authentication failed" / 401 errors</b></summary>

- Confirm `ALERTLOGIC_API_KEY` is the full `access_key_id:secret_key` string, including the colon separator.
- Verify `ALERTLOGIC_BASE_URL` matches your datacenter (US `api.cloudinsight.alertlogic.com` vs. UK `api.cloudinsight.alertlogic.co.uk`).
- Check that the access key is still active in the AlertLogic console (Manage → Users → Access Keys).
- Confirm `ALERTLOGIC_ACCOUNT_ID` is correct — a mismatch can cause 401s on account-scoped endpoints.

</details>

<details>
<summary><b>Tools don't appear in Claude Desktop</b></summary>

- Use absolute paths in `claude_desktop_config.json`. Tilde (`~`) and relative paths are not expanded.
- Point `command` at the virtual environment's Python (`.venv/bin/python`), not the system Python.
- Check Claude Desktop logs for stderr output from this server: macOS logs are in `~/Library/Logs/Claude/`.
- Restart Claude Desktop fully (quit and reopen) after editing the config file.

</details>

<details>
<summary><b>"ModuleNotFoundError: mcp" or missing dependencies</b></summary>

You are running `python main.py` outside the virtual environment. Either activate it first (`source .venv/bin/activate`) or invoke the venv's Python directly (`/path/to/.venv/bin/python main.py`).

</details>

<details>
<summary><b>HTTP mode: connection refused on port 8000</b></summary>

Make sure you started the server with `MCP_TRANSPORT=streamable-http python main.py` before attempting to connect. The server only binds a port when a non-stdio transport is selected.

</details>

<details>
<summary><b>Empty results or silent failures</b></summary>

If all tool calls return empty results or fail silently, this is often caused by an SSO or proxy layer blocking outbound API calls. Try running from a non-proxied network or a different client to confirm. Also check that `ALERTLOGIC_BASE_URL` and `ALERTLOGIC_ACCOUNT_ID` are both correct for your environment.

</details>

---

## Contributing

PRs and issues are welcome.

1. Fork the repository, create a feature branch, commit your changes, and open a PR.
2. Add new AlertLogic endpoints as additional `@server.tool` definitions in the matching module file under `modules/`.
3. For a new module: create `modules/<name>.py` with a `setup(server)` function, then add it to the `MODULES` list in `main.py`.
4. Keep tool docstrings accurate and descriptive — the docstring is what the LLM sees when deciding whether and how to call the tool.
5. Run `python smoke_test.py` before submitting to verify basic functionality.

---

## Related MCP Servers

These three servers cover complementary layers of a security stack — network/log (AlertLogic), endpoint protection (Sophos), and EDR/threat intel (CrowdStrike). Use them together for full-stack AI-powered SOC operations.

| Server | Platform | Highlights |
|--------|----------|------------|
| [falcon-mcp](https://github.com/rijul170/falcon-mcp) | CrowdStrike Falcon | EDR telemetry, RTR, threat intel, MSSP Flight Control, 1,296 tools |
| [sophos-central-mcp](https://github.com/rijul170/sophos-central-mcp) | Sophos Central | Endpoint isolation, Live Discover SQL, XDR, email/firewall/DNS, 334 tools |
| [alertlogic-mcp](https://github.com/rijul170/alertlogic-mcp) | Alert Logic MDR | Incident response, SQL log search, SOAR, vulnerability management, 473 tools |

## License

MIT License. See [LICENSE](LICENSE) for full text.
