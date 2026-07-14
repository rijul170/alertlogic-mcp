"""
Smoke test: hit one tool per service area and report status.
Reads creds from .env. Read-only — no writes.
"""
import os
import sys
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_DIR))
from dotenv import load_dotenv
load_dotenv(PROJECT_DIR / ".env")

from alertlogic_mcp.modules.auth import AuthModule
from alertlogic_mcp.modules.users import UsersModule
from alertlogic_mcp.modules.deployments import DeploymentsModule
from alertlogic_mcp.modules.incidents_mcp import IncidentsModule
from alertlogic_mcp.modules.vulnerability import VulnerabilityModule
from alertlogic_mcp.modules.seceng import SecEngModule
from alertlogic_mcp.modules.soar import SOARModule
from alertlogic_mcp.modules.common import CommonModule
from alertlogic_mcp.modules.billing import BillingModule
from alertlogic_mcp.modules.network_controls import NetworkControlsModule
from alertlogic_mcp.modules.logging_integration import LoggingIntegrationModule
from alertlogic_mcp.modules.credentials import CredentialsModule


def classify(result: dict) -> tuple[str, str]:
    """Return (status, summary)."""
    if "error" in result:
        sc = result.get("status_code")
        return ("FAIL", f"{result['error']} (status={sc})")
    sc = result.get("status_code")
    data = result.get("data", result)
    if isinstance(data, dict):
        # Pick a useful summary
        for key in ("users", "deployments", "incidents", "exposures",
                    "schedules", "playbooks", "subscriptions",
                    "notification_types", "items"):
            if key in data and isinstance(data[key], list):
                return ("OK", f"{sc} — {len(data[key])} {key}")
        if "authentication" in data:
            acct = data["authentication"].get("account", {}).get("id")
            return ("OK", f"{sc} — authenticated as account {acct}")
        if "account" in data and isinstance(data["account"], dict):
            return ("OK", f"{sc} — account {data['account'].get('id')}")
        return ("OK", f"{sc} — keys: {sorted(data.keys())[:6]}")
    if isinstance(data, list):
        return ("OK", f"{sc} — {len(data)} items")
    return ("OK", f"{sc} — {type(data).__name__}")


def run(label: str, fn) -> None:
    t0 = time.monotonic()
    try:
        result = fn()
        elapsed = (time.monotonic() - t0) * 1000
        status, summary = classify(result)
    except Exception as e:
        elapsed = (time.monotonic() - t0) * 1000
        status, summary = "EXC", f"{type(e).__name__}: {e}"
    flag = {"OK": "✓", "FAIL": "✗", "EXC": "!"}[status]
    print(f"  {flag} [{elapsed:6.0f}ms] {label:42s} → {summary}")


def main():
    print(f"AlertLogic MCP smoke test")
    print(f"Account: {os.getenv('ALERTLOGIC_ACCOUNT_ID')}")
    print(f"Base:    {os.getenv('ALERTLOGIC_BASE_URL', 'cloudinsight default')}")
    print()

    # 1. AIMS — auth + token info
    print("[1] AIMS (default host)")
    auth = AuthModule()
    run("aims_authenticate", lambda: auth.authenticate())
    run("aims_token_info", auth.aims_token_info)
    run("aims_list_users (UsersModule)", UsersModule().aims_list_users)

    # 2. Deployments — also captures a deployment_id for downstream tests
    print("\n[2] Deployments (default host)")
    dep_mod = DeploymentsModule()
    deployments_result = dep_mod.deployments_list()
    run("deployments_list", lambda: deployments_result)
    deployment_id = None
    data = deployments_result.get("data") or []
    if isinstance(data, list) and data:
        deployment_id = data[0].get("id")
        print(f"      using deployment_id={deployment_id} for scoped tests")

    # 3. IRIS
    print("\n[3] IRIS — incidents (default host)")
    now = int(time.time())
    day_ago = now - 24 * 3600
    run("incidents_list (last 24h)",
        lambda: IncidentsModule().incidents_list(
            start_time=str(day_ago), end_time=str(now), limit=10))

    # 4. assets_query v2 — exposures
    print("\n[4] assets_query v2 (default host)")
    run("vuln_list_exposures",
        lambda: VulnerabilityModule().vuln_list_exposures())

    # 5. Cargo v2
    print("\n[5] Cargo v2 (default host)")
    run("cargo_list_schedules",
        lambda: SecEngModule().cargo_list_schedules())

    # 6. Responder (dedicated host)
    print("\n[6] Responder (api.responder.alertlogic.com)")
    run("responder_list_playbooks",
        lambda: SOARModule().responder_list_playbooks())

    # 7. Connectors (dedicated host)
    print("\n[7] Connectors (connectors.mdr.global.alertlogic.com)")
    run("connectors_list_integration_types",
        lambda: CommonModule().connectors_list_integration_types())

    # Bonus — global host
    print("\n[8] Herald (global) + Subscriptions (global)")
    run("herald_list_notification_types",
        lambda: CommonModule().herald_list_notification_types())
    run("subscriptions_list",
        lambda: BillingModule().subscriptions_list())

    # Unverified modules — these were flagged because the SDK definitions
    # don't include their service. Live test tells us if the code is real.
    print("\n[9] Unverified — sources / exclusions / scan-credentials")
    run("sources_list  (logging_integration)",
        lambda: LoggingIntegrationModule().sources_list())
    if deployment_id:
        run("exclusions_list  (network_controls)",
            lambda: NetworkControlsModule().exclusions_list(deployment_id=deployment_id))
        run("whitelist_list_tags  (fixed path)",
            lambda: NetworkControlsModule().whitelist_list_tags(deployment_id=deployment_id))
        run("whitelist_list_hosts  (new tool)",
            lambda: NetworkControlsModule().whitelist_list_hosts(deployment_id=deployment_id))
        run("credentials_get_all_scan  (fixed path)",
            lambda: CredentialsModule().credentials_get_all_scan(environment_id=deployment_id))
    else:
        print("      (skipped deployment-scoped tests — no deployment_id)")


if __name__ == "__main__":
    main()
