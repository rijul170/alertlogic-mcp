"""
AlertLogic Scan Result (Legacy Cloud Insight).
Retrieves vulnerability scan results per host and deployment from the legacy
Cloud Insight scan/v1 API.

This is a legacy service predating the modern vulnerabilities/v1 and
remediations/v1 MDR APIs.  It returns raw scan execution output and per-host
vulnerability findings.

Console portal: https://console.cloudinsight.alertlogic.com/api/scan_result/
Service base:   https://api.cloudinsight.alertlogic.com

Endpoint summary
----------------
  GET /scan/v1/scans                           — list scans for an account
  GET /scan/v1/scans/{scan_id}                 — list executions for a scan
  GET /scan/v1/results/{scan_exec_id}          — get results for an execution
"""
from typing import Annotated, Optional

from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class ScanResultModule(BaseModule):
    """Legacy vulnerability scan result retrieval (scan/v1)."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.scan_result_list_scans, "scan_result_list_scans",
                        "List vulnerability scans for an account. "
                        "Optionally filter by customer/account ID and active-only flag.")
        self._add_tool(server, self.scan_result_list_executions, "scan_result_list_executions",
                        "List executions (runs) for a specific scan. "
                        "Returns up to the 10 most recent executions including "
                        "start/finish timestamps and duration.")
        self._add_tool(server, self.scan_result_get_results, "scan_result_get_results",
                        "Get vulnerability results for a scan execution. "
                        "Optionally filter to new vulnerabilities or new vulnerable "
                        "ports discovered in this specific execution.")
        self._add_tool(server, self.scan_result_get_latest, "scan_result_get_latest",
                        "Convenience helper: list executions for a scan and return "
                        "the results for the most recently completed execution.")

    # ------------------------------------------------------------------ #
    #  1. List scans                                                       #
    # ------------------------------------------------------------------ #

    def scan_result_list_scans(
        self,
        customer_id: Annotated[Optional[str], Field(
            description="Filter by customer/account ID. "
                        "When omitted the authenticated account is used."
        )] = None,
        active_only: Annotated[bool, Field(
            description="When True, return only scans that are currently active."
        )] = False,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID override (uses configured default when omitted)."
        )] = None,
    ) -> dict:
        """List scans. GET /scan/v1/scans[?customer_id=X]"""
        params: dict = {}
        if customer_id:
            params["customer_id"] = customer_id

        result = self._get("/scan/v1/scans", account_id=account_id, params=params or None)

        # Client-side active filter — the legacy API returns all scans and
        # callers are expected to filter client-side.
        if active_only and isinstance(result.get("data"), list):
            result["data"] = [s for s in result["data"] if s.get("active")]
        elif active_only and isinstance(result.get("data"), dict):
            scans = result["data"].get("scans", [])
            result["data"]["scans"] = [s for s in scans if s.get("active")]

        return result

    # ------------------------------------------------------------------ #
    #  2. List executions for a scan                                       #
    # ------------------------------------------------------------------ #

    def scan_result_list_executions(
        self,
        scan_id: Annotated[str, Field(
            description="Scan identifier (integer or UUID depending on account vintage)."
        )],
        limit: Annotated[Optional[int], Field(
            description="Maximum number of executions to return (default 10, max 10 "
                        "per legacy API contract).",
            ge=1,
            le=50,
        )] = 10,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID override."
        )] = None,
    ) -> dict:
        """List executions for a scan. GET /scan/v1/scans/{scan_id}"""
        result = self._get(f"/scan/v1/scans/{scan_id}", account_id=account_id)

        # Apply client-side limit and annotate the most recently completed execution.
        if isinstance(result.get("data"), list):
            executions = result["data"]
            executions = executions[:limit]
            completed = [e for e in executions if not e.get("active")]
            if completed:
                # Sort descending by finish_date so index 0 is the latest complete.
                completed_sorted = sorted(
                    completed,
                    key=lambda e: e.get("finish_date", ""),
                    reverse=True,
                )
                executions_with_latest = []
                latest_id = completed_sorted[0].get("id")
                for e in executions:
                    annotated = dict(e)
                    if annotated.get("id") == latest_id:
                        annotated["_latest_complete"] = True
                    executions_with_latest.append(annotated)
                result["data"] = executions_with_latest
            else:
                result["data"] = executions

        return result

    # ------------------------------------------------------------------ #
    #  3. Get results for an execution                                     #
    # ------------------------------------------------------------------ #

    def scan_result_get_results(
        self,
        scan_exec_id: Annotated[str, Field(
            description="Scan execution ID returned by scan_result_list_executions."
        )],
        new_vulns: Annotated[bool, Field(
            description="When True, return only vulnerabilities that are new in "
                        "this execution (not seen in prior runs)."
        )] = False,
        new_ports: Annotated[bool, Field(
            description="When True, return only newly discovered vulnerable ports "
                        "in this execution."
        )] = False,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID override."
        )] = None,
    ) -> dict:
        """Get scan results. GET /scan/v1/results/{scan_exec_id}[?new_vulns=true&new_ports=true]"""
        params: dict = {}
        if new_vulns:
            params["new_vulns"] = "true"
        if new_ports:
            params["new_ports"] = "true"
        return self._get(
            f"/scan/v1/results/{scan_exec_id}",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  4. Convenience: results for latest completed execution              #
    # ------------------------------------------------------------------ #

    def scan_result_get_latest(
        self,
        scan_id: Annotated[str, Field(
            description="Scan ID whose latest completed execution results to fetch."
        )],
        new_vulns: Annotated[bool, Field(
            description="Return only newly discovered vulnerabilities."
        )] = False,
        new_ports: Annotated[bool, Field(
            description="Return only newly discovered vulnerable ports."
        )] = False,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID override."
        )] = None,
    ) -> dict:
        """Fetch results for the latest completed execution of a scan.

        Calls GET /scan/v1/scans/{scan_id} to discover executions, then
        calls GET /scan/v1/results/{latest_exec_id} for the most recently
        finished one.
        """
        execs_result = self._get(f"/scan/v1/scans/{scan_id}", account_id=account_id)
        if "error" in execs_result:
            return execs_result

        data = execs_result.get("data", [])
        executions = data if isinstance(data, list) else data.get("executions", [])
        completed = [e for e in executions if not e.get("active")]

        if not completed:
            return {
                "error": "No completed executions found for scan",
                "scan_id": scan_id,
            }

        latest = max(completed, key=lambda e: e.get("finish_date", ""))
        exec_id = latest.get("id")
        if not exec_id:
            return {"error": "Latest execution has no ID", "execution": latest}

        return self.scan_result_get_results(
            scan_exec_id=str(exec_id),
            new_vulns=new_vulns,
            new_ports=new_ports,
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = ScanResultModule()
    mod.register_tools(server)
