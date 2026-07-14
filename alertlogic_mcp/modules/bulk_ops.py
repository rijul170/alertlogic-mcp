"""
AlertLogic Bulk Operations.
Cross-account batch operations for MSSP workflows.
"""
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated, List
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class BulkOpsModule(BaseModule):
    """Bulk/batch operations across managed accounts."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.bulk_list_deployments, "bulk_list_deployments",
                        "List deployments across all managed accounts (parallel)")
        self._add_tool(server, self.bulk_health_check, "bulk_health_check",
                        "Get collection-health summary across managed accounts (parallel)")

    def _fan_out(self, account_ids: List[str], path: str) -> dict:
        results: dict = {}
        with ThreadPoolExecutor(max_workers=min(16, max(1, len(account_ids)))) as pool:
            futures = {pool.submit(self._get, path, account_id=aid): aid for aid in account_ids}
            for fut, aid in futures.items():
                try:
                    results[aid] = fut.result()
                except Exception as e:
                    results[aid] = {"error": "request failed", "details": str(e)}
        return {"accounts": results}

    def bulk_list_deployments(
        self,
        account_ids: Annotated[List[str], Field(description="Managed account IDs to query")],
    ) -> dict:
        """Fan out: GET /deployments/v1/{account_id}/deployments per account."""
        return self._fan_out(account_ids, "/deployments/v1/{account_id}/deployments")

    def bulk_health_check(
        self,
        account_ids: Annotated[List[str], Field(description="Managed account IDs to check")],
    ) -> dict:
        """Fan out: GET /remediations/v1/{account_id}/health/summary per account."""
        return self._fan_out(account_ids, "/remediations/v1/{account_id}/health/summary")


def setup(server: FastMCP):
    mod = BulkOpsModule()
    mod.register_tools(server)
