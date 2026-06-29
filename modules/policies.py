"""
AlertLogic Policies Management.
List and inspect scan/IDS/log policies.

Official API: https://console.cloudinsight.alertlogic.com/api/policies/
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class PoliciesModule(BaseModule):
    """Policy inspection and management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.policies_list, "policies_list",
                        "List all policies for an account")
        self._add_tool(server, self.policies_get, "policies_get",
                        "Get a specific policy by ID")

    def policies_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List policies. GET /policies/v1/{account_id}/policies"""
        return self._get("/policies/v1/{account_id}/policies", account_id=account_id)

    def policies_get(
        self,
        policy_id: Annotated[str, Field(description="Policy UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get policy. GET /policies/v1/{account_id}/policies/{policy_id}"""
        return self._get(
            f"/policies/v1/{{account_id}}/policies/{policy_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = PoliciesModule()
    mod.register_tools(server)