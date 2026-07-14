"""
AlertLogic Account Management.
AIMS account relationships, topology, and account lookups.

Official API: https://console.cloudinsight.alertlogic.com/api/aims/
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


class AccountManagementModule(BaseModule):
    """AIMS Account Relationship & Topology Management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.aims_get_account_details, "aims_get_account_details",
                        "Get detailed account information")
        self._add_tool(server, self.aims_get_account_by_name, "aims_get_account_by_name",
                        "Look up accounts by name")
        self._add_tool(server, self.aims_get_account_topology, "aims_get_account_topology",
                        "Get account relationship topology (parent/child hierarchy)")
        self._add_tool(server, self.aims_check_relationship, "aims_check_relationship",
                        "Check if a relationship exists between two accounts")
        self._add_tool(server, self.aims_list_accounts_by_relationship, "aims_list_accounts_by_relationship",
                        "List all accounts by relationship type (managed/managing)")
        self._add_tool(server, self.aims_get_account_ids_by_relationship, "aims_get_account_ids_by_relationship",
                        "Return account IDs (not full objects) for a relationship type")
        self._add_tool(server, self.aims_list_accounts_managed_v2, "aims_list_accounts_managed_v2",
                        "Get all managed sub-accounts via the /accounts/managed endpoint")

    def aims_get_account_details(
        self,
        account_id: Annotated[Optional[str], Field(description="AIMS Account ID (defaults to your account)")] = None,
    ) -> dict:
        """Get account details. GET /aims/v1/{account_id}/account"""
        return self._get("/aims/v1/{account_id}/account", account_id=account_id)

    def aims_get_account_by_name(
        self,
        account_name: Annotated[str, Field(description="Account name to search for (URL-safe)")],
    ) -> dict:
        """Find accounts by name. GET /aims/v1/accounts/name/{account_name}"""
        return self._get(f"/aims/v1/accounts/name/{url_quote(account_name)}")

    def aims_get_account_topology(
        self,
        relationship: Annotated[str, Field(description="Relationship: 'managed' or 'managing'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        active: Annotated[Optional[bool], Field(description="Filter by active status")] = None,
    ) -> dict:
        """Get account topology. GET /aims/v1/{account_id}/accounts/{relationship}/topology"""
        params = {}
        if active is not None:
            params["active"] = str(active).lower()
        return self._get(
            f"/aims/v1/{{account_id}}/accounts/{relationship}/topology",
            account_id=account_id,
            params=params or None,
        )

    def aims_check_relationship(
        self,
        related_account_id: Annotated[str, Field(description="Related account ID to check")],
        relationship: Annotated[str, Field(description="Relationship: 'managed' or 'managing'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Check account relationship. GET /aims/v1/{account_id}/accounts/{relationship}/{related_account_id}"""
        return self._get(
            f"/aims/v1/{{account_id}}/accounts/{relationship}/{related_account_id}",
            account_id=account_id,
        )

    def aims_list_accounts_by_relationship(
        self,
        relationship: Annotated[str, Field(description="Relationship: 'managed' or 'managing'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        active: Annotated[Optional[bool], Field(description="Filter by active status")] = None,
    ) -> dict:
        """List accounts by relationship. GET /aims/v1/{account_id}/accounts/{relationship}"""
        params = {}
        if active is not None:
            params["active"] = str(active).lower()
        return self._get(
            f"/aims/v1/{{account_id}}/accounts/{relationship}",
            account_id=account_id,
            params=params or None,
        )

    def aims_get_account_ids_by_relationship(
        self,
        relationship: Annotated[str, Field(description="Relationship: 'managed' or 'managing'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Return account IDs for a relationship. GET /aims/v1/{account_id}/account_ids/{relationship}"""
        return self._get(
            f"/aims/v1/{{account_id}}/account_ids/{relationship}",
            account_id=account_id,
        )

    def aims_list_accounts_managed_v2(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        active: Annotated[Optional[bool], Field(description="Filter by active status")] = None,
    ) -> dict:
        """Get all managed sub-accounts. GET /aims/v1/{account_id}/accounts/managed"""
        params = {}
        if active is not None:
            params["active"] = str(active).lower()
        return self._get(
            "/aims/v1/{account_id}/accounts/managed",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = AccountManagementModule()
    mod.register_tools(server)
