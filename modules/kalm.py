"""
AlertLogic KALM — Named Queries and Tables Service.
Provides access to pre-defined named queries and data tables for Alert Logic
accounts. Named queries are reusable search templates; tables are structured
data sources that can be queried directly.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/kalm/kalm.v1.yaml
Host: api.cloudinsight.alertlogic.com (default)
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


KalmManagedAccounts = Literal["true", "children_only", "false"]


class KalmModule(BaseModule):
    """
    KALM — Named queries and tables for Alert Logic accounts.

    Named queries are stored, parameterized search templates.
    Tables are structured views of account data that support direct queries.
    Both can be scoped to managed (child) accounts.
    """

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server, self.kalm_list_named_queries, "kalm_list_named_queries",
            "List all named queries available for an account",
        )
        self._add_tool(
            server, self.kalm_get_named_query, "kalm_get_named_query",
            "Get a specific named query definition by name",
        )
        self._add_tool(
            server, self.kalm_list_tables, "kalm_list_tables",
            "List all data tables available for an account",
        )
        self._add_tool(
            server, self.kalm_get_table, "kalm_get_table",
            "Get a specific data table definition by name",
        )
        self._add_tool(
            server, self.kalm_run_query, "kalm_run_query",
            "Execute a named query or table query for an account",
        )

    # ------------------------------------------------------------------ #
    #  Named queries                                                       #
    # ------------------------------------------------------------------ #

    def kalm_list_named_queries(
        self,
        managed_accounts: Annotated[Optional[KalmManagedAccounts], Field(
            description=(
                "Include managed account data: "
                "'true' = account + all children, "
                "'children_only' = child accounts only, "
                "'false' = this account only (default)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List all named queries available for an account.
        GET /kalm/v1/{account_id}/named_query on default host.
        """
        params = {}
        if managed_accounts is not None:
            params["managed_accounts"] = managed_accounts
        return self._get(
            "/kalm/v1/{account_id}/named_query",
            account_id=account_id,
            params=params or None,
        )

    def kalm_get_named_query(
        self,
        query_name: Annotated[str, Field(
            description="Name identifier of the named query to retrieve"
        )],
        managed_accounts: Annotated[Optional[KalmManagedAccounts], Field(
            description=(
                "Scope for managed accounts: "
                "'true', 'children_only', or 'false' (default)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get a specific named query definition by name.
        GET /kalm/v1/{account_id}/named_query/{query_name} on default host.
        """
        params = {}
        if managed_accounts is not None:
            params["managed_accounts"] = managed_accounts
        return self._get(
            f"/kalm/v1/{{account_id}}/named_query/{query_name}",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  Tables                                                              #
    # ------------------------------------------------------------------ #

    def kalm_list_tables(
        self,
        managed_accounts: Annotated[Optional[KalmManagedAccounts], Field(
            description=(
                "Scope for managed accounts: "
                "'true', 'children_only', or 'false' (default)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List all data tables available for an account.
        GET /kalm/v1/{account_id}/table on default host.
        """
        params = {}
        if managed_accounts is not None:
            params["managed_accounts"] = managed_accounts
        return self._get(
            "/kalm/v1/{account_id}/table",
            account_id=account_id,
            params=params or None,
        )

    def kalm_get_table(
        self,
        table_name: Annotated[str, Field(
            description="Name identifier of the table to retrieve"
        )],
        managed_accounts: Annotated[Optional[KalmManagedAccounts], Field(
            description=(
                "Scope for managed accounts: "
                "'true', 'children_only', or 'false' (default)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get a specific data table definition by name.
        GET /kalm/v1/{account_id}/table/{table_name} on default host.
        """
        params = {}
        if managed_accounts is not None:
            params["managed_accounts"] = managed_accounts
        return self._get(
            f"/kalm/v1/{{account_id}}/table/{table_name}",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  Query execution                                                     #
    # ------------------------------------------------------------------ #

    def kalm_run_query(
        self,
        named_or_table_query: Annotated[str, Field(
            description=(
                "Name of the named query or table query to execute. "
                "This corresponds to a query_name from kalm_list_named_queries "
                "or a table_name from kalm_list_tables."
            )
        )],
        managed_accounts: Annotated[Optional[KalmManagedAccounts], Field(
            description=(
                "Scope for managed accounts: "
                "'true', 'children_only', or 'false' (default)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Execute a named query or table query for an account.
        GET /kalm/v1/{account_id}/query/{named_or_table_query} on default host.
        """
        params = {}
        if managed_accounts is not None:
            params["managed_accounts"] = managed_accounts
        return self._get(
            f"/kalm/v1/{{account_id}}/query/{named_or_table_query}",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = KalmModule()
    mod.register_tools(server)
