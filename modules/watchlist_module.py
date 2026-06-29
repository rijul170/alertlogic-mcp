"""
AlertLogic Watchlist Service.
Manage threat intelligence watchlist entries (IPs, domains, hashes).

Maps to: Watchlist API v1
"""
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


# Alert Logic watchlist entry types.
EntryType = Literal["ip", "domain", "hash", "url", "cidr"]


class WatchlistModule(BaseModule):
    """Watchlist CRUD and batch operations."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.watchlist_list_entries, "watchlist_list_entries",
                        "List all watchlist entries for an account, optionally filtered by type")
        self._add_tool(server, self.watchlist_get_entry, "watchlist_get_entry",
                        "Get a single watchlist entry by ID")
        self._add_tool(server, self.watchlist_add_entry, "watchlist_add_entry",
                        "Add a new entry to the watchlist")
        self._add_tool(server, self.watchlist_update_entry, "watchlist_update_entry",
                        "Update an existing watchlist entry")
        self._add_tool(server, self.watchlist_delete_entry, "watchlist_delete_entry",
                        "Delete a watchlist entry by ID")
        self._add_tool(server, self.watchlist_batch_add_entries, "watchlist_batch_add_entries",
                        "Add multiple watchlist entries in a single batch request")
        self._add_tool(server, self.watchlist_check, "watchlist_check",
                        "Check whether a given value is present in the watchlist")

    # ---- Read ----

    def watchlist_list_entries(
        self,
        entry_type: Annotated[Optional[EntryType], Field(
            description="Filter by entry type: ip, domain, hash, url, or cidr"
        )] = None,
        page: Annotated[Optional[int], Field(
            description="Page number (1-based) for paginated results"
        )] = None,
        page_size: Annotated[Optional[int], Field(
            description="Number of entries per page (default determined by server)"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List watchlist entries. GET /watchlist/v1/{account_id}/entries"""
        params = {}
        if entry_type is not None:
            params["type"] = entry_type
        if page is not None:
            params["page"] = page
        if page_size is not None:
            params["page_size"] = page_size
        return self._get(
            "/watchlist/v1/{account_id}/entries",
            account_id=account_id,
            params=params or None,
        )

    def watchlist_get_entry(
        self,
        entry_id: Annotated[str, Field(description="Watchlist entry ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a watchlist entry. GET /watchlist/v1/{account_id}/entries/{entry_id}"""
        return self._get(
            f"/watchlist/v1/{{account_id}}/entries/{entry_id}",
            account_id=account_id,
        )

    def watchlist_check(
        self,
        value: Annotated[str, Field(
            description="Value to look up (e.g. an IP address, domain, or hash)"
        )],
        entry_type: Annotated[Optional[EntryType], Field(
            description="Restrict the check to a specific entry type: ip, domain, hash, url, or cidr"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Check if a value is in the watchlist. GET /watchlist/v1/{account_id}/check"""
        params: dict = {"value": value}
        if entry_type is not None:
            params["type"] = entry_type
        return self._get(
            "/watchlist/v1/{account_id}/check",
            account_id=account_id,
            params=params,
        )

    # ---- Write ----

    def watchlist_add_entry(
        self,
        entry_type: Annotated[EntryType, Field(
            description="Entry type: ip, domain, hash, url, or cidr"
        )],
        value: Annotated[str, Field(
            description="The value to add (e.g. '1.2.3.4' for an IP entry)"
        )],
        comment: Annotated[Optional[str], Field(
            description="Human-readable comment / reason for adding this entry"
        )] = None,
        expiry: Annotated[Optional[str], Field(
            description="ISO 8601 expiry timestamp after which the entry is automatically removed"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Add a watchlist entry. POST /watchlist/v1/{account_id}/entries"""
        body: dict = {"type": entry_type, "value": value}
        if comment is not None:
            body["comment"] = comment
        if expiry is not None:
            body["expiry"] = expiry
        return self._post(
            "/watchlist/v1/{account_id}/entries",
            account_id=account_id,
            json_body=body,
        )

    def watchlist_update_entry(
        self,
        entry_id: Annotated[str, Field(description="Watchlist entry ID to update")],
        entry_type: Annotated[Optional[EntryType], Field(
            description="Updated entry type: ip, domain, hash, url, or cidr"
        )] = None,
        value: Annotated[Optional[str], Field(
            description="Updated value for the entry"
        )] = None,
        comment: Annotated[Optional[str], Field(
            description="Updated comment / reason"
        )] = None,
        expiry: Annotated[Optional[str], Field(
            description="Updated ISO 8601 expiry timestamp (pass null/empty to remove expiry)"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update a watchlist entry. PUT /watchlist/v1/{account_id}/entries/{entry_id}"""
        body: dict = {}
        if entry_type is not None:
            body["type"] = entry_type
        if value is not None:
            body["value"] = value
        if comment is not None:
            body["comment"] = comment
        if expiry is not None:
            body["expiry"] = expiry
        return self._put(
            f"/watchlist/v1/{{account_id}}/entries/{entry_id}",
            account_id=account_id,
            json_body=body,
        )

    def watchlist_delete_entry(
        self,
        entry_id: Annotated[str, Field(description="Watchlist entry ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete a watchlist entry. DELETE /watchlist/v1/{account_id}/entries/{entry_id}"""
        return self._delete(
            f"/watchlist/v1/{{account_id}}/entries/{entry_id}",
            account_id=account_id,
        )

    def watchlist_batch_add_entries(
        self,
        entries: Annotated[List[dict], Field(
            description=(
                "List of entry objects to add. Each entry must include 'type' and 'value'; "
                "'comment' and 'expiry' are optional. "
                "Example: [{'type': 'ip', 'value': '1.2.3.4', 'comment': 'C2 server'}]"
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Batch add watchlist entries. POST /watchlist/v1/{account_id}/entries/batch"""
        return self._post(
            "/watchlist/v1/{account_id}/entries/batch",
            account_id=account_id,
            json_body={"entries": entries},
        )


def setup(server: FastMCP):
    mod = WatchlistModule()
    mod.register_tools(server)
