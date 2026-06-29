"""
AlertLogic Suggestions Service — saved log search query management.

Covers the full v1 (simple saved searches) and v2 (enhanced saved searches
with metadata: description, tags, sharing) APIs.

Service base URL: https://api.cloudinsight.alertlogic.com (default host)
Spec: https://console.cloudinsight.alertlogic.com/api/suggestions/
"""
from typing import Annotated, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class SuggestionsModule(BaseModule):
    """Saved log search query management (Suggestions v1 and v2)."""

    def register_tools(self, server: FastMCP):
        # v1
        self._add_tool(server, self.suggestions_v1_list, "suggestions_v1_list",
                        "List all saved search queries for an account (v1)")
        self._add_tool(server, self.suggestions_v1_get, "suggestions_v1_get",
                        "Get a single saved search query by ID (v1)")
        self._add_tool(server, self.suggestions_v1_create, "suggestions_v1_create",
                        "Create a new saved search query (v1)")
        self._add_tool(server, self.suggestions_v1_update, "suggestions_v1_update",
                        "Update an existing saved search query (v1)")
        self._add_tool(server, self.suggestions_v1_delete, "suggestions_v1_delete",
                        "Delete a saved search query (v1)")
        # v2
        self._add_tool(server, self.suggestions_v2_list, "suggestions_v2_list",
                        "List saved search queries with optional filters: name, tags, shared (v2)")
        self._add_tool(server, self.suggestions_v2_get, "suggestions_v2_get",
                        "Get a single saved search query by ID (v2)")
        self._add_tool(server, self.suggestions_v2_create, "suggestions_v2_create",
                        "Create a new saved search query with metadata: description, tags, shared flag (v2)")
        self._add_tool(server, self.suggestions_v2_update, "suggestions_v2_update",
                        "Update an existing saved search query (v2)")
        self._add_tool(server, self.suggestions_v2_delete, "suggestions_v2_delete",
                        "Delete a saved search query (v2)")

    # ------------------------------------------------------------------ #
    #  v1 — Simple saved searches                                         #
    # ------------------------------------------------------------------ #

    def suggestions_v1_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List saved queries. GET /suggestions/v1/{account_id}/queries"""
        return self._get("/suggestions/v1/{account_id}/queries", account_id=account_id)

    def suggestions_v1_get(
        self,
        query_id: Annotated[str, Field(description="Saved query ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get saved query. GET /suggestions/v1/{account_id}/queries/{query_id}"""
        return self._get(
            f"/suggestions/v1/{{account_id}}/queries/{query_id}",
            account_id=account_id,
        )

    def suggestions_v1_create(
        self,
        name: Annotated[str, Field(description="Display name for the saved query")],
        search_request: Annotated[dict, Field(
            description=(
                "Structured search request object (v1 format). Required fields: "
                "'select' (list of field descriptors), 'where' (filter list). "
                "Use suggestions_v2_create for plain SQL/EMS query strings."
            )
        )],
        data_type: Annotated[str, Field(
            description="Data type for the query, e.g. 'logmsgs'"
        )] = "logmsgs",
        group_id: Annotated[Optional[str], Field(
            description="Group UUID to assign the query to"
        )] = None,
        description: Annotated[Optional[str], Field(
            description="Human-readable description of the query"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create saved query. POST /suggestions/v1/{account_id}/queries"""
        body: dict = {"name": name, "data_type": data_type, "search_request": search_request}
        if group_id is not None:
            body["group_id"] = group_id
        if description is not None:
            body["description"] = description
        return self._post(
            "/suggestions/v1/{account_id}/queries",
            account_id=account_id,
            json_body=body,
        )

    def suggestions_v1_update(
        self,
        query_id: Annotated[str, Field(description="Saved query ID to update")],
        name: Annotated[Optional[str], Field(description="New display name")] = None,
        search_request: Annotated[Optional[dict], Field(
            description="Updated structured search request object (v1 format)"
        )] = None,
        description: Annotated[Optional[str], Field(description="New description")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update saved query. PUT /suggestions/v1/{account_id}/queries/{query_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if search_request is not None:
            body["search_request"] = search_request
        if description is not None:
            body["description"] = description
        return self._put(
            f"/suggestions/v1/{{account_id}}/queries/{query_id}",
            account_id=account_id,
            json_body=body,
        )

    def suggestions_v1_delete(
        self,
        query_id: Annotated[str, Field(description="Saved query ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete saved query. DELETE /suggestions/v1/{account_id}/queries/{query_id}"""
        return self._delete(
            f"/suggestions/v1/{{account_id}}/queries/{query_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  v2 — Enhanced saved searches (description, tags, sharing)         #
    # ------------------------------------------------------------------ #

    def suggestions_v2_list(
        self,
        name: Annotated[Optional[str], Field(
            description="Filter by query name (substring or exact match)"
        )] = None,
        tags: Annotated[Optional[str], Field(
            description="Comma-separated list of tags to filter by"
        )] = None,
        shared: Annotated[Optional[bool], Field(
            description="If true, return only shared queries; if false, only private ones"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List v2 saved queries with optional filters.
        GET /suggestions/v2/{account_id}/queries"""
        params: dict = {}
        if name is not None:
            params["name"] = name
        if tags is not None:
            params["tags"] = tags
        if shared is not None:
            params["shared"] = str(shared).lower()
        return self._get(
            "/suggestions/v2/{account_id}/queries",
            account_id=account_id,
            params=params or None,
        )

    def suggestions_v2_get(
        self,
        query_id: Annotated[str, Field(description="Saved query ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get v2 saved query. GET /suggestions/v2/{account_id}/queries/{query_id}"""
        return self._get(
            f"/suggestions/v2/{{account_id}}/queries/{query_id}",
            account_id=account_id,
        )

    def suggestions_v2_create(
        self,
        name: Annotated[str, Field(description="Display name for the saved query")],
        query_string: Annotated[str, Field(description="The log search query string to save (SQL/EMS query text)")],
        description: Annotated[Optional[str], Field(
            description="Human-readable description of what this query does"
        )] = None,
        tags: Annotated[Optional[List[str]], Field(
            description="List of tag strings to categorise the query"
        )] = None,
        shared: Annotated[Optional[bool], Field(
            description="Whether this query is shared with other account users (default false)"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create v2 saved query. POST /suggestions/v2/{account_id}/queries"""
        body: dict = {"name": name, "search_request": query_string}
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        if shared is not None:
            body["shared"] = shared
        return self._post(
            "/suggestions/v2/{account_id}/queries",
            account_id=account_id,
            json_body=body,
        )

    def suggestions_v2_update(
        self,
        query_id: Annotated[str, Field(description="Saved query ID to update")],
        name: Annotated[Optional[str], Field(description="New display name")] = None,
        query_string: Annotated[Optional[str], Field(description="New query string (SQL/EMS text)")] = None,
        description: Annotated[Optional[str], Field(description="New description")] = None,
        tags: Annotated[Optional[List[str]], Field(description="Replacement tag list")] = None,
        shared: Annotated[Optional[bool], Field(description="Update sharing flag")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update v2 saved query.
        The v2 API uses POST to the resource URL for updates (not PUT).
        POST /suggestions/v2/{account_id}/queries/{query_id}
        """
        body: dict = {}
        if name is not None:
            body["name"] = name
        if query_string is not None:
            body["search_request"] = query_string
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        if shared is not None:
            body["shared"] = shared
        return self._post(
            f"/suggestions/v2/{{account_id}}/queries/{query_id}",
            account_id=account_id,
            json_body=body,
        )

    def suggestions_v2_delete(
        self,
        query_id: Annotated[str, Field(description="Saved query ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete v2 saved query using the required two-step soft-then-hard delete.

        The API requires that a query is first soft-deleted (POST {deleted:true})
        before the hard DELETE can succeed. This method performs both steps atomically.

        POST   /suggestions/v2/{account_id}/queries/{query_id}  (soft-delete: deleted=true)
        DELETE /suggestions/v2/{account_id}/queries/{query_id}  (hard-delete)
        """
        # Step 1: soft-delete — mark deleted=true via POST to the resource URL
        soft = self._post(
            f"/suggestions/v2/{{account_id}}/queries/{query_id}",
            account_id=account_id,
            json_body={"deleted": True},
        )
        if "error" in soft:
            return {
                "error": "soft-delete step failed",
                "details": soft,
            }
        # Step 2: hard-delete
        return self._delete(
            f"/suggestions/v2/{{account_id}}/queries/{query_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = SuggestionsModule()
    mod.register_tools(server)
