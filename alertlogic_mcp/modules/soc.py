"""
AlertLogic SOC Tools.
Threat hunting, log search, exposure lookup.

Maps to: search v2, assets_query v2, remediations v1
"""
from typing import Annotated, Optional, List
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class SOCModule(BaseModule):
    """SOC-focused operations (search + exposure + collection-health)."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.search_submit, "search_submit",
                        "Submit an AL-SQL search to the Search v2 service")
        self._add_tool(server, self.search_status, "search_status",
                        "Check status of an asynchronous search")
        self._add_tool(server, self.search_results, "search_results",
                        "Fetch results of a completed search")
        self._add_tool(server, self.search_release, "search_release",
                        "Cancel/release a running or completed search")
        self._add_tool(server, self.search_validate, "search_validate",
                        "Validate AL-SQL syntax without running a search job")
        self._add_tool(server, self.search_rerun, "search_rerun",
                        "Re-run a previous search by UUID (creates a new search from existing parameters)")
        self._add_tool(server, self.search_complete, "search_complete",
                        "Force-complete a suspended search that is taking too long")
        self._add_tool(server, self.search_get_grammar, "search_get_grammar",
                        "Fetch the complete AL-SQL grammar reference with all supported functions and syntax")
        self._add_tool(server, self.search_get_peg, "search_get_peg",
                        "Retrieve the PEG grammar definition for AL-SQL (for building query parsers/validators)")
        self._add_tool(server, self.search_convert_from_v1, "search_convert_from_v1",
                        "Convert a v1 search query to v2 expert mode syntax")
        self._add_tool(server, self.search_get_messages, "search_get_messages",
                        "Retrieve raw messages by ID using the v1 messages API (POST)")
        self._add_tool(server, self.search_get_messages_by_id, "search_get_messages_by_id",
                        "Retrieve raw messages by ID using the v1 messages API (GET)")
        self._add_tool(server, self.get_exposures, "get_exposures",
                        "Get exposures, optionally filtered by deployment")
        self._add_tool(server, self.get_health_summary, "get_health_summary",
                        "Get account-wide collection health summary")

    # ---- Search v2 ----
    # Per the search.v2 spec: search_type, start, end go in QUERY params,
    # and the body is a raw AL-SQL string sent as text/plain.

    def search_submit(
        self,
        sql: Annotated[str, Field(description="AL-SQL query string")],
        start_time: Annotated[Optional[str], Field(
            description="Start time (ISO 8601 or epoch). Required unless using a relative timeframe."
        )] = None,
        end_time: Annotated[Optional[str], Field(
            description="End time (ISO 8601 or epoch)"
        )] = None,
        search_type: Annotated[str, Field(
            description="'batch' (default), 'report', or 'interactive'"
        )] = "batch",
        timeframe: Annotated[Optional[int], Field(
            description="Relative timeframe in seconds (alternative to start/end)"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Submit search. POST /search/v2/{account_id}/searches (text/plain body)."""
        params = {"search_type": search_type}
        if start_time:
            params["start"] = start_time
        if end_time:
            params["end"] = end_time
        if timeframe is not None:
            params["timeframe"] = str(timeframe)
        return self._request(
            "POST",
            "/search/v2/{account_id}/searches",
            account_id=account_id,
            params=params,
            data=sql,
            content_type="text/plain",
        )

    def search_status(
        self,
        search_uuid: Annotated[str, Field(description="Search UUID returned by search_submit")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Search status. GET /search/v2/{account_id}/searches/{search_uuid}/status"""
        return self._get(
            f"/search/v2/{{account_id}}/searches/{search_uuid}/status",
            account_id=account_id,
        )

    def search_results(
        self,
        search_uuid: Annotated[str, Field(description="Search UUID")],
        offset: Annotated[int, Field(description="Result offset for pagination")] = 0,
        limit: Annotated[int, Field(description="Max rows to return")] = 100,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Search results. GET /search/v2/{account_id}/searches/{search_uuid}"""
        return self._get(
            f"/search/v2/{{account_id}}/searches/{search_uuid}",
            account_id=account_id,
            params={"offset": offset, "limit": limit},
        )

    def search_release(
        self,
        search_uuid: Annotated[str, Field(description="Search UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Cancel/release a search. DELETE /search/v2/{account_id}/searches/{search_uuid}"""
        return self._delete(
            f"/search/v2/{{account_id}}/searches/{search_uuid}",
            account_id=account_id,
        )

    def search_validate(
        self,
        sql_query: Annotated[Optional[str], Field(
            description="AL-SQL query string to validate (e.g. 'SELECT * FROM logmsgs WHERE ...')"
        )] = None,
        expert: Annotated[Optional[str], Field(
            description="Raw expert query to validate (alternative to sql_query)"
        )] = None,
    ) -> dict:
        """Validate AL-SQL syntax without running a search job. POST /search/v2/validate"""
        body = {}
        if sql_query:
            body["sql_query"] = sql_query
        if expert:
            body["expert"] = expert
        return self._request("POST", "/search/v2/validate", json_body=body)

    def search_rerun(
        self,
        search_uuid: Annotated[str, Field(description="UUID of the existing search to re-run")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Re-run a previous search. POST /search/v2/{account_id}/searches/{uuid}/rerun"""
        return self._request(
            "POST",
            f"/search/v2/{{account_id}}/searches/{search_uuid}/rerun",
            account_id=account_id,
        )

    def search_complete(
        self,
        search_uuid: Annotated[str, Field(description="UUID of the suspended search to force-complete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Force-complete a suspended search. POST /search/v2/{account_id}/searches/{uuid}/complete"""
        return self._request(
            "POST",
            f"/search/v2/{{account_id}}/searches/{search_uuid}/complete",
            account_id=account_id,
        )

    def search_get_grammar(self) -> dict:
        """Fetch the complete AL-SQL grammar reference. GET /search/v2/grammar"""
        return self._request("GET", "/search/v2/grammar")

    def search_get_peg(self) -> dict:
        """Retrieve the PEG grammar definition for AL-SQL. GET /search/v2/peg"""
        return self._request("GET", "/search/v2/peg")

    def search_convert_from_v1(
        self,
        query: Annotated[str, Field(description="v1 search query to convert to v2 expert mode syntax")],
    ) -> dict:
        """Convert a v1 search query to v2 expert mode syntax. POST /search/v2/convert-from-v1"""
        return self._request("POST", "/search/v2/convert-from-v1", json_body={"query": query})

    def search_get_messages(
        self,
        datatype: Annotated[str, Field(
            description="Message datatype, e.g. 'logmsgs' or 'auditmsgs'"
        )],
        ids: Annotated[List[str], Field(description="List of message IDs to retrieve")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Retrieve raw messages by ID (POST). POST /search/v1/{account_id}/messages/{datatype}"""
        return self._request(
            "POST",
            f"/search/v1/{{account_id}}/messages/{datatype}",
            account_id=account_id,
            json_body={"ids": ids},
        )

    def search_get_messages_by_id(
        self,
        datatype: Annotated[str, Field(
            description="Message datatype, e.g. 'logmsgs' or 'auditmsgs'"
        )],
        ids: Annotated[str, Field(description="Comma-separated message IDs to retrieve")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Retrieve raw messages by ID (GET). GET /search/v1/{account_id}/messages/{datatype}"""
        return self._get(
            f"/search/v1/{{account_id}}/messages/{datatype}",
            account_id=account_id,
            params={"ids": ids},
        )

    # ---- Exposures + health ----

    def get_exposures(
        self,
        deployment_id: Annotated[Optional[str], Field(description="Deployment UUID filter")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List exposures. GET /assets_query/v2/{account_id}/exposures"""
        params = {}
        if deployment_id:
            params["filter"] = [f"deployment_id:{deployment_id}"]
        return self._get(
            "/assets_query/v2/{account_id}/exposures",
            account_id=account_id,
            params=params or None,
        )

    def get_health_summary(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Collection-health summary. GET /remediations/v1/{account_id}/health/summary"""
        return self._get(
            "/remediations/v1/{account_id}/health/summary",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = SOCModule()
    mod.register_tools(server)
