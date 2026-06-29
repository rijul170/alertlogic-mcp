"""
AlertLogic Ingest and Inquisitor Services.

Ingest Service  — submit data to the ingest pipeline; list/get configured sources.
Inquisitor Service — submit, retrieve, and cancel log search queries.

Service hosts:
  ingest      https://ingest.mdr.global.alertlogic.com
  inquisitor  https://api.cloudinsight.alertlogic.com  (default base URL)
"""
import os
from typing import Annotated, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class IngestModule(BaseModule):
    """Ingest pipeline data submission and source management, plus Inquisitor log search."""

    def __init__(self):
        super().__init__()
        self.service_hosts["ingest"] = os.environ.get(
            "ALERTLOGIC_INGEST_BASE_URL",
            "https://ingest.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        # Ingest service
        self._add_tool(server, self.ingest_submit_data, "ingest_submit_data",
                       "Submit raw data to the Alert Logic ingest pipeline")
        self._add_tool(server, self.ingest_list_sources, "ingest_list_sources",
                       "List all configured ingest sources for an account")
        self._add_tool(server, self.ingest_get_source, "ingest_get_source",
                       "Get a single ingest source by ID")
        # Inquisitor service
        self._add_tool(server, self.inquisitor_submit_search, "inquisitor_submit_search",
                       "Submit a log search query to the Inquisitor service")
        self._add_tool(server, self.inquisitor_get_search, "inquisitor_get_search",
                       "Get the status and results of a previously submitted log search")
        self._add_tool(server, self.inquisitor_delete_search, "inquisitor_delete_search",
                       "Cancel and delete a log search by ID")

    # ------------------------------------------------------------------ #
    #  Ingest service                                                      #
    # ------------------------------------------------------------------ #

    def ingest_submit_data(
        self,
        data_type: Annotated[str, Field(
            description=(
                "Ingest data type. Determines how the pipeline parses and routes the payload. "
                "Common values: 'logmsgs' (syslog/plain-log lines), 'auditmsgs' (audit events), "
                "'IDS_log' (IDS event records). Consult Alert Logic documentation for the full list."
            )
        )],
        data: Annotated[str, Field(
            description="Raw payload to submit. Encoding and structure must match data_type."
        )],
        content_type: Annotated[str, Field(
            description=(
                "MIME content type of the payload sent to the API. "
                "Defaults to 'application/octet-stream' for binary/opaque data. "
                "Use 'text/plain' for plain-text log lines."
            )
        )] = "application/octet-stream",
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Submit raw data to the ingest pipeline.
        POST /ingest/v1/{account_id}/data/{data_type}
        """
        return self._request(
            "POST",
            f"/ingest/v1/{{account_id}}/data/{data_type}",
            account_id=account_id,
            data=data,
            base_url=self.service_hosts["ingest"],
            content_type=content_type,
        )

    def ingest_list_sources(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List all configured ingest sources for an account.
        GET /ingest/v1/{account_id}/sources
        """
        return self._get_at(
            "ingest",
            "/ingest/v1/{account_id}/sources",
            account_id=account_id,
        )

    def ingest_get_source(
        self,
        source_id: Annotated[str, Field(description="Ingest source ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a single ingest source by ID.
        GET /ingest/v1/{account_id}/sources/{source_id}
        """
        return self._get_at(
            "ingest",
            f"/ingest/v1/{{account_id}}/sources/{source_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Inquisitor service (log search/retrieval)                          #
    #  Uses the default base URL (https://api.cloudinsight.alertlogic.com)#
    # ------------------------------------------------------------------ #

    def inquisitor_submit_search(
        self,
        query: Annotated[str, Field(
            description=(
                "Search query string in Alert Logic query language (AL-SQL or equivalent). "
                "Example: \"SELECT * FROM logmsgs WHERE message CONTAINS 'failed password'\""
            )
        )],
        timeframe: Annotated[dict, Field(
            description=(
                "Time window for the search. Supported shapes: "
                "{\"type\": \"relative\", \"seconds\": 3600} for the last N seconds, or "
                "{\"type\": \"absolute\", \"start\": \"<ISO8601>\", \"end\": \"<ISO8601>\"} "
                "for an explicit window."
            )
        )],
        return_fields: Annotated[Optional[List[str]], Field(
            description=(
                "Optional list of field names to include in each result row. "
                "Omit to return all available fields. "
                "Example: [\"time_recv\", \"message\", \"srcip\"]"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Submit a log search to the Inquisitor service and receive a search_id for polling.
        POST /inquisitor/v1/{account_id}/searches
        """
        body: dict = {"query": query, "timeframe": timeframe}
        if return_fields is not None:
            body["return_fields"] = return_fields
        return self._post(
            "/inquisitor/v1/{account_id}/searches",
            account_id=account_id,
            json_body=body,
        )

    def inquisitor_get_search(
        self,
        search_id: Annotated[str, Field(
            description=(
                "Search ID returned by inquisitor_submit_search. "
                "Poll this endpoint until status is 'complete' or 'failed'."
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get the status and results of a log search.
        GET /inquisitor/v1/{account_id}/searches/{search_id}
        """
        return self._get(
            f"/inquisitor/v1/{{account_id}}/searches/{search_id}",
            account_id=account_id,
        )

    def inquisitor_delete_search(
        self,
        search_id: Annotated[str, Field(
            description="Search ID to cancel and delete. Returns 204 No Content on success."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Cancel and delete a log search.
        DELETE /inquisitor/v1/{account_id}/searches/{search_id}
        """
        return self._delete(
            f"/inquisitor/v1/{{account_id}}/searches/{search_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = IngestModule()
    mod.register_tools(server)
