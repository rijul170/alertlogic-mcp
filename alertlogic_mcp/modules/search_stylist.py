"""
AlertLogic Search Stylist — Search Result Formatter.
Transforms and exports Alert Logic search results in different formats
(JSON, CSV), with support for pagination, column selection, and date
formatting. Useful for exporting log search results for reporting.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/search_stylist/search_stylist.v1.yaml
Host: api.global-services.global.alertlogic.com
"""
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


SearchResultFormat = Literal["json", "csv"]


class SearchStylistModule(BaseModule):
    """
    Search Stylist — formats and exports Alert Logic search results.

    Two operations:
      - get (paginated): retrieve a page of transformed search results
      - export (bulk):   retrieve the complete result set in one call

    Both support JSON and CSV output formats, UTC offset adjustment for
    timestamps, and optional row selection.
    """

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server,
            self.search_stylist_get_results,
            "search_stylist_get_results",
            (
                "Get transformed/formatted search results for a completed search. "
                "Supports JSON and CSV formats, pagination, and timestamp UTC offset."
            ),
        )
        self._add_tool(
            server,
            self.search_stylist_export_results,
            "search_stylist_export_results",
            (
                "Export the complete transformed search results for a completed search "
                "in JSON or CSV format (no pagination — returns full result set)."
            ),
        )

    # ------------------------------------------------------------------ #
    #  GET /search_stylist/v1/{account_id}/searches/{search_uuid}/transform/{result_format}
    # ------------------------------------------------------------------ #

    def search_stylist_get_results(
        self,
        search_uuid: Annotated[str, Field(
            description="UUID of the completed search to retrieve results for"
        )],
        result_format: Annotated[SearchResultFormat, Field(
            description="Output format: 'json' or 'csv'"
        )],
        limit: Annotated[Optional[int], Field(
            description="Maximum number of rows to return (0–100000)"
        )] = None,
        offset: Annotated[Optional[int], Field(
            description="Row offset for pagination"
        )] = None,
        starting_token: Annotated[Optional[str], Field(
            description="Pagination token from a previous response to continue from"
        )] = None,
        details: Annotated[Optional[bool], Field(
            description="Include debugging information in the response"
        )] = None,
        selected: Annotated[Optional[List[int]], Field(
            description="Specific row numbers to return (e.g. [0, 1, 5])"
        )] = None,
        utc_offset: Annotated[Optional[str], Field(
            description=(
                "UTC offset for DateTime field transformation, "
                "in ±HH:MM format (e.g. '+05:30', '-08:00')"
            )
        )] = None,
        date_format: Annotated[Optional[Literal["excel"]], Field(
            description="Alternate date format — 'excel' adjusts date formatting for Excel compatibility"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get paginated transformed search results in the requested format.
        GET /search_stylist/v1/{account_id}/searches/{search_uuid}/transform/{result_format}
        on global-services host.
        """
        params: dict = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if starting_token:
            params["starting_token"] = starting_token
        if details is not None:
            params["details"] = str(details).lower()
        if selected:
            params["selected"] = selected
        if utc_offset:
            params["utc_offset"] = utc_offset
        if date_format:
            params["date_format"] = date_format

        return self._get_global(
            f"/search_stylist/v1/{{account_id}}/searches/{search_uuid}/transform/{result_format}",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  GET /search_stylist/v1/{account_id}/searches/{search_uuid}/export/{result_format}
    # ------------------------------------------------------------------ #

    def search_stylist_export_results(
        self,
        search_uuid: Annotated[str, Field(
            description="UUID of the completed search to export"
        )],
        result_format: Annotated[SearchResultFormat, Field(
            description="Export format: 'json' or 'csv'"
        )],
        limit: Annotated[Optional[int], Field(
            description="Maximum number of rows to export (0–100000)"
        )] = None,
        offset: Annotated[Optional[int], Field(
            description="Starting row offset for the export"
        )] = None,
        utc_offset: Annotated[Optional[str], Field(
            description=(
                "UTC offset for DateTime fields in ±HH:MM format "
                "(e.g. '+00:00' for UTC, '-05:00' for EST)"
            )
        )] = None,
        date_format: Annotated[Optional[Literal["excel"]], Field(
            description="'excel' adjusts date formatting for Excel compatibility"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Export the complete transformed search results (bulk, no pagination tokens).
        GET /search_stylist/v1/{account_id}/searches/{search_uuid}/export/{result_format}
        on global-services host.

        Use this for downloading full result sets. For interactive pagination,
        use search_stylist_get_results instead.
        """
        params: dict = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if utc_offset:
            params["utc_offset"] = utc_offset
        if date_format:
            params["date_format"] = date_format

        return self._get_global(
            f"/search_stylist/v1/{{account_id}}/searches/{search_uuid}/export/{result_format}",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = SearchStylistModule()
    mod.register_tools(server)
