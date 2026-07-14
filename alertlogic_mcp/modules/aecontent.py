"""
AlertLogic AEContent & Aether.
Analytics/detection content management (AEContent v1) and exposure search (Aether v1).

Services:
  - aecontent.v1 — host: aecontent.mdr.global.alertlogic.com
      Global:  GET  /aecontent/v1/analytics
               GET  /aecontent/v1/analytics/{path}
               GET  /aecontent/v1/analytics/{path}/observations
               GET  /aecontent/v1/observations
               GET  /aecontent/v1/content_types
               GET  /aecontent/v1/tags
      Account: GET    /aecontent/v1/{account_id}/analytics
               GET    /aecontent/v1/{account_id}/analytics/{path}
               POST   /aecontent/v1/{account_id}/analytics/{path}
               DELETE /aecontent/v1/{account_id}/analytics/{path}

  - aether.v1   — host: api.cloudinsight.alertlogic.com (default)
      Account: GET /aether/v1/{account_id}/exposures/search

    Note: The aether service is not published in the alertlogic-sdk-definitions repo and
    has no publicly documented endpoints beyond /exposures/search. The dispose/conclude
    lifecycle actions for exposures are managed through the remediations service, not
    aether. The /exposures/search endpoint is the canonical aether API surface.

Note: AEContent is distinct from AETuner (seceng.py).
  AETuner tunes thresholds/severity on existing analytics;
  AEContent manages the content definitions themselves.
"""
import os
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


AecontentType = Literal[
    "logsmsgs", "observations", "telemetry", "correlation", "detection",
]
ExposureSeverity = Literal["info", "low", "medium", "high", "critical"]
ExposureGroupBy = Literal["remediation_id", "vulnerability_id", "asset_type", "deployment_id", "severity"]


class AecontentModule(BaseModule):
    """AEContent analytics content management + Aether exposure search."""

    def __init__(self):
        super().__init__()
        self.service_hosts["aecontent"] = os.environ.get(
            "ALERTLOGIC_AECONTENT_BASE_URL",
            "https://aecontent.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        # ---- Global analytics content ----
        self._add_tool(server, self.aecontent_list_analytics, "aecontent_list_analytics",
                       "List all global analytics content definitions")
        self._add_tool(server, self.aecontent_get_analytic, "aecontent_get_analytic",
                       "Get a specific global analytic content definition by path")
        self._add_tool(server, self.aecontent_get_analytic_observations,
                       "aecontent_get_analytic_observations",
                       "List observation definitions produced by a specific analytic")
        self._add_tool(server, self.aecontent_list_observations, "aecontent_list_observations",
                       "List all global observation content definitions")
        # ---- Content metadata ----
        self._add_tool(server, self.aecontent_list_content_types, "aecontent_list_content_types",
                       "List available AEContent content types")
        self._add_tool(server, self.aecontent_list_tags, "aecontent_list_tags",
                       "List available AEContent tags and categories")
        # ---- Account-scoped analytics ----
        self._add_tool(server, self.aecontent_list_account_analytics,
                       "aecontent_list_account_analytics",
                       "List analytics content definitions for a specific account")
        self._add_tool(server, self.aecontent_get_account_analytic,
                       "aecontent_get_account_analytic",
                       "Get an account-specific analytic content definition by path")
        self._add_tool(server, self.aecontent_create_account_analytic,
                       "aecontent_create_account_analytic",
                       "Create or update an account-level analytic content override")
        self._add_tool(server, self.aecontent_delete_account_analytic,
                       "aecontent_delete_account_analytic",
                       "Delete an account-level analytic content override")
        # ---- Aether exposure search ----
        self._add_tool(server, self.aether_search_exposures, "aether_search_exposures",
                       "Search exposures for an account via the Aether v1 API")

    # ------------------------------------------------------------------ #
    #  Global analytics content                                           #
    # ------------------------------------------------------------------ #

    def aecontent_list_analytics(
        self,
        page: Annotated[Optional[int], Field(
            description="Page number (1-based) for paginated results"
        )] = None,
        size: Annotated[Optional[int], Field(
            description="Page size — number of records per page"
        )] = None,
        content_type: Annotated[Optional[AecontentType], Field(
            description="Filter by content type: logsmsgs / observations / telemetry / correlation / detection"
        )] = None,
        enabled: Annotated[Optional[bool], Field(
            description="Filter by enabled flag — True returns only enabled analytics"
        )] = None,
    ) -> dict:
        """List all global analytics content definitions.
        GET /aecontent/v1/analytics on aecontent host.
        """
        params = {}
        if page is not None:
            params["page"] = page
        if size is not None:
            params["size"] = size
        if content_type:
            params["type"] = content_type
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        return self._get_at(
            "aecontent",
            "/aecontent/v1/analytics",
            params=params or None,
        )

    def aecontent_get_analytic(
        self,
        path: Annotated[str, Field(
            description=(
                "Analytic path identifier, e.g. 'logsmsgs/SomeRule' or "
                "'observations/SomeObservation'. Slashes are URL-encoded automatically."
            )
        )],
    ) -> dict:
        """Get a specific global analytic content definition.
        GET /aecontent/v1/analytics/{path} on aecontent host.
        """
        return self._get_at(
            "aecontent",
            f"/aecontent/v1/analytics/{url_quote(path)}",
        )

    def aecontent_get_analytic_observations(
        self,
        path: Annotated[str, Field(
            description="Analytic path identifier. Slashes are URL-encoded automatically."
        )],
        page: Annotated[Optional[int], Field(description="Page number (1-based)")] = None,
        size: Annotated[Optional[int], Field(description="Page size")] = None,
    ) -> dict:
        """List observation definitions produced by a specific analytic.
        GET /aecontent/v1/analytics/{path}/observations on aecontent host.
        """
        params = {}
        if page is not None:
            params["page"] = page
        if size is not None:
            params["size"] = size
        return self._get_at(
            "aecontent",
            f"/aecontent/v1/analytics/{url_quote(path)}/observations",
            params=params or None,
        )

    def aecontent_list_observations(
        self,
        page: Annotated[Optional[int], Field(description="Page number (1-based)")] = None,
        size: Annotated[Optional[int], Field(description="Page size")] = None,
        content_type: Annotated[Optional[AecontentType], Field(
            description="Filter by content type"
        )] = None,
        enabled: Annotated[Optional[bool], Field(
            description="Filter by enabled flag"
        )] = None,
    ) -> dict:
        """List all global observation content definitions.
        GET /aecontent/v1/observations on aecontent host.
        """
        params = {}
        if page is not None:
            params["page"] = page
        if size is not None:
            params["size"] = size
        if content_type:
            params["type"] = content_type
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        return self._get_at(
            "aecontent",
            "/aecontent/v1/observations",
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  Content metadata                                                    #
    # ------------------------------------------------------------------ #

    def aecontent_list_content_types(self) -> dict:
        """List available AEContent content types.
        GET /aecontent/v1/content_types on aecontent host.
        """
        return self._get_at("aecontent", "/aecontent/v1/content_types")

    def aecontent_list_tags(
        self,
        content_type: Annotated[Optional[AecontentType], Field(
            description="Optional content type to narrow the tag list"
        )] = None,
    ) -> dict:
        """List available AEContent tags and categories.
        GET /aecontent/v1/tags on aecontent host.
        """
        params = {}
        if content_type:
            params["type"] = content_type
        return self._get_at(
            "aecontent",
            "/aecontent/v1/tags",
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  Account-scoped analytics                                           #
    # ------------------------------------------------------------------ #

    def aecontent_list_account_analytics(
        self,
        page: Annotated[Optional[int], Field(description="Page number (1-based)")] = None,
        size: Annotated[Optional[int], Field(description="Page size")] = None,
        content_type: Annotated[Optional[AecontentType], Field(
            description="Filter by content type"
        )] = None,
        enabled: Annotated[Optional[bool], Field(
            description="Filter by enabled flag"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List analytics content definitions for a specific account.
        GET /aecontent/v1/{account_id}/analytics on aecontent host.
        Includes both inherited global definitions and account-level overrides.
        """
        params = {}
        if page is not None:
            params["page"] = page
        if size is not None:
            params["size"] = size
        if content_type:
            params["type"] = content_type
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        return self._get_at(
            "aecontent",
            "/aecontent/v1/{account_id}/analytics",
            account_id=account_id,
            params=params or None,
        )

    def aecontent_get_account_analytic(
        self,
        path: Annotated[str, Field(
            description="Analytic path identifier. Slashes are URL-encoded automatically."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get an account-specific analytic content definition.
        GET /aecontent/v1/{account_id}/analytics/{path} on aecontent host.
        Returns the account override if present, otherwise falls back to global.
        """
        return self._get_at(
            "aecontent",
            f"/aecontent/v1/{{account_id}}/analytics/{url_quote(path)}",
            account_id=account_id,
        )

    def aecontent_create_account_analytic(
        self,
        path: Annotated[str, Field(
            description="Analytic path identifier for the override. Slashes URL-encoded automatically."
        )],
        body: Annotated[dict, Field(
            description=(
                "Analytics content definition object. Typical fields: "
                "{'enabled': bool, 'severity': str, 'visibility': str, "
                "'tuning': [...], 'tags': [...]}. "
                "Omitted fields inherit from the global definition."
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create or update an account-level analytic content override.
        POST /aecontent/v1/{account_id}/analytics/{path} on aecontent host.
        """
        return self._post_at(
            "aecontent",
            f"/aecontent/v1/{{account_id}}/analytics/{url_quote(path)}",
            account_id=account_id,
            json_body=body,
        )

    def aecontent_delete_account_analytic(
        self,
        path: Annotated[str, Field(
            description="Analytic path identifier of the override to remove. Slashes URL-encoded automatically."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete an account-level analytic content override.
        DELETE /aecontent/v1/{account_id}/analytics/{path} on aecontent host.
        After deletion the account inherits the global definition.
        """
        return self._delete_at(
            "aecontent",
            f"/aecontent/v1/{{account_id}}/analytics/{url_quote(path)}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Aether exposure search (default host)                              #
    # ------------------------------------------------------------------ #

    def aether_search_exposures(
        self,
        query: Annotated[Optional[str], Field(
            description=(
                "Free-text or structured search query for exposures. "
                "Supports field:value syntax, e.g. 'cve:CVE-2021-44228' or "
                "'asset_type:host severity:high'."
            )
        )] = None,
        asset_types: Annotated[Optional[str], Field(
            description=(
                "Comma-separated asset types to restrict the search, "
                "e.g. 'host,application,container'."
            )
        )] = None,
        severity: Annotated[Optional[ExposureSeverity], Field(
            description="Filter by exposure severity: info / low / medium / high / critical"
        )] = None,
        deployment_id: Annotated[Optional[str], Field(
            description="Filter results to a specific deployment UUID"
        )] = None,
        group_by: Annotated[Optional[ExposureGroupBy], Field(
            description=(
                "Group results by a common attribute — useful for counting or aggregating. "
                "One of: remediation_id / vulnerability_id / asset_type / deployment_id / severity. "
                "When set, each result group contains a count and representative exposure."
            )
        )] = None,
        return_count: Annotated[Optional[bool], Field(
            description=(
                "When True, return only the total count of matching exposures rather than "
                "the full result list. Useful for dashboards or quota checks."
            )
        )] = None,
        filter: Annotated[Optional[str], Field(
            description=(
                "Structured filter expression in the Alert Logic assets-query filter syntax, "
                "e.g. 'host.scope_agent_os_type=unix' or 'vulnerability.cvss_score>>7.0'. "
                "Use this for precise field comparisons; use `query` for free-text search."
            )
        )] = None,
        sort: Annotated[Optional[str], Field(
            description=(
                "Sort field and optional direction, e.g. 'severity' or 'severity:desc'. "
                "Common sort fields: severity, cvss_score, asset_count, vulnerability_id."
            )
        )] = None,
        details: Annotated[bool, Field(
            description="Return full exposure details (may increase response size significantly)"
        )] = False,
        page: Annotated[Optional[int], Field(description="Page number (1-based)")] = None,
        size: Annotated[Optional[int], Field(description="Page size")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Search exposures for an account via the Aether v1 API.
        GET /aether/v1/{account_id}/exposures/search on default host
        (api.cloudinsight.alertlogic.com).

        This is the only publicly documented aether endpoint. The aether service is not
        published in the alertlogic-sdk-definitions repo; dispose/conclude lifecycle
        actions are managed via the separate remediations service.
        """
        params: dict = {"details": str(details).lower()}
        if query:
            params["query"] = query
        if asset_types:
            params["asset_types"] = asset_types
        if severity:
            params["severity"] = severity
        if deployment_id:
            params["deployment_id"] = deployment_id
        if group_by:
            params["group_by"] = group_by
        if return_count is not None:
            params["return_count"] = str(return_count).lower()
        if filter:
            params["filter"] = filter
        if sort:
            params["sort"] = sort
        if page is not None:
            params["page"] = page
        if size is not None:
            params["size"] = size
        return self._get(
            "/aether/v1/{account_id}/exposures/search",
            account_id=account_id,
            params=params,
        )


def setup(server: FastMCP):
    mod = AecontentModule()
    mod.register_tools(server)
