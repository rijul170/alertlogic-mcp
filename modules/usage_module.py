"""
AlertLogic Usage & Billing Service.
Query usage statistics, per-metric consumption, billing summaries, and account limits.

Maps to: Usage API v1
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


# Supported time-series granularities for usage queries.
Granularity = Literal["hour", "day", "week", "month"]


class UsageModule(BaseModule):
    """Usage statistics and billing."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.usage_get, "usage_get",
                        "Get aggregated usage statistics for an account within a time window")
        self._add_tool(server, self.usage_get_metric, "usage_get_metric",
                        "Get usage data for a specific metric within a time window")
        self._add_tool(server, self.usage_get_billing, "usage_get_billing",
                        "Get the billing summary for an account")
        self._add_tool(server, self.usage_get_limits, "usage_get_limits",
                        "Get the current usage limits and entitlements for an account")

    # ---- Usage ----

    def usage_get(
        self,
        from_time: Annotated[Optional[str], Field(
            description=(
                "Start of the reporting window. Accepts ISO 8601 datetime "
                "(e.g. '2026-01-01T00:00:00Z') or Unix epoch seconds."
            )
        )] = None,
        to_time: Annotated[Optional[str], Field(
            description=(
                "End of the reporting window. Accepts ISO 8601 datetime "
                "(e.g. '2026-01-31T23:59:59Z') or Unix epoch seconds."
            )
        )] = None,
        granularity: Annotated[Optional[Granularity], Field(
            description="Time-series bucket size: hour, day, week, or month"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get usage statistics. GET /usage/v1/{account_id}/usage"""
        params: dict = {}
        if from_time is not None:
            params["from"] = from_time
        if to_time is not None:
            params["to"] = to_time
        if granularity is not None:
            params["granularity"] = granularity
        return self._get(
            "/usage/v1/{account_id}/usage",
            account_id=account_id,
            params=params or None,
        )

    def usage_get_metric(
        self,
        metric: Annotated[str, Field(
            description=(
                "Metric name to retrieve (e.g. 'log_bytes', 'protected_hosts', "
                "'network_bytes'). Use usage_get first to discover available metric names."
            )
        )],
        from_time: Annotated[Optional[str], Field(
            description=(
                "Start of the reporting window. Accepts ISO 8601 datetime "
                "or Unix epoch seconds."
            )
        )] = None,
        to_time: Annotated[Optional[str], Field(
            description=(
                "End of the reporting window. Accepts ISO 8601 datetime "
                "or Unix epoch seconds."
            )
        )] = None,
        granularity: Annotated[Optional[Granularity], Field(
            description="Time-series bucket size: hour, day, week, or month"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a specific metric. GET /usage/v1/{account_id}/usage/{metric}"""
        params: dict = {}
        if from_time is not None:
            params["from"] = from_time
        if to_time is not None:
            params["to"] = to_time
        if granularity is not None:
            params["granularity"] = granularity
        return self._get(
            f"/usage/v1/{{account_id}}/usage/{metric}",
            account_id=account_id,
            params=params or None,
        )

    # ---- Billing ----

    def usage_get_billing(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get billing summary. GET /usage/v1/{account_id}/billing"""
        return self._get(
            "/usage/v1/{account_id}/billing",
            account_id=account_id,
        )

    # ---- Limits ----

    def usage_get_limits(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get account limits. GET /usage/v1/{account_id}/limits"""
        return self._get(
            "/usage/v1/{account_id}/limits",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = UsageModule()
    mod.register_tools(server)
