"""
AlertLogic Security Engineering & Compliance.
Cargo v2 (scheduled reports) and AETuner v1/v2 (analytics tuning).

Specs:
  - cargo.v2.yaml  — host: api.cloudinsight.alertlogic.com (default)
  - aetuner.v1.yaml — host: aetuner.mdr.global.alertlogic.com
  - aetuner.v2.yaml — host: aetuner.mdr.global.alertlogic.com (analytics2 endpoints)
"""
from typing import Annotated, Dict, List, Literal, Optional, Union
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


CargoScheduleType = Literal["tableau", "search", "search_v2"]
CargoStatus = Literal["scheduled", "running", "cancelled", "failed", "completed"]
AetunerDataType = Literal["logsmsgs", "observations", "telemetry"]
AetunerOutput = Literal["all", "correlations", "analytics"]
AetunerTuningType = Literal[
    "severity", "visibility", "threshold", "handling", "whitelist", "blacklist"
]
AetunerTuningOp = Literal["add", "subtract", "write", "delete"]


class SecEngModule(BaseModule):
    """Cargo report scheduling + AETuner analytics tuning (v1 and v2)."""

    def register_tools(self, server: FastMCP):
        # ---- Cargo v2 ----
        self._add_tool(server, self.cargo_list_schedules, "cargo_list_schedules",
                        "List Cargo report schedules")
        self._add_tool(server, self.cargo_list_executions, "cargo_list_executions",
                        "List Cargo execution records (report runs)")
        self._add_tool(server, self.cargo_rerun_execution, "cargo_rerun_execution",
                        "Rerun a single execution record")
        self._add_tool(server, self.cargo_rerun_executions, "cargo_rerun_executions",
                        "Rerun multiple execution records (comma-separated IDs)")
        self._add_tool(server, self.cargo_get_schedule, "cargo_get_schedule",
                        "Get a single Cargo scheduled report by ID")
        self._add_tool(server, self.cargo_create_schedule, "cargo_create_schedule",
                        "Create a new Cargo scheduled report")
        self._add_tool(server, self.cargo_update_schedule, "cargo_update_schedule",
                        "Update an existing Cargo scheduled report")
        self._add_tool(server, self.cargo_delete_schedule, "cargo_delete_schedule",
                        "Delete a Cargo scheduled report")
        self._add_tool(server, self.cargo_get_execution, "cargo_get_execution",
                        "Get a single Cargo execution record by ID")
        self._add_tool(server, self.cargo_trigger_instant_report, "cargo_trigger_instant_report",
                        "Trigger an immediate (instant) execution of a scheduled report")
        # ---- AETuner v1 ----
        self._add_tool(server, self.aetuner_list_analytics, "aetuner_list_analytics",
                        "List analytics names (logmsgs/observations/telemetry)")
        self._add_tool(server, self.aetuner_get_analytic, "aetuner_get_analytic",
                        "Get a single analytic by its name")
        self._add_tool(server, self.aetuner_set_tuning, "aetuner_set_tuning",
                        "Apply tuning entries to an analytic (severity/visibility/threshold/etc.)")
        self._add_tool(server, self.aetuner_reset_analytic, "aetuner_reset_analytic",
                        "Reset a single v1 analytic to its default tuning")
        self._add_tool(server, self.aetuner_reset_all_visibility, "aetuner_reset_all_visibility",
                        "Reset visibility tuning for all v1 analytics")
        self._add_tool(server, self.aetuner_reset_all_severity, "aetuner_reset_all_severity",
                        "Reset severity tuning for all v1 analytics")
        self._add_tool(server, self.aetuner_reset_all_handling, "aetuner_reset_all_handling",
                        "Reset handling tuning for all v1 analytics")
        # ---- AETuner v2 (analytics2) ----
        self._add_tool(server, self.aetuner_list_analytics_v2, "aetuner_list_analytics_v2",
                        "List v2 analytics (analytics2 endpoint)")
        self._add_tool(server, self.aetuner_get_analytic_v2, "aetuner_get_analytic_v2",
                        "Get a single v2 analytic by path")
        self._add_tool(server, self.aetuner_update_analytic_v2, "aetuner_update_analytic_v2",
                        "Update visibility/severity/handling/tuning for a v2 analytic")
        self._add_tool(server, self.aetuner_list_tagsets, "aetuner_list_tagsets",
                        "List tagsets for an account")
        self._add_tool(server, self.aetuner_update_tagsets, "aetuner_update_tagsets",
                        "Create or replace tagsets for an account")
        self._add_tool(server, self.aetuner_reset_all_visibility_v2, "aetuner_reset_all_visibility_v2",
                        "Reset visibility tuning for all v2 analytics")
        self._add_tool(server, self.aetuner_reset_all_severity_v2, "aetuner_reset_all_severity_v2",
                        "Reset severity tuning for all v2 analytics")
        self._add_tool(server, self.aetuner_reset_all_handling_v2, "aetuner_reset_all_handling_v2",
                        "Reset handling tuning for all v2 analytics")

    # ---- Cargo v2 (default host) ----

    def cargo_list_schedules(
        self,
        schedule_type: Annotated[Optional[CargoScheduleType], Field(
            description="Filter: tableau / search / search_v2"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /cargo/v2/{account_id}/schedule"""
        params = {}
        if schedule_type:
            params["type"] = schedule_type
        return self._get(
            "/cargo/v2/{account_id}/schedule",
            account_id=account_id,
            params=params or None,
        )

    def cargo_list_executions(
        self,
        schedule_id: Annotated[Optional[str], Field(description="Filter by schedule ID")] = None,
        status: Annotated[Optional[CargoStatus], Field(description="Filter by status")] = None,
        latest_only: Annotated[bool, Field(description="Only the latest run per schedule")] = False,
        start_time: Annotated[Optional[int], Field(description="Epoch seconds — lower bound")] = None,
        end_time: Annotated[Optional[int], Field(description="Epoch seconds — upper bound")] = None,
        order: Annotated[Literal["asc", "desc"], Field(description="Sort order")] = "desc",
        limit: Annotated[int, Field(description="Max records (1..1000)")] = 100,
        continuation: Annotated[Optional[str], Field(description="Pagination token")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /cargo/v2/{account_id}/execution_record"""
        params = {"order": order, "limit": limit, "latest_only": str(latest_only).lower()}
        if schedule_id:
            params["schedule_id"] = schedule_id
        if status:
            params["status"] = status
        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        if continuation:
            params["continuation"] = continuation
        return self._get(
            "/cargo/v2/{account_id}/execution_record",
            account_id=account_id,
            params=params,
        )

    def cargo_rerun_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution record ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /cargo/v2/{account_id}/execution_record/{exec_id}/rerun"""
        return self._post(
            f"/cargo/v2/{{account_id}}/execution_record/{execution_id}/rerun",
            account_id=account_id,
        )

    def cargo_rerun_executions(
        self,
        execution_ids: Annotated[List[str], Field(description="Execution record IDs to rerun")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /cargo/v2/{account_id}/execution_record/rerun?ids=..."""
        return self._post(
            "/cargo/v2/{account_id}/execution_record/rerun",
            account_id=account_id,
            params={"ids": ",".join(execution_ids)},
        )

    def cargo_get_schedule(
        self,
        schedule_id: Annotated[str, Field(description="Scheduled report ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /cargo/v2/{account_id}/scheduled_report/{schedule_id}"""
        return self._get(
            f"/cargo/v2/{{account_id}}/scheduled_report/{schedule_id}",
            account_id=account_id,
        )

    def cargo_create_schedule(
        self,
        name: Annotated[str, Field(description="Human-readable name for the schedule")],
        type: Annotated[CargoScheduleType, Field(description="Report type: tableau / search / search_v2")],
        definition: Annotated[dict, Field(description="Report definition object (type-specific structure)")],
        active: Annotated[bool, Field(description="Whether the schedule is active")] = True,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /cargo/v2/{account_id}/scheduled_report"""
        body = {"name": name, "type": type, "definition": definition, "active": active}
        return self._post(
            "/cargo/v2/{account_id}/scheduled_report",
            account_id=account_id,
            json_body=body,
        )

    def cargo_update_schedule(
        self,
        schedule_id: Annotated[str, Field(description="Scheduled report ID to update")],
        name: Annotated[Optional[str], Field(description="New name for the schedule")] = None,
        type: Annotated[Optional[CargoScheduleType], Field(description="Report type")] = None,
        definition: Annotated[Optional[dict], Field(description="Updated report definition")] = None,
        active: Annotated[Optional[bool], Field(description="Enable or disable the schedule")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /cargo/v2/{account_id}/scheduled_report/{schedule_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if type is not None:
            body["type"] = type
        if definition is not None:
            body["definition"] = definition
        if active is not None:
            body["active"] = active
        return self._put(
            f"/cargo/v2/{{account_id}}/scheduled_report/{schedule_id}",
            account_id=account_id,
            json_body=body,
        )

    def cargo_delete_schedule(
        self,
        schedule_id: Annotated[str, Field(description="Scheduled report ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /cargo/v2/{account_id}/scheduled_report/{schedule_id}"""
        return self._delete(
            f"/cargo/v2/{{account_id}}/scheduled_report/{schedule_id}",
            account_id=account_id,
        )

    def cargo_get_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution record ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /cargo/v2/{account_id}/execution_record/{execution_id}"""
        return self._get(
            f"/cargo/v2/{{account_id}}/execution_record/{execution_id}",
            account_id=account_id,
        )

    def cargo_trigger_instant_report(
        self,
        schedule_id: Annotated[str, Field(description="Schedule ID to trigger immediately")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /cargo/v2/{account_id}/scheduled_report/{schedule_id}/instant_report"""
        return self._post(
            f"/cargo/v2/{{account_id}}/scheduled_report/{schedule_id}/instant_report",
            account_id=account_id,
        )

    # ---- AETuner v1 (dedicated host) ----

    def aetuner_list_analytics(
        self,
        datatype: Annotated[Optional[AetunerDataType], Field(
            description="logsmsgs / observations / telemetry"
        )] = None,
        output: Annotated[AetunerOutput, Field(
            description="all / correlations / analytics"
        )] = "all",
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/analytics on aetuner host"""
        params = {"output": output}
        if datatype:
            params["datatype"] = datatype
        return self._get_at(
            "aetuner",
            "/v1/{account_id}/analytics",
            account_id=account_id,
            params=params,
        )

    def aetuner_get_analytic(
        self,
        analytic_name: Annotated[str, Field(
            description="Analytic name (multi-segment, e.g. 'logmsgs/SomeRule'). Slashes URL-encoded automatically."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        include_audit_events: Annotated[bool, Field(description="Include audit events")] = False,
    ) -> dict:
        """GET /v1/{account_id}/analytics/{name} on aetuner host"""
        params = {"enable_new": "true"}
        if include_audit_events:
            params["include_audit_events"] = "true"
        return self._get_at(
            "aetuner",
            f"/v1/{{account_id}}/analytics/{url_quote(analytic_name)}",
            account_id=account_id,
            params=params,
        )

    def aetuner_set_tuning(
        self,
        analytic_name: Annotated[str, Field(description="Analytic name")],
        reason: Annotated[str, Field(description="Reason for the change (audit trail)")],
        tuning: Annotated[List[dict], Field(
            description=(
                "Tuning entries. Each: {type, operation?, value?, path?, key?}. "
                "type ∈ severity|visibility|threshold|handling|whitelist|blacklist. "
                "operation ∈ add|subtract|write|delete. "
                "Example: [{'type':'severity','operation':'write','value':'low'}]"
            )
        )],
        dry_run: Annotated[bool, Field(description="Validate without applying")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/analytics/{name} on aetuner host"""
        body = {"reason": reason, "tuning": tuning, "dry_run": dry_run}
        return self._post_at(
            "aetuner",
            f"/v1/{{account_id}}/analytics/{url_quote(analytic_name)}",
            account_id=account_id,
            json_body=body,
        )

    def aetuner_reset_analytic(
        self,
        analytic_path: Annotated[str, Field(
            description="Analytic path (e.g. 'logmsgs/SomeRule'). URL-encoded automatically."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/analytics/{path} on aetuner host"""
        return self._post_at(
            "aetuner",
            f"/v1/{{account_id}}/reset/analytics/{url_quote(analytic_path)}",
            account_id=account_id,
            json_body={},
        )

    def aetuner_reset_all_visibility(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics/visibility on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics/visibility",
            account_id=account_id,
            json_body={},
        )

    def aetuner_reset_all_severity(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics/severity on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics/severity",
            account_id=account_id,
            json_body={},
        )

    def aetuner_reset_all_handling(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics/handling on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics/handling",
            account_id=account_id,
            json_body={},
        )

    # ---- AETuner v2 / analytics2 (dedicated host) ----

    def aetuner_list_analytics_v2(
        self,
        limit: Annotated[Optional[int], Field(description="Max results to return")] = None,
        marker: Annotated[Optional[str], Field(description="Pagination marker")] = None,
        filter: Annotated[Optional[str], Field(description="Filter expression")] = None,
        type: Annotated[Optional[str], Field(description="Analytic type filter")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/analytics2 on aetuner host"""
        params: dict = {}
        if limit is not None:
            params["limit"] = limit
        if marker is not None:
            params["marker"] = marker
        if filter is not None:
            params["filter"] = filter
        if type is not None:
            params["type"] = type
        return self._get_at(
            "aetuner",
            "/v1/{account_id}/analytics2",
            account_id=account_id,
            params=params or None,
        )

    def aetuner_get_analytic_v2(
        self,
        analytic_path: Annotated[str, Field(
            description="Analytic path (e.g. 'logmsgs/SomeRule'). URL-encoded automatically."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/analytics2/{path} on aetuner host"""
        return self._get_at(
            "aetuner",
            f"/v1/{{account_id}}/analytics2/{url_quote(analytic_path)}",
            account_id=account_id,
        )

    def aetuner_update_analytic_v2(
        self,
        analytic_path: Annotated[str, Field(
            description="Analytic path (e.g. 'logmsgs/SomeRule'). URL-encoded automatically."
        )],
        visibility: Annotated[Optional[str], Field(description="Visibility override")] = None,
        severity: Annotated[Optional[str], Field(description="Severity override")] = None,
        handling: Annotated[Optional[str], Field(description="Handling override")] = None,
        tuning: Annotated[Optional[List[dict]], Field(
            description=(
                "Tuning entries. Each: {type, operation?, value?, path?, key?}. "
                "type ∈ severity|visibility|threshold|handling|whitelist|blacklist."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/analytics2/{path} on aetuner host"""
        body: dict = {}
        if visibility is not None:
            body["visibility"] = visibility
        if severity is not None:
            body["severity"] = severity
        if handling is not None:
            body["handling"] = handling
        if tuning is not None:
            body["tuning"] = tuning
        return self._post_at(
            "aetuner",
            f"/v1/{{account_id}}/analytics2/{url_quote(analytic_path)}",
            account_id=account_id,
            json_body=body,
        )

    def aetuner_list_tagsets(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/tagsets on aetuner host"""
        return self._get_at(
            "aetuner",
            "/v1/{account_id}/tagsets",
            account_id=account_id,
        )

    def aetuner_update_tagsets(
        self,
        tagsets: Annotated[Union[dict, list], Field(
            description="Tagset object or array to create/replace for the account"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/tagsets on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/tagsets",
            account_id=account_id,
            json_body=tagsets,
        )

    def aetuner_reset_all_visibility_v2(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics2/visibility on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics2/visibility",
            account_id=account_id,
            json_body={},
        )

    def aetuner_reset_all_severity_v2(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics2/severity on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics2/severity",
            account_id=account_id,
            json_body={},
        )

    def aetuner_reset_all_handling_v2(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/reset/all_analytics2/handling on aetuner host"""
        return self._post_at(
            "aetuner",
            "/v1/{account_id}/reset/all_analytics2/handling",
            account_id=account_id,
            json_body={},
        )


def setup(server: FastMCP):
    mod = SecEngModule()
    mod.register_tools(server)
