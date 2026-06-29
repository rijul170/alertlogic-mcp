"""
AlertLogic Scan Scheduler (scheduler v2).

Manage scan schedules, trigger/stop scans, validate IPs,
and inspect scan intervals for Alert Logic deployments.

Spec: https://github.com/alertlogic/alertlogic-sdk-definitions
       (alsdkdefs/apis/scan_scheduler/scan_scheduler.v2.yaml)

Service host: https://scheduler.mdr.global.alertlogic.com
"""
import os
from typing import Annotated, List, Literal, Optional

from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


ScanType = Literal["vulnerability", "external", "discovery", "abs"]

ScanFrequency = Literal[
    "automatic", "daily", "weekly", "fortnightly", "monthly", "quarterly", "once"
]

AssetType = Literal[
    "deployment", "region", "network", "vpc", "subnet", "host",
    "external-ip", "external-dns-name", "agent",
]


class ScanSchedulerModule(BaseModule):
    """Scan Scheduler v2 — schedule management, trigger/stop, IP validation."""

    def __init__(self):
        super().__init__()
        self.service_hosts["scan_scheduler"] = os.environ.get(
            "ALERTLOGIC_SCAN_SCHEDULER_URL",
            "https://scheduler.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.scan_scheduler_trigger,
                        "scan_scheduler_trigger",
                        "Expedite (trigger immediately) a scan for an asset in a deployment")
        self._add_tool(server, self.scan_scheduler_stop,
                        "scan_scheduler_stop",
                        "Stop active scans for selected assets in a deployment")
        self._add_tool(server, self.scan_scheduler_validate_ips,
                        "scan_scheduler_validate_ips",
                        "Validate a list of IPs/CIDRs against a deployment (no scan type filter)")
        self._add_tool(server, self.scan_scheduler_validate_ips_by_type,
                        "scan_scheduler_validate_ips_by_type",
                        "Validate a list of IPs/CIDRs against a deployment for a specific scan type")
        self._add_tool(server, self.scan_scheduler_list_timezones,
                        "scan_scheduler_list_timezones",
                        "List all supported scan-window timezones")
        self._add_tool(server, self.scan_scheduler_list_schedules,
                        "scan_scheduler_list_schedules",
                        "List all scan schedules for a deployment")
        self._add_tool(server, self.scan_scheduler_create_schedule,
                        "scan_scheduler_create_schedule",
                        "Create a new scan schedule for a deployment")
        self._add_tool(server, self.scan_scheduler_get_schedule,
                        "scan_scheduler_get_schedule",
                        "Get a single scan schedule by ID")
        self._add_tool(server, self.scan_scheduler_delete_schedule,
                        "scan_scheduler_delete_schedule",
                        "Delete a scan schedule (default schedules cannot be deleted)")
        self._add_tool(server, self.scan_scheduler_update_schedule,
                        "scan_scheduler_update_schedule",
                        "Update an existing scan schedule")
        self._add_tool(server, self.scan_scheduler_stop_schedule,
                        "scan_scheduler_stop_schedule",
                        "Stop all active scans belonging to a schedule")
        self._add_tool(server, self.scan_scheduler_get_schedule_summary,
                        "scan_scheduler_get_schedule_summary",
                        "Get metrics/summary for a scan schedule (SLA coverage, next scan date, status, etc.)")
        self._add_tool(server, self.scan_scheduler_get_scan_intervals,
                        "scan_scheduler_get_scan_intervals",
                        "List all scan intervals (active/upcoming windows) for every schedule in a deployment")

    # ------------------------------------------------------------------ #
    #  1. Trigger / expedite a scan                                       #
    # ------------------------------------------------------------------ #

    def scan_scheduler_trigger(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_type: Annotated[AssetType, Field(
            description=(
                "Asset topology level to scan: deployment, region, network, vpc, "
                "subnet, host, external-ip, external-dns-name, or agent"
            )
        )],
        asset_key: Annotated[str, Field(
            description=(
                "Asset identifier path (e.g. '/aws/us-east-1/host/i-0abc123'). "
                "Slashes within the key are percent-encoded automatically."
            )
        )],
        force: Annotated[Optional[bool], Field(
            description="Override exclusion rules applied to the target assets"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Expedite scan for an asset. PUT /scheduler/v2/{account_id}/{deployment_id}/scan"""
        params = {}
        if force is not None:
            params["force"] = str(force).lower()
        body = {
            "type": "asset",
            "asset_type": asset_type,
            "key": asset_key,
        }
        return self._put_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/scan",
            account_id=account_id,
            json_body=body,
        )

    # ------------------------------------------------------------------ #
    #  2. Stop scans for assets                                           #
    # ------------------------------------------------------------------ #

    def scan_scheduler_stop(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_type: Annotated[AssetType, Field(
            description="Asset topology level: deployment, region, network, vpc, subnet, host, etc."
        )],
        asset_key: Annotated[str, Field(
            description="Asset identifier path (e.g. '/aws/us-east-1/host/i-0abc123')"
        )],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Stop active scans for an asset. PUT /scheduler/v2/{account_id}/{deployment_id}/stop"""
        body = {
            "type": "asset",
            "asset_type": asset_type,
            "key": asset_key,
        }
        return self._put_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/stop",
            account_id=account_id,
            json_body=body,
        )

    # ------------------------------------------------------------------ #
    #  3. Validate IPs (no scan type)                                     #
    # ------------------------------------------------------------------ #

    def scan_scheduler_validate_ips(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        ip_addresses: Annotated[List[str], Field(
            description=(
                "List of IPs, CIDR ranges, or IP ranges to validate. "
                "Examples: '10.0.0.1', '10.0.1.0/24', '10.0.0.1 - 10.0.0.100'"
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Validate IPs against a deployment. POST /scheduler/v2/{account_id}/{deployment_id}/ip_validator"""
        return self._post_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/ip_validator",
            account_id=account_id,
            json_body=ip_addresses,
        )

    # ------------------------------------------------------------------ #
    #  4. Validate IPs by scan type                                       #
    # ------------------------------------------------------------------ #

    def scan_scheduler_validate_ips_by_type(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        ip_addresses: Annotated[List[str], Field(
            description=(
                "List of IPs, CIDR ranges, or IP ranges to validate. "
                "Examples: '10.0.0.1', '10.0.1.0/24', '10.0.0.1 - 10.0.0.100'"
            )
        )],
        scan_type: Annotated[ScanType, Field(
            description="Scan type whose validation criteria to apply: vulnerability, external, discovery, or abs"
        )] = "vulnerability",
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Validate IPs for a scan type. POST /scheduler/v2/{account_id}/{deployment_id}/ip_validator/{scan_type}"""
        return self._post_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/ip_validator/{scan_type}",
            account_id=account_id,
            json_body=ip_addresses,
        )

    # ------------------------------------------------------------------ #
    #  5. List timezones                                                  #
    # ------------------------------------------------------------------ #

    def scan_scheduler_list_timezones(self) -> dict:
        """List supported scan-window timezones. GET /scheduler/v2/timezones"""
        return self._get_at("scan_scheduler", "/scheduler/v2/timezones")

    # ------------------------------------------------------------------ #
    #  6. List schedules                                                  #
    # ------------------------------------------------------------------ #

    def scan_scheduler_list_schedules(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        return_fields: Annotated[Optional[List[str]], Field(
            description=(
                "Limit returned fields. Allowed values: id, name, enabled, "
                "scan_frequency, scan_window, scope. Omit to return full objects."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """List scan schedules. GET /scheduler/v2/{account_id}/{deployment_id}/schedules"""
        params = {}
        if return_fields:
            params["return_fields"] = return_fields
        return self._get_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules",
            account_id=account_id,
            params=params,
        )

    # ------------------------------------------------------------------ #
    #  7. Create schedule                                                 #
    # ------------------------------------------------------------------ #

    def scan_scheduler_create_schedule(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        name: Annotated[str, Field(description="Human-readable schedule name")],
        type_of_scan: Annotated[ScanType, Field(
            description="Scan type: vulnerability, external, discovery, or abs"
        )],
        scan_frequency: Annotated[ScanFrequency, Field(
            description=(
                "SLA period: automatic, daily, weekly, fortnightly, "
                "monthly, quarterly, or once"
            )
        )],
        enabled: Annotated[bool, Field(description="Whether the schedule is active")] = True,
        timezone: Annotated[Optional[str], Field(
            description="IANA timezone for scan windows (e.g. 'America/New_York'). Defaults to UTC."
        )] = None,
        include_all_assets: Annotated[bool, Field(
            description="When True, schedule covers all deployment assets (ignores include list)"
        )] = False,
        include_assets: Annotated[Optional[List[dict]], Field(
            description=(
                "Assets/IPs/CIDRs to include in scope. Each item is a dict with 'type' and "
                "type-specific fields. Supported types:\n"
                "  asset:      {'type':'asset','asset_type':'<type>','key':'<path>'}\n"
                "  cidr:       {'type':'cidr','value':'10.0.0.0/24'}\n"
                "  ip_address: {'type':'ip_address','value':'10.0.0.1'}\n"
                "  ip_range:   {'type':'ip_range','from_ip':'10.0.0.1','to_ip':'10.0.0.10'}\n"
                "  tag:        {'type':'tag','key':'<name>','value':'<value>'}"
            )
        )] = None,
        scan_windows: Annotated[Optional[List[dict]], Field(
            description=(
                "Time windows during which scanning is permitted. Each window is a dict with a "
                "'type' discriminator. Supported types:\n"
                "  days_of_week:    {'type':'days_of_week','days_of_week':[1-7],'start_time':'HH:MM','end_time':'HH:MM'}\n"
                "  days_of_month:   {'type':'days_of_month','days_of_month':[1-31],'start_time':'HH:MM','end_time':'HH:MM'}\n"
                "  weekday_of_month:{'type':'weekday_of_month','day_of_week':1-7,'nth_week':1-4,'start_time':'HH:MM','end_time':'HH:MM'}\n"
                "  weekly_period:   {'type':'weekly_period','start_day':1-7,'start_time':'HH:MM','end_day':1-7,'end_time':'HH:MM'}\n"
                "  monthly_period:  {'type':'monthly_period','start_day':1-31,'start_time':'HH:MM','end_day':1-31,'end_time':'HH:MM'}\n"
                "  specific_date:   {'type':'specific_date','start_date':'YYYY.MM.DD','start_time':'HH:MM',"
                "'end_date':'YYYY.MM.DD','end_time':'HH:MM'}\n"
                "  quarterly:       {'type':'quarterly','month_of_quarter':1-3,'start_day':1-31,"
                "'start_time':'HH:MM','end_day':1-31,'end_time':'HH:MM'}"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Create scan schedule. POST /scheduler/v2/{account_id}/{deployment_id}/schedules"""
        body: dict = {
            "name": name,
            "type_of_scan": type_of_scan,
            "scan_frequency": scan_frequency,
            "enabled": enabled,
            "scan_scope": {
                "include_all_assets": include_all_assets,
            },
        }
        if timezone is not None:
            body["timezone"] = timezone
        if include_assets is not None:
            body["scan_scope"]["include"] = include_assets
        if scan_windows is not None:
            body["scan_windows"] = scan_windows
        return self._post_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules",
            account_id=account_id,
            json_body=body,
        )

    # ------------------------------------------------------------------ #
    #  8. Get schedule                                                    #
    # ------------------------------------------------------------------ #

    def scan_scheduler_get_schedule(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        schedule_id: Annotated[str, Field(description="Schedule UUID")],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Get a scan schedule. GET /scheduler/v2/{account_id}/{deployment_id}/schedules/{schedule_id}"""
        return self._get_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules/{schedule_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  9. Delete schedule                                                 #
    # ------------------------------------------------------------------ #

    def scan_scheduler_delete_schedule(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        schedule_id: Annotated[str, Field(description="Schedule UUID")],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Delete a scan schedule. DELETE /scheduler/v2/{account_id}/{deployment_id}/schedules/{schedule_id}"""
        return self._delete_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules/{schedule_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  10. Update schedule                                                #
    # ------------------------------------------------------------------ #

    def scan_scheduler_update_schedule(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        schedule_id: Annotated[str, Field(description="Schedule UUID")],
        name: Annotated[Optional[str], Field(description="New schedule name")] = None,
        type_of_scan: Annotated[Optional[ScanType], Field(
            description="New scan type: vulnerability, external, discovery, or abs"
        )] = None,
        scan_frequency: Annotated[Optional[ScanFrequency], Field(
            description="New SLA period: automatic, daily, weekly, fortnightly, monthly, quarterly, or once"
        )] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable or disable the schedule")] = None,
        timezone: Annotated[Optional[str], Field(
            description="IANA timezone for scan windows (e.g. 'America/Chicago')"
        )] = None,
        include_all_assets: Annotated[Optional[bool], Field(
            description="When True, schedule covers all deployment assets"
        )] = None,
        include_assets: Annotated[Optional[List[dict]], Field(
            description=(
                "Replacement asset/IP/CIDR scope list. Each item dict uses the same format as "
                "scan_scheduler_create_schedule (type: asset | cidr | ip_address | ip_range | tag)."
            )
        )] = None,
        scan_windows: Annotated[Optional[List[dict]], Field(
            description=(
                "Replacement scan windows list. Each window dict uses the same format as "
                "scan_scheduler_create_schedule (type: days_of_week | days_of_month | etc.)."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Update a scan schedule. PUT /scheduler/v2/{account_id}/{deployment_id}/schedules/{schedule_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if type_of_scan is not None:
            body["type_of_scan"] = type_of_scan
        if scan_frequency is not None:
            body["scan_frequency"] = scan_frequency
        if enabled is not None:
            body["enabled"] = enabled
        if timezone is not None:
            body["timezone"] = timezone
        if include_all_assets is not None or include_assets is not None:
            scope: dict = {}
            if include_all_assets is not None:
                scope["include_all_assets"] = include_all_assets
            if include_assets is not None:
                scope["include"] = include_assets
            body["scan_scope"] = scope
        if scan_windows is not None:
            body["scan_windows"] = scan_windows
        return self._put_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules/{schedule_id}",
            account_id=account_id,
            json_body=body,
        )

    # ------------------------------------------------------------------ #
    #  11. Stop a schedule's active scans                                 #
    # ------------------------------------------------------------------ #

    def scan_scheduler_stop_schedule(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        schedule_id: Annotated[str, Field(description="Schedule UUID")],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Stop active scans for a schedule. PUT /scheduler/v2/{account_id}/{deployment_id}/schedules/{schedule_id}/stop"""
        return self._put_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules/{schedule_id}/stop",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  12. Schedule summary / metrics                                     #
    # ------------------------------------------------------------------ #

    def scan_scheduler_get_schedule_summary(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        schedule_id: Annotated[str, Field(description="Schedule UUID")],
        return_fields: Annotated[Optional[List[str]], Field(
            description=(
                "Limit returned fields. Allowed values: assets_number, assets_in_sla, "
                "assets_excluded, assets_to_scan, assets_being_scanned, last_scan_date, "
                "next_scan_date, status. Omit to return the full summary object."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """Get schedule metrics. GET /scheduler/v2/{account_id}/{deployment_id}/schedules/{schedule_id}/summary"""
        params = {}
        if return_fields:
            params["return_fields"] = return_fields
        return self._get_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/schedules/{schedule_id}/summary",
            account_id=account_id,
            params=params,
        )

    # ------------------------------------------------------------------ #
    #  13. Scan intervals for a deployment                                #
    # ------------------------------------------------------------------ #

    def scan_scheduler_get_scan_intervals(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Override account ID")] = None,
    ) -> dict:
        """List all scan intervals across schedules. GET /scheduler/v2/{account_id}/{deployment_id}/scan_intervals"""
        return self._get_at(
            "scan_scheduler",
            f"/scheduler/v2/{{account_id}}/{deployment_id}/scan_intervals",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = ScanSchedulerModule()
    mod.register_tools(server)
