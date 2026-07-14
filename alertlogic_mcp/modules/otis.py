"""
AlertLogic Otis — IDS Customer Configurations Service (v3).
Manages IDS/scan protection options per account/deployment/VPC and
cross-network protection relationships.

Official spec: alsdkdefs/apis/otis/otis.v3.yaml
Service host:  https://otis.mdr.global.alertlogic.com
"""
import os
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


# ---- Option name literals -----------------------------------------------
# Exhaustive list from otis.v3.yaml oneOf discriminator values.

OptionName = Literal[
    "abs_follow_internal_scan_schedules",
    "agent_assisted_decryption",
    "cross_network_protection",
    "discovery_scan_frequency",
    "external_scan_frequency",
    "ids_appliance_instance_type",
    "ids_appliance_instance_type_test",
    "ids_appliances_placement",
    "ids_appliances_scaling",
    "ids_security_resource_tags",
    "max_discovery_scan_jobs",
    "max_vulnerability_scan_jobs",
    "no_stats_interval_hours",
    "predefined_security_subnet",
    "prohibit_cross_az_connection",
    "scan_appliance_instance_type",
    "scan_appliances_scaling",
    "scan_security_resource_tags",
    "scan_security_subnet_cidr_block",
    "security_resource_tags",
    "span_port_enabled",
    "vulnerability_scan_frequency",
]

ScanFrequency = Literal["automatic", "daily", "weekly", "monthly"]
DiscoveryFrequency = Literal["automatic", 1, 2, 3, 4]
PlacementPolicy = Literal["automatic", "constant"]
ScalingPolicy = Literal["automatic", "constant"]


class OtisModule(BaseModule):
    """Otis v3: IDS/scan protection options and cross-network configuration."""

    def __init__(self):
        super().__init__()
        self.service_hosts["otis"] = os.environ.get(
            "ALERTLOGIC_OTIS_BASE_URL",
            "https://otis.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        # Options CRUD
        self._add_tool(server, self.otis_list_options, "otis_list_options",
                       "List all IDS/scan configuration options for an account")
        self._add_tool(server, self.otis_get_option, "otis_get_option",
                       "Get a specific IDS/scan configuration option by ID")
        self._add_tool(server, self.otis_create_option, "otis_create_option",
                       "Create a new IDS/scan configuration option")
        self._add_tool(server, self.otis_update_option, "otis_update_option",
                       "Update an existing IDS/scan configuration option")
        self._add_tool(server, self.otis_delete_option, "otis_delete_option",
                       "Delete an IDS/scan configuration option")
        # Cross-network protection queries
        self._add_tool(server, self.otis_list_cross_protected_networks,
                       "otis_list_cross_protected_networks",
                       "List networks that are protected by another (cross-account IDS) network")
        self._add_tool(server, self.otis_list_cross_protecting_networks,
                       "otis_list_cross_protecting_networks",
                       "List networks that are protecting another network (cross-account IDS)")

    # ------------------------------------------------------------------ #
    #  Options                                                            #
    # ------------------------------------------------------------------ #

    def otis_list_options(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List all protection/configuration options.
        GET /otis/v3/{account_id}/options
        """
        return self._get_at(
            "otis",
            "/otis/v3/{account_id}/options",
            account_id=account_id,
        )

    def otis_get_option(
        self,
        option_id: Annotated[str, Field(description="Option UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a single configuration option by UUID.
        GET /otis/v3/{account_id}/options/{option_id}
        """
        return self._get_at(
            "otis",
            f"/otis/v3/{{account_id}}/options/{option_id}",
            account_id=account_id,
        )

    def otis_create_option(
        self,
        name: Annotated[OptionName, Field(
            description=(
                "Option identifier. Determines the shape of `value` and `scope`. "
                "Boolean options: abs_follow_internal_scan_schedules, "
                "agent_assisted_decryption, prohibit_cross_az_connection, span_port_enabled. "
                "Frequency options: discovery_scan_frequency (automatic|1-4), "
                "external_scan_frequency / vulnerability_scan_frequency "
                "(automatic|daily|weekly|monthly). "
                "Instance-type options: ids_appliance_instance_type, "
                "ids_appliance_instance_type_test, scan_appliance_instance_type (AWS type strings). "
                "Placement: ids_appliances_placement — value={policy, max_zones?, zone_keys?[]}. "
                "Scaling: ids_appliances_scaling / scan_appliances_scaling — "
                "value={policy, num_instances?, scale_up_threshold?, scale_down_threshold?}. "
                "Tag options: ids_security_resource_tags, scan_security_resource_tags, "
                "security_resource_tags — value=[{key, value}] (max 30). "
                "Integer options: max_discovery_scan_jobs, max_vulnerability_scan_jobs, "
                "no_stats_interval_hours (max 24). "
                "Subnet: predefined_security_subnet (subnet asset key string), "
                "scan_security_subnet_cidr_block (CIDR /16-/28). "
                "Cross-network: cross_network_protection — "
                "value={deployment_id, vpc_key}, scope required."
            )
        )],
        value: Annotated[object, Field(
            description=(
                "Option value — shape depends on `name`. "
                "Boolean: true/false. "
                "Frequency string: 'automatic'|'daily'|'weekly'|'monthly'. "
                "Discovery frequency: 'automatic' or integer 1-4. "
                "Instance type: AWS instance-type string (e.g. 't3.medium'). "
                "Placement: {\"policy\": \"automatic\"|\"constant\", \"max_zones\": int, "
                "\"zone_keys\": [\"...\", ...]}. "
                "Scaling: {\"policy\": \"automatic\"|\"constant\", \"num_instances\": 1-8, "
                "\"scale_up_threshold\": float, \"scale_down_threshold\": float}. "
                "Tags: [{\"key\": \"...\", \"value\": \"...\"}]. "
                "Integer (jobs/hours): integer. "
                "Subnet/CIDR: string. "
                "Cross-network: {\"deployment_id\": \"...\", \"vpc_key\": \"...\"}."
            )
        )],
        scope: Annotated[Optional[dict], Field(
            description=(
                "Scope restricts the option to a specific deployment/region/VPC. "
                "Shape: {\"deployment_id\": \"...\", \"region_key\": \"...\", \"vpc_key\": \"...\"}. "
                "Required for cross_network_protection, agent_assisted_decryption, "
                "abs_follow_internal_scan_schedules."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create a new configuration option.
        POST /otis/v3/{account_id}/options
        """
        body: dict = {"name": name, "value": value}
        if scope is not None:
            body["scope"] = scope
        return self._post_at(
            "otis",
            "/otis/v3/{account_id}/options",
            account_id=account_id,
            json_body=body,
        )

    def otis_update_option(
        self,
        option_id: Annotated[str, Field(description="Option UUID to update")],
        name: Annotated[OptionName, Field(description="Option identifier (same set as create)")],
        value: Annotated[object, Field(description="New option value (same shape rules as create)")],
        scope: Annotated[Optional[dict], Field(
            description=(
                "Updated scope. Shape: {\"deployment_id\": \"...\", "
                "\"region_key\": \"...\", \"vpc_key\": \"...\"}."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update an existing configuration option.
        PUT /otis/v3/{account_id}/options/{option_id}
        """
        body: dict = {"name": name, "value": value}
        if scope is not None:
            body["scope"] = scope
        return self._put_at(
            "otis",
            f"/otis/v3/{{account_id}}/options/{option_id}",
            account_id=account_id,
            json_body=body,
        )

    def otis_delete_option(
        self,
        option_id: Annotated[str, Field(description="Option UUID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete a configuration option.
        DELETE /otis/v3/{account_id}/options/{option_id}
        Returns 204 No Content on success.
        """
        return self._delete_at(
            "otis",
            f"/otis/v3/{{account_id}}/options/{option_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Cross-network protection queries                                   #
    # ------------------------------------------------------------------ #

    def otis_list_cross_protected_networks(
        self,
        deployment_id: Annotated[Optional[str], Field(
            description="Filter by deployment ID of the protected network"
        )] = None,
        option_id: Annotated[Optional[str], Field(
            description="Filter by cross_network_protection option UUID"
        )] = None,
        vpc_key: Annotated[Optional[str], Field(
            description="Filter by VPC asset key of the protected network"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List networks that are being protected by another network (cross-account IDS).
        Each result includes the protected network identity and the protecting_network object.
        GET /otis/v3/{account_id}/cross_protected_networks
        """
        params = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        if option_id:
            params["option_id"] = option_id
        if vpc_key:
            params["vpc_key"] = vpc_key
        return self._get_at(
            "otis",
            "/otis/v3/{account_id}/cross_protected_networks",
            account_id=account_id,
            params=params or None,
        )

    def otis_list_cross_protecting_networks(
        self,
        deployment_id: Annotated[Optional[str], Field(
            description="Filter by deployment ID of the protecting network"
        )] = None,
        option_id: Annotated[Optional[str], Field(
            description="Filter by cross_network_protection option UUID"
        )] = None,
        vpc_key: Annotated[Optional[str], Field(
            description="Filter by VPC asset key of the protecting network"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List networks that are acting as IDS protectors for another network (cross-account IDS).
        Each result includes the protecting network identity and the protected_network object.
        GET /otis/v3/{account_id}/cross_protecting_networks
        """
        params = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        if option_id:
            params["option_id"] = option_id
        if vpc_key:
            params["vpc_key"] = vpc_key
        return self._get_at(
            "otis",
            "/otis/v3/{account_id}/cross_protecting_networks",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = OtisModule()
    mod.register_tools(server)
