"""
AlertLogic Cloud Explorer.
Enumerate and inspect cloud environments, topology, and remediations
across AWS, Azure, and GCP deployments (Cloud Insight legacy service).

Official API: https://console.cloudinsight.alertlogic.com/api/cloud_explorer/
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class CloudExplorerModule(BaseModule):
    """Cloud environment discovery and topology queries (cloud_explorer v1)."""

    def register_tools(self, server: FastMCP):
        # ---- Environments ----
        self._add_tool(server, self.cloud_explorer_list_environments,
                       "cloud_explorer_list_environments",
                       "List all cloud environments (deployments) for an account")
        self._add_tool(server, self.cloud_explorer_get_environment,
                       "cloud_explorer_get_environment",
                       "Get details of a single cloud environment")
        # ---- Topology ----
        self._add_tool(server, self.cloud_explorer_get_topology,
                       "cloud_explorer_get_topology",
                       "Get topological layout of a cloud environment (VPCs, subnets, hosts)")
        self._add_tool(server, self.cloud_explorer_get_topology_v2,
                       "cloud_explorer_get_topology_v2",
                       "Get v2 topological layout of a cloud environment with richer asset detail")
        # ---- Regions / VPCs / Subnets / Hosts ----
        self._add_tool(server, self.cloud_explorer_list_regions,
                       "cloud_explorer_list_regions",
                       "List cloud regions discovered in an environment")
        self._add_tool(server, self.cloud_explorer_list_vpcs,
                       "cloud_explorer_list_vpcs",
                       "List VPCs/networks discovered in a region of an environment")
        self._add_tool(server, self.cloud_explorer_list_subnets,
                       "cloud_explorer_list_subnets",
                       "List subnets discovered in a VPC")
        self._add_tool(server, self.cloud_explorer_list_hosts,
                       "cloud_explorer_list_hosts",
                       "List hosts/instances in an environment, optionally scoped to a region or VPC")
        # ---- Remediations ----
        self._add_tool(server, self.cloud_explorer_list_remediations,
                       "cloud_explorer_list_remediations",
                       "List remediation groups (groups of exposures) for an environment")
        self._add_tool(server, self.cloud_explorer_get_remediation,
                       "cloud_explorer_get_remediation",
                       "Get a specific remediation group by ID")
        # ---- Exposures ----
        self._add_tool(server, self.cloud_explorer_list_exposures,
                       "cloud_explorer_list_exposures",
                       "List all exposures for an environment")
        self._add_tool(server, self.cloud_explorer_get_exposure,
                       "cloud_explorer_get_exposure",
                       "Get a specific exposure by ID")

    # ---- Environments ----

    def cloud_explorer_list_environments(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List environments. GET /cloud_explorer/v1/{account_id}/environments"""
        return self._get(
            "/cloud_explorer/v1/{account_id}/environments",
            account_id=account_id,
        )

    def cloud_explorer_get_environment(
        self,
        environment_id: Annotated[str, Field(description="Environment (deployment) UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get environment. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}"""
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}",
            account_id=account_id,
        )

    # ---- Topology ----

    def cloud_explorer_get_topology(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        include: Annotated[Optional[str], Field(
            description="Comma-separated asset types to include (e.g., 'vpc,subnet,host')"
        )] = None,
        extras: Annotated[Optional[str], Field(
            description="Extra data to include (e.g., 'vulnerabilities,remediations')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Topology layout. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/topology"""
        params = {}
        if include:
            params["include"] = include
        if extras:
            params["extras"] = extras
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/topology",
            account_id=account_id,
            params=params or None,
        )

    def cloud_explorer_get_topology_v2(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        include: Annotated[Optional[str], Field(
            description="Comma-separated asset types to include"
        )] = None,
        extras: Annotated[Optional[str], Field(
            description="Extra data to include"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Topology v2. GET /cloud_explorer/v2/{account_id}/environments/{environment_id}/topology"""
        params = {}
        if include:
            params["include"] = include
        if extras:
            params["extras"] = extras
        return self._get(
            f"/cloud_explorer/v2/{{account_id}}/environments/{environment_id}/topology",
            account_id=account_id,
            params=params or None,
        )

    # ---- Regions ----

    def cloud_explorer_list_regions(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List regions. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/regions"""
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/regions",
            account_id=account_id,
        )

    # ---- VPCs / Networks ----

    def cloud_explorer_list_vpcs(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        region: Annotated[Optional[str], Field(
            description="Cloud region to filter by (e.g., 'us-east-1')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List VPCs. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/vpcs"""
        params = {}
        if region:
            params["region"] = region
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/vpcs",
            account_id=account_id,
            params=params or None,
        )

    # ---- Subnets ----

    def cloud_explorer_list_subnets(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        vpc_key: Annotated[Optional[str], Field(
            description="VPC asset key to scope the subnet listing"
        )] = None,
        region: Annotated[Optional[str], Field(description="Cloud region filter")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List subnets. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/subnets"""
        params = {}
        if vpc_key:
            params["vpc_key"] = vpc_key
        if region:
            params["region"] = region
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/subnets",
            account_id=account_id,
            params=params or None,
        )

    # ---- Hosts ----

    def cloud_explorer_list_hosts(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        region: Annotated[Optional[str], Field(description="Cloud region filter")] = None,
        vpc_key: Annotated[Optional[str], Field(description="VPC asset key filter")] = None,
        subnet_key: Annotated[Optional[str], Field(description="Subnet asset key filter")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List hosts. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/hosts"""
        params = {}
        if region:
            params["region"] = region
        if vpc_key:
            params["vpc_key"] = vpc_key
        if subnet_key:
            params["subnet_key"] = subnet_key
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/hosts",
            account_id=account_id,
            params=params or None,
        )

    # ---- Remediations ----

    def cloud_explorer_list_remediations(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        filters: Annotated[Optional[str], Field(
            description="Filter expression (e.g., 'severity:high')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List remediations. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/remediations"""
        params = {}
        if filters:
            params["filters"] = filters
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/remediations",
            account_id=account_id,
            params=params or None,
        )

    def cloud_explorer_get_remediation(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        remediation_id: Annotated[str, Field(description="Remediation group ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get remediation. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/remediations/{remediation_id}"""
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/remediations/{remediation_id}",
            account_id=account_id,
        )

    # ---- Exposures ----

    def cloud_explorer_list_exposures(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        severity: Annotated[Optional[str], Field(
            description="Filter by severity: 'critical', 'high', 'medium', 'low', 'info'"
        )] = None,
        asset_type: Annotated[Optional[str], Field(
            description="Filter by asset type (e.g., 'host', 'vpc')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List exposures. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/exposures"""
        params = {}
        if severity:
            params["severity"] = severity
        if asset_type:
            params["asset_type"] = asset_type
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/exposures",
            account_id=account_id,
            params=params or None,
        )

    def cloud_explorer_get_exposure(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        exposure_id: Annotated[str, Field(description="Exposure ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get exposure. GET /cloud_explorer/v1/{account_id}/environments/{environment_id}/exposures/{exposure_id}"""
        return self._get(
            f"/cloud_explorer/v1/{{account_id}}/environments/{environment_id}/exposures/{exposure_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = CloudExplorerModule()
    mod.register_tools(server)
