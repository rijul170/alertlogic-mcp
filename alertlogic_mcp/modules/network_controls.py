"""
AlertLogic Exclusions / Network Controls.
Manage scan and IDS exclusion rules per deployment.

Official API: https://console.cloudinsight.alertlogic.com/api/exclusions/
"""
from typing import Annotated, Optional, List
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


class NetworkControlsModule(BaseModule):
    """Scan & IDS exclusion rule management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.exclusions_list, "exclusions_list",
                        "List all exclusion rules for a deployment")
        self._add_tool(server, self.exclusions_get, "exclusions_get",
                        "Get a specific exclusion rule")
        self._add_tool(server, self.exclusions_create, "exclusions_create",
                        "Create a new exclusion rule (scan/IDS blackout)")
        self._add_tool(server, self.exclusions_update, "exclusions_update",
                        "Update an existing exclusion rule")
        self._add_tool(server, self.exclusions_delete, "exclusions_delete",
                        "Delete an exclusion rule")
        self._add_tool(server, self.exclusions_check_asset, "exclusions_check_asset",
                        "Check if an asset is excluded for a given feature")
        self._add_tool(server, self.whitelist_list_tags, "whitelist_list_tags",
                        "List all designated whitelist tags")
        self._add_tool(server, self.whitelist_add_tag, "whitelist_add_tag",
                        "Designate a tag as whitelisted for scanning")
        self._add_tool(server, self.whitelist_remove_tag, "whitelist_remove_tag",
                        "Remove a tag from the whitelist")
        self._add_tool(server, self.whitelist_list_hosts, "whitelist_list_hosts",
                        "List whitelisted hosts in a deployment")
        self._add_tool(server, self.whitelist_check_host, "whitelist_check_host",
                        "Check if a single host is whitelisted")
        self._add_tool(server, self.endpoints_query_batch, "endpoints_query_batch",
                        "Batch multi-service endpoint query for a given residency")
        self._add_tool(server, self.endpoints_get_by_type, "endpoints_get_by_type",
                        "Get a service endpoint filtered by endpoint type (api, ui, etc.)")
        self._add_tool(server, self.endpoints_get_by_residency, "endpoints_get_by_residency",
                        "Get a service endpoint for a specific residency/region")
        self._add_tool(server, self.assets_write_batch, "assets_write_batch",
                        "Asset-group level batch declare/dispose (not deployment-scoped)")

    def exclusions_list(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List exclusions. GET /exclusions/v1/{account_id}/{deployment_id}/rules"""
        return self._get(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/rules",
            account_id=account_id,
        )

    def exclusions_get(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        rule_id: Annotated[str, Field(description="Exclusion rule ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get exclusion rule. GET /exclusions/v1/{account_id}/{deployment_id}/rules/{rule_id}"""
        return self._get(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/rules/{rule_id}",
            account_id=account_id,
        )

    def exclusions_create(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        name: Annotated[str, Field(description="Rule name")],
        enabled: Annotated[bool, Field(description="Whether rule is enabled")] = True,
        features: Annotated[Optional[List[str]], Field(
            description="Features to exclude: ['scan', 'ids'] (empty = all features)"
        )] = None,
        assets: Annotated[Optional[List[dict]], Field(
            description="Assets to exclude: [{'type': 'cidr', 'value': '10.0.0.0/8'}] or [{'type': 'asset', 'key': '...', 'asset_type': 'host'}]"
        )] = None,
        description: Annotated[Optional[str], Field(description="Rule description")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create exclusion. POST /exclusions/v1/{account_id}/{deployment_id}/rules"""
        body = {"name": name, "enabled": enabled}
        if features is not None:
            body["features"] = features
        if assets is not None:
            body["assets"] = assets
        if description:
            body["description"] = description
        return self._post(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/rules",
            account_id=account_id,
            json_body=body,
        )

    def exclusions_update(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        rule_id: Annotated[str, Field(description="Rule ID to update")],
        name: Annotated[Optional[str], Field(description="New name")] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable/disable")] = None,
        features: Annotated[Optional[List[str]], Field(description="Features list")] = None,
        assets: Annotated[Optional[List[dict]], Field(description="Assets list")] = None,
        description: Annotated[Optional[str], Field(description="Description")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update exclusion. PUT /exclusions/v1/{account_id}/{deployment_id}/rules/{rule_id}"""
        body = {}
        if name is not None:
            body["name"] = name
        if enabled is not None:
            body["enabled"] = enabled
        if features is not None:
            body["features"] = features
        if assets is not None:
            body["assets"] = assets
        if description is not None:
            body["description"] = description
        return self._put(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/rules/{rule_id}",
            account_id=account_id,
            json_body=body,
        )

    def exclusions_delete(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        rule_id: Annotated[str, Field(description="Rule ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete exclusion. DELETE /exclusions/v1/{account_id}/{deployment_id}/rules/{rule_id}"""
        return self._delete(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/rules/{rule_id}",
            account_id=account_id,
        )

    def exclusions_check_asset(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        feature_id: Annotated[str, Field(description="Feature: 'scan' or 'ids'")],
        asset_type: Annotated[str, Field(description="Asset type")],
        asset_key: Annotated[str, Field(description="Asset key")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Is-excluded selector. GET /exclusions/v2/{aid}/{dep}/is_excluded/{feature}/{type}/{key}"""
        return self._get(
            f"/exclusions/v2/{{account_id}}/{deployment_id}/is_excluded/{feature_id}/{url_quote(asset_type)}/{url_quote(asset_key)}",
            account_id=account_id,
        )

    # ---- Whitelist Tags ----
    # Real paths (per AlertLogic apiDoc):
    #   GET    /exclusions/v1/{aid}/{dep}/tags         — list designated tags
    #   GET    /exclusions/v1/{aid}/{dep}/hosts        — list whitelisted hosts
    #   GET    /exclusions/v1/{aid}/{dep}/host/{key}   — check single host
    #   POST   /exclusions/v1/{aid}/{dep}/             — designate (body: {tag: {...}})
    #   DELETE /exclusions/v1/{aid}/{dep}/             — un-designate (body: {tag: {...}})

    def whitelist_list_tags(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /exclusions/v1/{aid}/{dep}/tags"""
        return self._get(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/tags",
            account_id=account_id,
        )

    def whitelist_add_tag(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        tag_key: Annotated[str, Field(description="Tag key to whitelist")],
        tag_value: Annotated[str, Field(description="Tag value")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /exclusions/v1/{aid}/{dep}/  body: {tag: {type:'tag', tag_key, tag_value}}"""
        body = {"tag": {"type": "tag", "tag_key": tag_key, "tag_value": tag_value}}
        return self._post(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/",
            account_id=account_id,
            json_body=body,
        )

    def whitelist_remove_tag(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        tag_key: Annotated[str, Field(description="Tag key to remove")],
        tag_value: Annotated[str, Field(description="Tag value")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /exclusions/v1/{aid}/{dep}/  body: {tag: {type:'tag', tag_key, tag_value}}"""
        body = {"tag": {"type": "tag", "tag_key": tag_key, "tag_value": tag_value}}
        return self._delete(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/",
            account_id=account_id,
            json_body=body,
        )

    def whitelist_list_hosts(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        tag_key: Annotated[Optional[str], Field(description="Filter: whitelist tag key")] = None,
        tag_value: Annotated[Optional[str], Field(description="Filter: whitelist tag value")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /exclusions/v1/{aid}/{dep}/hosts"""
        params = {}
        if tag_key:
            params["type"] = "tag"
            params["tag_key"] = tag_key
        if tag_value:
            params["tag_value"] = tag_value
        return self._get(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/hosts",
            account_id=account_id,
            params=params or None,
        )

    def whitelist_check_host(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_key: Annotated[str, Field(description="Host asset key")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /exclusions/v1/{aid}/{dep}/host/{asset_key}"""
        return self._get(
            f"/exclusions/v1/{{account_id}}/{deployment_id}/host/{url_quote(asset_key)}",
            account_id=account_id,
        )

    # ---- Endpoints v1 ----
    # Base URL: https://api.cloudinsight.alertlogic.com
    # Docs: https://console.cloudinsight.alertlogic.com/api/endpoints/

    def endpoints_query_batch(
        self,
        residency: Annotated[str, Field(description="Residency/region: 'default', 'us', 'emea', etc.")],
        services: Annotated[List[str], Field(description="List of service names to query endpoints for")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Batch multi-service endpoint query. POST /endpoints/v1/{account_id}/residency/{residency}/endpoints"""
        body = {"services": services}
        return self._post(
            f"/endpoints/v1/{{account_id}}/residency/{url_quote(residency)}/endpoints",
            account_id=account_id,
            json_body=body,
            base_url=self.base_url,
        )

    def endpoints_get_by_type(
        self,
        service_name: Annotated[str, Field(description="Service name (e.g., 'ingest', 'lm')")],
        endpoint_type: Annotated[str, Field(description="Endpoint type: 'api', 'ui', etc.")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get endpoint filtered by type. GET /endpoints/v1/{account_id}/services/{service_name}/endpoint/{endpoint_type}"""
        return self._get(
            f"/endpoints/v1/{{account_id}}/services/{url_quote(service_name)}/endpoint/{url_quote(endpoint_type)}",
            account_id=account_id,
            base_url=self.base_url,
        )

    def endpoints_get_by_residency(
        self,
        residency: Annotated[str, Field(description="Residency/region: 'default', 'us', 'emea', etc.")],
        service_name: Annotated[str, Field(description="Service name (e.g., 'ingest', 'lm')")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get service endpoint for a specific residency. GET /endpoints/v1/{account_id}/residency/{residency}/services/{service_name}/endpoint"""
        return self._get(
            f"/endpoints/v1/{{account_id}}/residency/{url_quote(residency)}/services/{url_quote(service_name)}/endpoint",
            account_id=account_id,
        )

    # ---- Assets Write (account-level batch) ----
    # Base URL: https://api.cloudinsight.alertlogic.com
    # Docs: https://console.cloudinsight.alertlogic.com/api/assets_write/

    def assets_write_batch(
        self,
        operation: Annotated[str, Field(description="Operation: 'declare' or 'dispose'")],
        assets: Annotated[List[dict], Field(
            description="Assets to write: [{'type': 'asset_type', 'key': '/key/path', 'properties': {...}}]"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Asset-group level batch write (not deployment-scoped). PUT /assets_write/v1/{account_id}/assets"""
        body = {"operation": operation, "scope": "groups", "assets": assets}
        return self._put(
            "/assets_write/v1/{account_id}/assets",
            account_id=account_id,
            json_body=body,
        )


def setup(server: FastMCP):
    mod = NetworkControlsModule()
    mod.register_tools(server)