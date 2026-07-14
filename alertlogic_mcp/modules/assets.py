"""
AlertLogic Assets Management.
Query asset topology and declare/remove/update assets.

Spec: assets_query.v1, assets_write.v1

Note: remediations live in compliance.py (PUT /assets_query/v2/.../remediations).
"""
from typing import Annotated, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class AssetsModule(BaseModule):
    """Assets query (v1) + write (v1)."""

    def register_tools(self, server: FastMCP):
        # Query
        self._add_tool(server, self.assets_query, "assets_query",
                        "Query assets for a deployment")
        self._add_tool(server, self.assets_get_topology, "assets_get_topology",
                        "Get topological layout of assets in a deployment")
        # Write
        self._add_tool(server, self.assets_declare, "assets_declare",
                        "Declare a single asset in the asset model")
        self._add_tool(server, self.assets_batch_declare, "assets_batch_declare",
                        "Declare multiple assets/properties in one batch")
        self._add_tool(server, self.assets_remove, "assets_remove",
                        "Remove an asset from the asset model")
        self._add_tool(server, self.assets_declare_properties, "assets_declare_properties",
                        "Set/update properties on an asset")
        # Asset groups
        self._add_tool(server, self.assets_list_groups, "assets_list_groups",
                        "List asset groups for an account")
        self._add_tool(server, self.assets_create_update_group, "assets_create_update_group",
                        "Create or update an asset group")
        self._add_tool(server, self.assets_delete_group, "assets_delete_group",
                        "Delete an asset group by key")
        # Fast asset lookup
        self._add_tool(server, self.assets_find, "assets_find",
                        "Fast lookup of a single asset by known identifier")
        self._add_tool(server, self.assets_find_batch, "assets_find_batch",
                        "Batch fast lookup of assets by known identifiers")
        # Asset details
        self._add_tool(server, self.assets_get_details, "assets_get_details",
                        "Get detailed network info for assets")
        self._add_tool(server, self.assets_get_details_post, "assets_get_details_post",
                        "Batch get detailed network info for assets via POST")
        # Account-wide query
        self._add_tool(server, self.assets_query_all, "assets_query_all",
                        "Query assets across ALL deployments (no deployment scope)")
        # Exposure variant
        self._add_tool(server, self.assets_get_exposures_post, "assets_get_exposures_post",
                        "POST variant of exposure query for complex filters")

    # ---- Query ----

    def assets_query(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID (get from deployments_list)")],
        asset_types: Annotated[Optional[str], Field(
            description="Comma-separated asset types (e.g., 'host,vpc,subnet')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """General asset query. GET /assets_query/v1/{account_id}/deployments/{deployment_id}/assets"""
        params = {}
        if asset_types:
            params["asset_types"] = asset_types
        return self._get(
            f"/assets_query/v1/{{account_id}}/deployments/{deployment_id}/assets",
            account_id=account_id,
            params=params or None,
        )

    def assets_get_topology(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        include_filters: Annotated[Optional[str], Field(
            description="Asset types to include (comma-separated)"
        )] = None,
        extras: Annotated[Optional[str], Field(
            description="Extra data to include (e.g., 'vulnerabilities')"
        )] = None,
    ) -> dict:
        """Topology query. GET /assets_query/v1/{account_id}/deployments/{deployment_id}/topology"""
        params = {}
        if include_filters:
            params["include_filters"] = include_filters
        if extras:
            params["extras"] = extras
        return self._get(
            f"/assets_query/v1/{{account_id}}/deployments/{deployment_id}/topology",
            account_id=account_id,
            params=params or None,
        )

    # ---- Write ----
    # All writes hit PUT /assets_write/v1/{account_id}/deployments/{deployment_id}/assets
    # with an `operation` discriminator in the body.

    def _write(self, deployment_id: str, body: dict, account_id: Optional[str]) -> dict:
        return self._put(
            f"/assets_write/v1/{{account_id}}/deployments/{deployment_id}/assets",
            account_id=account_id,
            json_body=body,
        )

    def assets_declare(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_type: Annotated[str, Field(description="Asset type (e.g., 'host')")],
        asset_key: Annotated[str, Field(description="Asset key (e.g., '/aws/us-west-2/host/i-123')")],
        scope: Annotated[Optional[str], Field(description="Asset scope (e.g., deployment scope key)")] = None,
        properties: Annotated[Optional[dict], Field(description="Asset properties")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Declare one asset. PUT /assets_write/v1/.../assets (operation=declare_asset)"""
        body = {"operation": "declare_asset", "type": asset_type, "key": asset_key}
        if scope is not None:
            body["scope"] = scope
        if properties is not None:
            body["properties"] = properties
        return self._write(deployment_id, body, account_id)

    def assets_batch_declare(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        operations: Annotated[List[dict], Field(
            description="List of operations: [{'operation': 'declare_asset', 'type': 'host', 'key': '/aws/...', ...}, ...]"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Batch declare. PUT /assets_write/v1/.../assets (operation=batch_declare)"""
        body = {"operation": "batch_declare", "operations": operations}
        return self._write(deployment_id, body, account_id)

    def assets_remove(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_type: Annotated[str, Field(description="Asset type")],
        asset_key: Annotated[str, Field(description="Asset key")],
        scope: Annotated[Optional[str], Field(description="Asset scope")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Remove an asset. PUT /assets_write/v1/.../assets (operation=remove_asset)"""
        body = {"operation": "remove_asset", "type": asset_type, "key": asset_key}
        if scope is not None:
            body["scope"] = scope
        return self._write(deployment_id, body, account_id)

    def assets_declare_properties(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        asset_type: Annotated[str, Field(description="Asset type")],
        asset_key: Annotated[str, Field(description="Asset key")],
        properties: Annotated[dict, Field(description="Properties to set")],
        scope: Annotated[Optional[str], Field(description="Asset scope")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Declare properties. PUT /assets_write/v1/.../assets (operation=declare_properties)"""
        body = {
            "operation": "declare_properties",
            "type": asset_type,
            "key": asset_key,
            "properties": properties,
        }
        if scope is not None:
            body["scope"] = scope
        return self._write(deployment_id, body, account_id)

    # ---- Asset Groups ----

    def assets_list_groups(
        self,
        deployment_id: Annotated[Optional[str], Field(description="Filter by deployment UUID")] = None,
        group_type: Annotated[Optional[str], Field(description="Filter by group type (e.g., 'user_defined')")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List asset groups. GET /assets_query/v1/{account_id}/asset_groups"""
        params = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        if group_type:
            params["group_type"] = group_type
        return self._get(
            "/assets_query/v1/{account_id}/asset_groups",
            account_id=account_id,
            params=params or None,
        )

    def assets_create_update_group(
        self,
        group_type: Annotated[str, Field(description="Group type (e.g., 'user_defined')")],
        name: Annotated[str, Field(description="Human-readable group name")],
        key: Annotated[str, Field(description="Unique group key")],
        assets: Annotated[List[dict], Field(
            description="Assets in the group: [{'type': 'host', 'key': '/aws/...'}, ...]"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create or update an asset group. PUT /assets_query/v1/{account_id}/asset_groups"""
        body = {
            "group_type": group_type,
            "name": name,
            "key": key,
            "assets": assets,
        }
        return self._put(
            "/assets_query/v1/{account_id}/asset_groups",
            account_id=account_id,
            json_body=body,
        )

    def assets_delete_group(
        self,
        group_key: Annotated[str, Field(description="The group key to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete an asset group. DELETE /assets_query/v1/{account_id}/asset_groups/{group_key}"""
        return self._delete(
            f"/assets_query/v1/{{account_id}}/asset_groups/{group_key}",
            account_id=account_id,
        )

    # ---- Fast Asset Lookup ----

    def assets_find(
        self,
        asset_type: Annotated[str, Field(description="Asset type to look up (e.g., 'host')")],
        key: Annotated[Optional[str], Field(description="Asset key")] = None,
        ip_address: Annotated[Optional[str], Field(description="IP address of the asset")] = None,
        external_id: Annotated[Optional[str], Field(description="External/cloud provider ID")] = None,
        name: Annotated[Optional[str], Field(description="Asset name")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Fast single-asset lookup by known identifier. GET /assets_query/v1/{account_id}/find"""
        params: dict = {"type": asset_type}
        if key:
            params["key"] = key
        if ip_address:
            params["ip_address"] = ip_address
        if external_id:
            params["external_id"] = external_id
        if name:
            params["name"] = name
        return self._get(
            "/assets_query/v1/{account_id}/find",
            account_id=account_id,
            params=params,
        )

    def assets_find_batch(
        self,
        lookups: Annotated[List[dict], Field(
            description="List of lookup objects: [{'type': 'host', 'ip_address': '10.0.0.1'}, ...]"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Batch fast asset lookup. POST /assets_query/v1/{account_id}/find"""
        return self._post(
            "/assets_query/v1/{account_id}/find",
            account_id=account_id,
            json_body=lookups,
        )

    # ---- Asset Details ----

    def assets_get_details(
        self,
        asset_type: Annotated[str, Field(description="Asset type (e.g., 'host')")],
        key: Annotated[str, Field(description="Asset key")],
        deployment_id: Annotated[Optional[str], Field(description="Filter by deployment UUID")] = None,
        scope: Annotated[Optional[str], Field(description="Optional scope filter")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get detailed network info for an asset. GET /assets_query/v1/{account_id}/details"""
        params: dict = {"type": asset_type, "key": key}
        if deployment_id:
            params["deployment_id"] = deployment_id
        if scope:
            params["scope"] = scope
        return self._get(
            "/assets_query/v1/{account_id}/details",
            account_id=account_id,
            params=params,
        )

    def assets_get_details_post(
        self,
        assets: Annotated[List[dict], Field(
            description="List of asset references: [{'type': 'host', 'key': '/aws/...'}, ...]"
        )],
        deployment_id: Annotated[Optional[str], Field(description="Filter by deployment UUID")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Batch get asset details via POST. POST /assets_query/v1/{account_id}/details"""
        body: dict = {"assets": assets}
        if deployment_id:
            body["deployment_id"] = deployment_id
        return self._post(
            "/assets_query/v1/{account_id}/details",
            account_id=account_id,
            json_body=body,
        )

    # ---- Account-wide Query ----

    def assets_query_all(
        self,
        asset_types: Annotated[Optional[str], Field(
            description="Comma-separated asset types (e.g., 'host,vpc')"
        )] = None,
        query_filters: Annotated[Optional[str], Field(
            description="Filter expression for asset properties"
        )] = None,
        return_types: Annotated[Optional[str], Field(
            description="Asset types to return in results"
        )] = None,
        qid: Annotated[Optional[str], Field(description="Query ID for pagination")] = None,
        extras: Annotated[Optional[str], Field(
            description="Extra data to include (e.g., 'vulnerabilities')"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Query assets across ALL deployments. GET /assets_query/v1/{account_id}/assets"""
        params = {}
        if asset_types:
            params["asset_types"] = asset_types
        if query_filters:
            params["query_filters"] = query_filters
        if return_types:
            params["return_types"] = return_types
        if qid:
            params["qid"] = qid
        if extras:
            params["extras"] = extras
        return self._get(
            "/assets_query/v1/{account_id}/assets",
            account_id=account_id,
            params=params or None,
        )

    # ---- Exposures (POST variant) ----

    def assets_get_exposures_post(
        self,
        asset_types: Annotated[Optional[str], Field(
            description="Comma-separated asset types to filter"
        )] = None,
        query_filters: Annotated[Optional[str], Field(
            description="Filter expression for exposures"
        )] = None,
        return_types: Annotated[Optional[str], Field(
            description="Asset types to return in results"
        )] = None,
        qid: Annotated[Optional[str], Field(description="Query ID for pagination")] = None,
        extras: Annotated[Optional[str], Field(
            description="Extra data to include"
        )] = None,
        deployment_id: Annotated[Optional[str], Field(description="Filter by deployment UUID")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST variant of exposure query (use for complex filters). POST /assets_query/v2/{account_id}/exposures"""
        body = {}
        if asset_types:
            body["asset_types"] = asset_types
        if query_filters:
            body["query_filters"] = query_filters
        if return_types:
            body["return_types"] = return_types
        if qid:
            body["qid"] = qid
        if extras:
            body["extras"] = extras
        if deployment_id:
            body["deployment_id"] = deployment_id
        return self._post(
            "/assets_query/v2/{account_id}/exposures",
            account_id=account_id,
            json_body=body,
        )


def setup(server: FastMCP):
    mod = AssetsModule()
    mod.register_tools(server)
