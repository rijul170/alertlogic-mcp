"""
AlertLogic Deployments Management.
Create, list, update, and delete deployments (AWS, Azure, Datacenter).

Official API: https://console.cloudinsight.alertlogic.com/api/deployments/
"""
from typing import Annotated, Optional, List
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class DeploymentsModule(BaseModule):
    """Deployment lifecycle management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.deployments_list, "deployments_list",
                        "List all deployments for an account")
        self._add_tool(server, self.deployments_get, "deployments_get",
                        "Get a specific deployment by ID")
        self._add_tool(server, self.deployments_create, "deployments_create",
                        "Create a new deployment (AWS/Azure/Datacenter)")
        self._add_tool(server, self.deployments_update, "deployments_update",
                        "Update an existing deployment")
        self._add_tool(server, self.deployments_delete, "deployments_delete",
                        "Delete a deployment")

    def deployments_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List deployments. GET /deployments/v1/{account_id}/deployments"""
        return self._get("/deployments/v1/{account_id}/deployments", account_id=account_id)

    def deployments_get(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get deployment. GET /deployments/v1/{account_id}/deployments/{deployment_id}"""
        return self._get(
            f"/deployments/v1/{{account_id}}/deployments/{deployment_id}",
            account_id=account_id,
        )

    def deployments_create(
        self,
        name: Annotated[str, Field(description="Deployment name")],
        platform_type: Annotated[str, Field(description="Platform: 'aws', 'azure', or 'datacenter'")],
        platform_id: Annotated[Optional[str], Field(
            description="Platform-specific ID (AWS account ID or Azure subscription ID)"
        )] = None,
        mode: Annotated[str, Field(
            description="Mode: 'automatic', 'guided', 'readonly', 'manual', or 'none'"
        )] = "automatic",
        enabled: Annotated[bool, Field(description="Whether deployment is enabled")] = True,
        discover: Annotated[bool, Field(description="Whether deployment is discovered")] = True,
        scan: Annotated[bool, Field(description="Whether deployment is scanned")] = True,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create deployment. POST /deployments/v1/{account_id}/deployments"""
        body = {
            "name": name,
            "platform": {"type": platform_type},
            "mode": mode,
            "enabled": enabled,
            "discover": discover,
            "scan": scan,
        }
        if platform_id:
            body["platform"]["id"] = platform_id
        return self._post(
            "/deployments/v1/{account_id}/deployments",
            account_id=account_id,
            json_body=body,
        )

    def deployments_update(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        name: Annotated[Optional[str], Field(description="New name")] = None,
        mode: Annotated[Optional[str], Field(description="New mode")] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable/disable")] = None,
        discover: Annotated[Optional[bool], Field(description="Enable/disable discovery")] = None,
        scan: Annotated[Optional[bool], Field(description="Enable/disable scanning")] = None,
        scope: Annotated[Optional[dict], Field(
            description="Protection scope: {'include': [...], 'exclude': [...]} where each item is {'type': '...', 'key': '...'}"
        )] = None,
        policy_id: Annotated[Optional[str], Field(
            description="Outcomes policy UUID to attach to this deployment"
        )] = None,
    ) -> dict:
        """Update deployment. PUT /deployments/v1/{account_id}/deployments/{deployment_id}"""
        body = {}
        if name is not None:
            body["name"] = name
        if mode is not None:
            body["mode"] = mode
        if enabled is not None:
            body["enabled"] = enabled
        if discover is not None:
            body["discover"] = discover
        if scan is not None:
            body["scan"] = scan
        if scope is not None:
            body["scope"] = scope
        if policy_id is not None:
            body["policy"] = {"id": policy_id}
        return self._put(
            f"/deployments/v1/{{account_id}}/deployments/{deployment_id}",
            account_id=account_id,
            json_body=body,
        )

    def deployments_delete(
        self,
        deployment_id: Annotated[str, Field(description="Deployment UUID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete deployment. DELETE /deployments/v1/{account_id}/deployments/{deployment_id}"""
        return self._delete(
            f"/deployments/v1/{{account_id}}/deployments/{deployment_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = DeploymentsModule()
    mod.register_tools(server)