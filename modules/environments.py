"""
AlertLogic Environments (Legacy Cloud Insight).
Legacy CRUD surface for cloud environments (AWS accounts, Azure subscriptions)
that pre-dates the deployments/v1 API. Backed by sources/v1 with type=environment.
Also covers launcher/v1 (deployment status) and the scheduler/v1 scan-trigger
endpoints that the legacy CLI used alongside environments.

Still required for backwards-compat MSSP accounts that have not migrated to
the deployments API.

Official portal: https://console.cloudinsight.alertlogic.com/api/environments/
Sources API:     /sources/v1/{account_id}/sources
Launcher API:    /launcher/v1/{account_id}/environments/{deployment_id}
"""
from typing import Annotated, List, Literal, Optional

from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


DeploymentMode = Literal["automatic", "guided", "readonly", "manual", "none"]


class EnvironmentsModule(BaseModule):
    """Legacy environments management via sources/v1 and launcher/v1."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.environments_list, "environments_list",
                        "List cloud environments (legacy sources/v1). "
                        "Optionally filter by AWS account ID.")
        self._add_tool(server, self.environments_get, "environments_get",
                        "Get a specific environment (source) by ID.")
        self._add_tool(server, self.environments_create_aws, "environments_create_aws",
                        "Create a legacy AWS cloud environment linked to an IAM-role credential.")
        self._add_tool(server, self.environments_update, "environments_update",
                        "Update an existing environment (merge semantics — only supplied "
                        "fields are changed).")
        self._add_tool(server, self.environments_delete, "environments_delete",
                        "Delete a legacy cloud environment.")
        self._add_tool(server, self.environments_get_status, "environments_get_status",
                        "Get the deployment/launch status of a legacy environment "
                        "(launcher/v1).")
        self._add_tool(server, self.environments_list_resources, "environments_list_resources",
                        "List deployed resources for a legacy environment (launcher/v1).")
        self._add_tool(server, self.environments_trigger_scan, "environments_trigger_scan",
                        "Trigger an immediate vulnerability scan for an asset inside a "
                        "legacy environment (scheduler/v1).")
        self._add_tool(server, self.environments_list_scans, "environments_list_scans",
                        "List scheduled scans for a legacy environment (scheduler/v1).")
        self._add_tool(server, self.environments_get_scan_summary, "environments_get_scan_summary",
                        "Get scan coverage summary for a legacy environment, optionally "
                        "filtered by VPC (scheduler/v1).")

    # ------------------------------------------------------------------ #
    #  1. List environments                                                #
    # ------------------------------------------------------------------ #

    def environments_list(
        self,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID. Uses the configured default when omitted."
        )] = None,
        aws_account_id: Annotated[Optional[str], Field(
            description="Filter by AWS account ID (maps to "
                        "source.config.aws.account_id query filter)."
        )] = None,
        environment_id: Annotated[Optional[str], Field(
            description="Filter by specific environment (source) UUID."
        )] = None,
    ) -> dict:
        """List environments. GET /sources/v1/{account_id}/sources"""
        params: dict = {}
        if aws_account_id:
            params["source.config.aws.account_id"] = aws_account_id
        if environment_id:
            params["source.environment"] = environment_id
        return self._get(
            "/sources/v1/{account_id}/sources",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  2. Get environment                                                  #
    # ------------------------------------------------------------------ #

    def environments_get(
        self,
        environment_id: Annotated[str, Field(description="Environment (source) UUID.")],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Get environment by ID. GET /sources/v1/{account_id}/sources/{environment_id}"""
        return self._get(
            f"/sources/v1/{{account_id}}/sources/{environment_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  3. Create AWS environment                                           #
    # ------------------------------------------------------------------ #

    def environments_create_aws(
        self,
        name: Annotated[str, Field(description="Human-readable environment name.")],
        aws_account_id: Annotated[str, Field(
            description="AWS account ID that this environment represents."
        )],
        credential_id: Annotated[str, Field(
            description="UUID of an existing IAM-role credential "
                        "(create via credentials_create_iam_role)."
        )],
        mode: Annotated[DeploymentMode, Field(
            description="Deployment mode: automatic, guided, readonly, manual, or none."
        )] = "automatic",
        discover: Annotated[bool, Field(
            description="Enable asset discovery for this environment."
        )] = True,
        scan: Annotated[bool, Field(
            description="Enable vulnerability scanning for this environment."
        )] = True,
        scope_include: Annotated[Optional[List[str]], Field(
            description="Asset key paths to include in scope "
                        "(e.g. ['/aws/us-east-1']). Empty list means all regions."
        )] = None,
        scope_exclude: Annotated[Optional[List[str]], Field(
            description="Asset key paths to exclude from scope."
        )] = None,
        enabled: Annotated[bool, Field(description="Whether the environment is enabled.")] = True,
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Create AWS cloud environment. POST /sources/v1/{account_id}/sources"""
        scope: dict = {
            "include": scope_include or [],
            "exclude": scope_exclude or [],
        }
        body = {
            "source": {
                "name": name,
                "type": "environment",
                "enabled": enabled,
                "product_type": "outcomes",
                "tags": [],
                "config": {
                    "collection_method": "api",
                    "collection_type": "aws",
                    "aws": {
                        "account_id": aws_account_id,
                        "credential": {"id": credential_id},
                        "discover": discover,
                        "scan": scan,
                        "deployment_mode": mode,
                        "scope": scope,
                    },
                },
            }
        }
        return self._post(
            "/sources/v1/{account_id}/sources",
            account_id=account_id,
            json_body=body,
        )

    # ------------------------------------------------------------------ #
    #  4. Update environment (merge)                                       #
    # ------------------------------------------------------------------ #

    def environments_update(
        self,
        environment_id: Annotated[str, Field(description="Environment (source) UUID to update.")],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
        name: Annotated[Optional[str], Field(description="New environment name.")] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable or disable.")] = None,
        mode: Annotated[Optional[DeploymentMode], Field(
            description="New deployment mode: automatic, guided, readonly, manual, or none."
        )] = None,
        discover: Annotated[Optional[bool], Field(description="Toggle asset discovery.")] = None,
        scan: Annotated[Optional[bool], Field(description="Toggle vulnerability scanning.")] = None,
        scope_include: Annotated[Optional[List[str]], Field(
            description="Replacement include scope list (full replacement, not append)."
        )] = None,
        scope_exclude: Annotated[Optional[List[str]], Field(
            description="Replacement exclude scope list."
        )] = None,
        credential_id: Annotated[Optional[str], Field(
            description="Replace the linked IAM-role credential UUID."
        )] = None,
    ) -> dict:
        """Update environment (merge). POST /sources/v1/{account_id}/sources/{environment_id}"""
        # sources/v1 uses POST (not PUT) for partial updates — merge semantics.
        top: dict = {}
        aws: dict = {}

        if name is not None:
            top["name"] = name
        if enabled is not None:
            top["enabled"] = enabled
        if mode is not None:
            aws["deployment_mode"] = mode
        if discover is not None:
            aws["discover"] = discover
        if scan is not None:
            aws["scan"] = scan
        if credential_id is not None:
            aws["credential"] = {"id": credential_id}
        if scope_include is not None or scope_exclude is not None:
            scope: dict = {}
            if scope_include is not None:
                scope["include"] = scope_include
            if scope_exclude is not None:
                scope["exclude"] = scope_exclude
            aws["scope"] = scope

        config: dict = {}
        if aws:
            config["aws"] = aws

        source: dict = {**top}
        if config:
            source["config"] = config

        return self._post(
            f"/sources/v1/{{account_id}}/sources/{environment_id}",
            account_id=account_id,
            json_body={"source": source},
        )

    # ------------------------------------------------------------------ #
    #  5. Delete environment                                               #
    # ------------------------------------------------------------------ #

    def environments_delete(
        self,
        environment_id: Annotated[str, Field(description="Environment (source) UUID to delete.")],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Delete environment. DELETE /sources/v1/{account_id}/sources/{environment_id}"""
        return self._delete(
            f"/sources/v1/{{account_id}}/sources/{environment_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  6. Deployment status (launcher/v1)                                 #
    # ------------------------------------------------------------------ #

    def environments_get_status(
        self,
        environment_id: Annotated[str, Field(
            description="Environment UUID (same as source/deployment ID)."
        )],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Get environment deployment status. GET /launcher/v1/{account_id}/environments/{environment_id}"""
        return self._get(
            f"/launcher/v1/{{account_id}}/environments/{environment_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  7. List deployed resources (launcher/v1)                           #
    # ------------------------------------------------------------------ #

    def environments_list_resources(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID.")],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """List deployed resources. GET /launcher/v1/{account_id}/{environment_id}/resources"""
        return self._get(
            f"/launcher/v1/{{account_id}}/{environment_id}/resources",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  8. Trigger scan (scheduler/v1)                                     #
    # ------------------------------------------------------------------ #

    def environments_trigger_scan(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID.")],
        asset_key: Annotated[str, Field(
            description="Asset key to scan (e.g. '/aws/us-east-1/host/i-0abc123'). "
                        "Passed as the 'asset' query parameter."
        )],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Trigger immediate scan. PUT /scheduler/v1/{account_id}/{environment_id}/scan?asset={key}"""
        return self._put(
            f"/scheduler/v1/{{account_id}}/{environment_id}/scan",
            account_id=account_id,
            json_body=None,
        )

    # ------------------------------------------------------------------ #
    #  9. List scans (scheduler/v1)                                       #
    # ------------------------------------------------------------------ #

    def environments_list_scans(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID.")],
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """List scan schedule/status. GET /scheduler/v1/{account_id}/{environment_id}/list"""
        return self._get(
            f"/scheduler/v1/{{account_id}}/{environment_id}/list",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  10. Scan summary (scheduler/v1)                                    #
    # ------------------------------------------------------------------ #

    def environments_get_scan_summary(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID.")],
        vpc_key: Annotated[Optional[str], Field(
            description="Optional VPC key to scope the summary "
                        "(e.g. '/aws/us-east-1/vpc/vpc-abc123')."
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Alert Logic account ID.")] = None,
    ) -> dict:
        """Get scan summary. GET /scheduler/v1/{account_id}/{environment_id}/summary"""
        params = {}
        if vpc_key:
            params["vpc_key"] = vpc_key
        return self._get(
            f"/scheduler/v1/{{account_id}}/{environment_id}/summary",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = EnvironmentsModule()
    mod.register_tools(server)
