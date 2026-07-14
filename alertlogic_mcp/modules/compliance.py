"""
AlertLogic Compliance & Remediations.
Track and act on remediations via assets_query v2.

Spec: assets_query.v2 (PUT /assets_query/v2/{account_id}/remediations,
       GET /assets_query/v2/{account_id}/remediation-items)
"""
from typing import Annotated, Any, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


# Operation names per assets_query v2 spec.
RemediationOp = Literal[
    "conclude_remediations",
    "dispose_remediations",
    "undispose_remediations",
]


class ComplianceModule(BaseModule):
    """Remediation tracking and bulk state changes."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.remediation_items_list, "remediation_items_list",
                        "List remediation items, optionally filtered by deployment")
        self._add_tool(server, self.remediations_conclude, "remediations_conclude",
                        "Mark remediations as concluded (replaces 'complete')")
        self._add_tool(server, self.remediations_dispose, "remediations_dispose",
                        "Dispose remediations (accept risk) with a reason")
        self._add_tool(server, self.remediations_undispose, "remediations_undispose",
                        "Reverse a previous dispose (replaces 'uncomplete')")

    def remediation_items_list(
        self,
        deployment_id: Annotated[Optional[str], Field(
            description="Filter to a single deployment UUID"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List remediation items. GET /assets_query/v2/{account_id}/remediation-items"""
        params = {}
        if deployment_id:
            params["deployment_ids"] = deployment_id
        return self._get(
            "/assets_query/v2/{account_id}/remediation-items",
            account_id=account_id,
            params=params or None,
        )

    def _remediation_op(
        self,
        operation: RemediationOp,
        filters: List[str],
        account_id: Optional[str],
        remediation_ids: Optional[List[str]] = None,
        vulnerability_ids: Optional[List[str]] = None,
        reason: Optional[str] = None,
        comment: Optional[str] = None,
        deployment_ids: Optional[List[str]] = None,
    ) -> dict:
        body: dict = {"operation": operation, "filters": filters}
        if remediation_ids:
            body["remediation_ids"] = remediation_ids
        if vulnerability_ids:
            body["vulnerability_ids"] = vulnerability_ids
        if reason is not None:
            body["reason"] = reason
        if comment is not None:
            body["comment"] = comment
        if deployment_ids:
            body["deployment_ids"] = deployment_ids
        return self._put(
            "/assets_query/v2/{account_id}/remediations",
            account_id=account_id,
            json_body=body,
        )

    def remediations_conclude(
        self,
        filters: Annotated[List[str], Field(
            description="Filter strings (required, can be empty list); e.g. ['deployment_id:abc123']"
        )],
        remediation_ids: Annotated[Optional[List[str]], Field(
            description="Specific remediation IDs to conclude (alternative to vulnerability_ids)"
        )] = None,
        vulnerability_ids: Annotated[Optional[List[str]], Field(
            description="Vulnerability IDs whose remediations to conclude"
        )] = None,
        deployment_ids: Annotated[Optional[List[str]], Field(
            description="Optional deployment scope"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Conclude. PUT /assets_query/v2/{account_id}/remediations"""
        return self._remediation_op(
            "conclude_remediations", filters, account_id,
            remediation_ids=remediation_ids,
            vulnerability_ids=vulnerability_ids,
            deployment_ids=deployment_ids,
        )

    def remediations_dispose(
        self,
        filters: Annotated[List[str], Field(
            description="Filter strings (required, can be empty list)"
        )],
        reason: Annotated[str, Field(
            description="Disposal reason (must match server enum: e.g. 'compensating_control', 'acceptable_risk', 'false_positive')"
        )],
        comment: Annotated[str, Field(description="Audit-trail comment (required)")],
        remediation_ids: Annotated[Optional[List[str]], Field(
            description="Specific remediation IDs (alternative to vulnerability_ids)"
        )] = None,
        vulnerability_ids: Annotated[Optional[List[str]], Field(
            description="Vulnerability IDs to dispose"
        )] = None,
        deployment_ids: Annotated[Optional[List[str]], Field(description="Optional deployment scope")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Dispose. PUT /assets_query/v2/{account_id}/remediations"""
        return self._remediation_op(
            "dispose_remediations", filters, account_id,
            remediation_ids=remediation_ids,
            vulnerability_ids=vulnerability_ids,
            reason=reason, comment=comment,
            deployment_ids=deployment_ids,
        )

    def remediations_undispose(
        self,
        filters: Annotated[List[str], Field(description="Filter strings (required, can be empty list)")],
        remediation_ids: Annotated[Optional[List[str]], Field(description="Specific remediation IDs")] = None,
        vulnerability_ids: Annotated[Optional[List[str]], Field(description="Vulnerability IDs")] = None,
        deployment_ids: Annotated[Optional[List[str]], Field(description="Optional deployment scope")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Undispose. PUT /assets_query/v2/{account_id}/remediations"""
        return self._remediation_op(
            "undispose_remediations", filters, account_id,
            remediation_ids=remediation_ids,
            vulnerability_ids=vulnerability_ids,
            deployment_ids=deployment_ids,
        )



def setup(server: FastMCP):
    mod = ComplianceModule()
    mod.register_tools(server)
