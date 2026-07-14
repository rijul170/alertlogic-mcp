"""
AlertLogic Vulnerability & Remediation Knowledge Base.
CRUD operations for vulnerability and remediation *definitions* in the
vulnerabilities.v1 service.

These are global knowledge-base records (no account_id in the path).
For operational exposure queries against discovered assets, see vulnerability.py
(assets_query/v2/exposures).

Official API: https://console.cloudinsight.alertlogic.com/api/vulnerabilities/
"""
from typing import Annotated, Any, Dict, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class VulnerabilitiesKBModule(BaseModule):
    """
    Vulnerability and remediation knowledge-base management.

    Covers GET/POST/batch for /vulnerability/v1 and /remediation/v1.
    Paths are not account-scoped — requests go directly to the default
    base URL without any {account_id} substitution.
    """

    def register_tools(self, server: FastMCP):
        # Vulnerability KB tools
        self._add_tool(server, self.vuln_kb_get, "vuln_kb_get",
                       "Get a vulnerability definition by ID from the knowledge base")
        self._add_tool(server, self.vuln_kb_list, "vuln_kb_list",
                       "List or search vulnerability definitions in the knowledge base")
        self._add_tool(server, self.vuln_kb_create, "vuln_kb_create",
                       "Create a vulnerability definition in the knowledge base (privileged)")
        self._add_tool(server, self.vuln_kb_batch_create, "vuln_kb_batch_create",
                       "Batch-create multiple vulnerability definitions (privileged)")

        # Remediation KB tools
        self._add_tool(server, self.remediation_kb_get, "remediation_kb_get",
                       "Get a remediation definition by ID from the knowledge base")
        self._add_tool(server, self.remediation_kb_list, "remediation_kb_list",
                       "List or search remediation definitions in the knowledge base")
        self._add_tool(server, self.remediation_kb_update, "remediation_kb_update",
                       "Update a remediation definition in the knowledge base (privileged)")
        self._add_tool(server, self.remediation_kb_create, "remediation_kb_create",
                       "Create a remediation definition in the knowledge base (privileged)")
        self._add_tool(server, self.remediation_kb_batch_create, "remediation_kb_batch_create",
                       "Batch-create multiple remediation definitions (privileged)")

    # ------------------------------------------------------------------ #
    #  Vulnerability KB                                                   #
    # ------------------------------------------------------------------ #

    def vuln_kb_get(
        self,
        vulnerability_id: Annotated[str, Field(description="Vulnerability ID (e.g. 'CVE-2021-44228' or an internal ID)")],
    ) -> dict:
        """Get a single vulnerability definition. GET /vulnerability/v1/{vulnerability_id}"""
        return self._request("GET", f"/vulnerability/v1/{vulnerability_id}")

    def vuln_kb_list(
        self,
        page_size: Annotated[Optional[int], Field(description="Number of results per page")] = None,
        page_num: Annotated[Optional[int], Field(description="Page number (0-indexed)")] = None,
        sort_by: Annotated[Optional[str], Field(
            description="Field to sort by (e.g. 'cvss_score', 'id')"
        )] = None,
        sort_order: Annotated[Optional[str], Field(
            description="Sort direction: 'asc' or 'desc'"
        )] = None,
        filter: Annotated[Optional[str], Field(
            description="Filter expression for narrowing results (service-specific syntax)"
        )] = None,
    ) -> dict:
        """List/search vulnerability definitions. GET /vulnerability/v1"""
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["page_size"] = page_size
        if page_num is not None:
            params["page_num"] = page_num
        if sort_by is not None:
            params["sort_by"] = sort_by
        if sort_order is not None:
            params["sort_order"] = sort_order
        if filter is not None:
            params["filter"] = filter
        return self._request("GET", "/vulnerability/v1", params=params)

    def vuln_kb_create(
        self,
        vulnerability_id: Annotated[str, Field(description="Unique vulnerability ID (e.g. CVE ID or internal ID)")],
        name: Annotated[str, Field(description="Short name / title of the vulnerability")],
        description: Annotated[Optional[str], Field(description="Full description of the vulnerability")] = None,
        severity: Annotated[Optional[str], Field(
            description="Severity level: 'info', 'low', 'medium', 'high', or 'critical'"
        )] = None,
        cvss_score: Annotated[Optional[float], Field(description="CVSS base score (0.0 – 10.0)")] = None,
        cvss_vector: Annotated[Optional[str], Field(description="CVSS vector string")] = None,
        remediation_ids: Annotated[Optional[List[str]], Field(
            description="List of associated remediation IDs"
        )] = None,
        affected_software: Annotated[Optional[List[Dict[str, Any]]], Field(
            description="List of affected software objects (vendor/product/version metadata)"
        )] = None,
        references: Annotated[Optional[List[str]], Field(
            description="List of reference URLs (NVD, vendor advisories, etc.)"
        )] = None,
        extra_fields: Annotated[Optional[Dict[str, Any]], Field(
            description="Any additional top-level fields to include in the vulnerability definition body"
        )] = None,
    ) -> dict:
        """Create a vulnerability definition. POST /vulnerability/v1"""
        body: Dict[str, Any] = {"id": vulnerability_id, "name": name}
        if description is not None:
            body["description"] = description
        if severity is not None:
            body["severity"] = severity
        if cvss_score is not None:
            body["cvss_score"] = cvss_score
        if cvss_vector is not None:
            body["cvss_vector"] = cvss_vector
        if remediation_ids is not None:
            body["remediation_ids"] = remediation_ids
        if affected_software is not None:
            body["affected_software"] = affected_software
        if references is not None:
            body["references"] = references
        if extra_fields:
            body.update(extra_fields)
        return self._request("POST", "/vulnerability/v1", json_body=body)

    def vuln_kb_batch_create(
        self,
        vulnerabilities: Annotated[List[Dict[str, Any]], Field(
            description=(
                "List of vulnerability definition objects to create. Each object should contain "
                "at minimum 'id' and 'name', and optionally 'description', 'severity', "
                "'cvss_score', 'cvss_vector', 'remediation_ids', 'affected_software', and 'references'."
            )
        )],
    ) -> dict:
        """Batch-create vulnerability definitions. POST /vulnerability/v1/batch"""
        return self._request("POST", "/vulnerability/v1/batch", json_body=vulnerabilities)

    # ------------------------------------------------------------------ #
    #  Remediation KB                                                     #
    # ------------------------------------------------------------------ #

    def remediation_kb_get(
        self,
        remediation_id: Annotated[str, Field(description="Remediation definition ID")],
    ) -> dict:
        """Get a single remediation definition. GET /remediation/v1/{remediation_id}"""
        return self._request("GET", f"/remediation/v1/{remediation_id}")

    def remediation_kb_list(
        self,
        page_size: Annotated[Optional[int], Field(description="Number of results per page")] = None,
        page_num: Annotated[Optional[int], Field(description="Page number (0-indexed)")] = None,
        sort_by: Annotated[Optional[str], Field(
            description="Field to sort by (e.g. 'name', 'id')"
        )] = None,
        sort_order: Annotated[Optional[str], Field(
            description="Sort direction: 'asc' or 'desc'"
        )] = None,
        filter: Annotated[Optional[str], Field(
            description="Filter expression for narrowing results (service-specific syntax)"
        )] = None,
    ) -> dict:
        """List/search remediation definitions. GET /remediation/v1"""
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["page_size"] = page_size
        if page_num is not None:
            params["page_num"] = page_num
        if sort_by is not None:
            params["sort_by"] = sort_by
        if sort_order is not None:
            params["sort_order"] = sort_order
        if filter is not None:
            params["filter"] = filter
        return self._request("GET", "/remediation/v1", params=params)

    def remediation_kb_update(
        self,
        remediation_id: Annotated[str, Field(description="Remediation definition ID to update")],
        name: Annotated[Optional[str], Field(description="Updated name / title")] = None,
        description: Annotated[Optional[str], Field(description="Updated description")] = None,
        resolution: Annotated[Optional[str], Field(
            description="Updated resolution / fix instructions"
        )] = None,
        references: Annotated[Optional[List[str]], Field(
            description="Updated list of reference URLs"
        )] = None,
        extra_fields: Annotated[Optional[Dict[str, Any]], Field(
            description="Any additional top-level fields to include in the update body"
        )] = None,
    ) -> dict:
        """Update a remediation definition. POST /remediation/v1/{remediation_id}"""
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if resolution is not None:
            body["resolution"] = resolution
        if references is not None:
            body["references"] = references
        if extra_fields:
            body.update(extra_fields)
        return self._request("POST", f"/remediation/v1/{remediation_id}", json_body=body)

    def remediation_kb_create(
        self,
        remediation_id: Annotated[str, Field(description="Unique remediation definition ID")],
        name: Annotated[str, Field(description="Short name / title of the remediation")],
        description: Annotated[Optional[str], Field(description="Full description of the remediation")] = None,
        resolution: Annotated[Optional[str], Field(
            description="Resolution steps / fix instructions"
        )] = None,
        references: Annotated[Optional[List[str]], Field(
            description="List of reference URLs (vendor advisories, patches, etc.)"
        )] = None,
        extra_fields: Annotated[Optional[Dict[str, Any]], Field(
            description="Any additional top-level fields to include in the remediation definition body"
        )] = None,
    ) -> dict:
        """Create a remediation definition. POST /remediation/v1"""
        body: Dict[str, Any] = {"id": remediation_id, "name": name}
        if description is not None:
            body["description"] = description
        if resolution is not None:
            body["resolution"] = resolution
        if references is not None:
            body["references"] = references
        if extra_fields:
            body.update(extra_fields)
        return self._request("POST", "/remediation/v1", json_body=body)

    def remediation_kb_batch_create(
        self,
        remediations: Annotated[List[Dict[str, Any]], Field(
            description=(
                "List of remediation definition objects to create. Each object should contain "
                "at minimum 'id' and 'name', and optionally 'description', 'resolution', "
                "and 'references'."
            )
        )],
    ) -> dict:
        """Batch-create remediation definitions. POST /remediation/v1/batch"""
        return self._request("POST", "/remediation/v1/batch", json_body=remediations)


def setup(server: FastMCP):
    mod = VulnerabilitiesKBModule()
    mod.register_tools(server)
