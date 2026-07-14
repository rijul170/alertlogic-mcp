"""
AlertLogic Assets Manager service.

Spec: assets_manager.v1.yaml (OpenAPI 3.0.1)
Source: https://raw.githubusercontent.com/alertlogic/alertlogic-sdk-definitions/master/alsdkdefs/apis/assets_manager/assets_manager.v1.yaml

This service provides an additional validation layer in front of assets to ensure
user-supplied configuration is consistent. It handles:
  - Protection scope export/import (CSV or JSON)
  - Network create/update with CIDR validation

Endpoints
---------
POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/scope/export
POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/scope/import
POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/networks
PUT  /assets_manager/v1/{account_id}/deployments/{deployment_id}/networks/{network_uuid}

Protection-level policy ID mapping
------------------------------------
D12D5E67-166C-474F-87AA-6F86FC9FB9BC  →  professional
A8E8B104-8F45-411D-A240-A30EA5FE25B0  →  essentials
EC735B49-2517-4D98-BB9D-BEBC1E75D56D  →  enterprise
A562D3E4-ECBE-426E-B2CF-78D2336E5D63  →  lm_essentials
7E184449-FB15-4693-807F-C01A1ECD7E66  →  lmpro
D2A589A9-EA56-456C-844E-65843B483D68  →  tmpro
"""

from typing import Annotated, List, Optional

from mcp.server import FastMCP
from pydantic import Field

from alertlogic_mcp.modules.base import BaseModule

# Human-readable name → policy UUID
PROTECTION_LEVEL_IDS: dict[str, str] = {
    "professional":  "D12D5E67-166C-474F-87AA-6F86FC9FB9BC",
    "essentials":    "A8E8B104-8F45-411D-A240-A30EA5FE25B0",
    "enterprise":    "EC735B49-2517-4D98-BB9D-BEBC1E75D56D",
    "lm_essentials": "A562D3E4-ECBE-426E-B2CF-78D2336E5D63",
    "lmpro":         "7E184449-FB15-4693-807F-C01A1ECD7E66",
    "tmpro":         "D2A589A9-EA56-456C-844E-65843B483D68",
}


class AssetsManagerModule(BaseModule):
    """Wraps the Alert Logic assets_manager v1 API."""

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.assets_manager_export_scope,
            "assets_manager_export_scope",
            "Export the protection scope of a deployment (returns JSON list of assets with protection levels).",
        )
        self._add_tool(
            server,
            self.assets_manager_import_scope,
            "assets_manager_import_scope",
            (
                "Import/apply a protection scope to a deployment. "
                "Supports dry-run (write=False, default) or live write (write=True). "
                "Accepts a list of asset-protection dicts with keys: type, key, protection_level."
            ),
        )
        self._add_tool(
            server,
            self.assets_manager_create_network,
            "assets_manager_create_network",
            "Create a new network asset in a deployment with CIDR validation.",
        )
        self._add_tool(
            server,
            self.assets_manager_update_network,
            "assets_manager_update_network",
            "Update an existing network asset (name, CIDR ranges, span-port setting) in a deployment.",
        )
        self._add_tool(
            server,
            self.assets_manager_list_protection_levels,
            "assets_manager_list_protection_levels",
            "Return the mapping of protection level names to their policy UUIDs (reference tool, no API call).",
        )

    # ------------------------------------------------------------------
    # Protection Scope
    # ------------------------------------------------------------------

    def assets_manager_export_scope(
        self,
        deployment_id: Annotated[
            str,
            Field(description="Deployment UUID (uppercase, from deployments_list)."),
        ],
        account_id: Annotated[
            Optional[str],
            Field(description="AIMS account ID. Defaults to ALERTLOGIC_ACCOUNT_ID env var."),
        ] = None,
    ) -> dict:
        """
        Export protection scope.

        POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/scope/export

        Returns a JSON list of AssetProtection objects. Each entry has:
          type, key, protection_level, name (optional), cidr_block (optional),
          region (optional), network (optional), cidr_ranges (optional).

        Protection levels: professional, essentials, enterprise,
                           lm_essentials, lmpro, tmpro, excluded, inherited.
        """
        return self._request(
            "POST",
            f"/assets_manager/v1/{{account_id}}/deployments/{deployment_id}/scope/export",
            account_id=account_id,
        )

    def assets_manager_import_scope(
        self,
        deployment_id: Annotated[
            str,
            Field(description="Deployment UUID (uppercase)."),
        ],
        scope_items: Annotated[
            List[dict],
            Field(
                description=(
                    "List of asset-protection objects. Each must have: "
                    "'type' (e.g. 'vpc', 'subnet', 'host'), "
                    "'key' (e.g. '/aws/us-west-2/vpc/vpc-abc123'), "
                    "'protection_level' (one of: professional, essentials, enterprise, "
                    "lm_essentials, lmpro, tmpro, excluded, inherited). "
                    "All other fields are ignored."
                )
            ),
        ],
        write: Annotated[
            bool,
            Field(
                description=(
                    "If False (default) the endpoint runs in dry-run mode and returns "
                    "what would change without persisting. Set True to apply the scope."
                )
            ),
        ] = False,
        account_id: Annotated[
            Optional[str],
            Field(description="AIMS account ID. Defaults to ALERTLOGIC_ACCOUNT_ID env var."),
        ] = None,
    ) -> dict:
        """
        Import protection scope.

        POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/scope/import?write={write}

        Returns an ImportSummary with three lists:
          included  - assets now protected by this request
          excluded  - assets no longer protected
          new_scope - the complete new protection scope
        """
        params = {"write": str(write).lower()}
        return self._request(
            "POST",
            f"/assets_manager/v1/{{account_id}}/deployments/{deployment_id}/scope/import",
            account_id=account_id,
            params=params,
            json_body=scope_items,
        )

    # ------------------------------------------------------------------
    # Network Operations
    # ------------------------------------------------------------------

    def assets_manager_create_network(
        self,
        deployment_id: Annotated[
            str,
            Field(description="Deployment UUID (uppercase)."),
        ],
        network_name: Annotated[
            str,
            Field(description="Human-readable name for the new network."),
        ],
        cidr_ranges: Annotated[
            List[str],
            Field(
                description=(
                    "One or more CIDR blocks for the network (e.g. ['10.0.0.0/16']). "
                    "Required — at least one entry."
                )
            ),
        ],
        public_cidr_ranges: Annotated[
            Optional[List[str]],
            Field(
                description="Optional list of public CIDR blocks within the network."
            ),
        ] = None,
        span_port_enabled: Annotated[
            bool,
            Field(description="Enable span-port for this network. Defaults to False."),
        ] = False,
        force_large_network: Annotated[
            bool,
            Field(
                description=(
                    "Suppress validation that rejects networks too large for timely "
                    "appliance discovery scans. Defaults to False."
                )
            ),
        ] = False,
        account_id: Annotated[
            Optional[str],
            Field(description="AIMS account ID. Defaults to ALERTLOGIC_ACCOUNT_ID env var."),
        ] = None,
    ) -> dict:
        """
        Create a network asset.

        POST /assets_manager/v1/{account_id}/deployments/{deployment_id}/networks

        Returns a Network object with:
          key, network_name, network_uuid, cidr_ranges, claim_key,
          public_cidr_ranges (optional), span_port_enabled.

        Error 400 with code 'too_large_network' if CIDR range is too large
        (use force_large_network=True to override).
        """
        params = {"force_large_network": str(force_large_network).lower()}
        body: dict = {
            "network_name": network_name,
            "cidr_ranges": cidr_ranges,
            "span_port_enabled": span_port_enabled,
        }
        if public_cidr_ranges is not None:
            body["public_cidr_ranges"] = public_cidr_ranges
        return self._request(
            "POST",
            f"/assets_manager/v1/{{account_id}}/deployments/{deployment_id}/networks",
            account_id=account_id,
            params=params,
            json_body=body,
        )

    def assets_manager_update_network(
        self,
        deployment_id: Annotated[
            str,
            Field(description="Deployment UUID (uppercase)."),
        ],
        network_uuid: Annotated[
            str,
            Field(description="UUID of the network asset to update (uppercase)."),
        ],
        network_name: Annotated[
            Optional[str],
            Field(description="New human-readable name for the network."),
        ] = None,
        cidr_ranges: Annotated[
            Optional[List[str]],
            Field(description="Replacement list of CIDR blocks (e.g. ['10.0.0.0/16', '10.1.0.0/16'])."),
        ] = None,
        public_cidr_ranges: Annotated[
            Optional[List[str]],
            Field(description="Replacement list of public CIDR blocks."),
        ] = None,
        span_port_enabled: Annotated[
            Optional[bool],
            Field(description="Enable or disable span-port for this network."),
        ] = None,
        force_large_network: Annotated[
            bool,
            Field(
                description=(
                    "Suppress large-network CIDR validation. Defaults to False."
                )
            ),
        ] = False,
        account_id: Annotated[
            Optional[str],
            Field(description="AIMS account ID. Defaults to ALERTLOGIC_ACCOUNT_ID env var."),
        ] = None,
    ) -> dict:
        """
        Update an existing network asset.

        PUT /assets_manager/v1/{account_id}/deployments/{deployment_id}/networks/{network_uuid}

        Only fields provided in the request body are updated. Returns the updated
        Network object on success. Error 400 with code 'too_large_network' if the
        new CIDR is too wide (use force_large_network=True to override).
        """
        params = {"force_large_network": str(force_large_network).lower()}
        body: dict = {}
        if network_name is not None:
            body["network_name"] = network_name
        if cidr_ranges is not None:
            body["cidr_ranges"] = cidr_ranges
        if public_cidr_ranges is not None:
            body["public_cidr_ranges"] = public_cidr_ranges
        if span_port_enabled is not None:
            body["span_port_enabled"] = span_port_enabled
        return self._request(
            "PUT",
            f"/assets_manager/v1/{{account_id}}/deployments/{deployment_id}/networks/{network_uuid}",
            account_id=account_id,
            params=params,
            json_body=body,
        )

    # ------------------------------------------------------------------
    # Reference / helper (no API call)
    # ------------------------------------------------------------------

    def assets_manager_list_protection_levels(self) -> dict:
        """
        Return the protection-level name → policy UUID mapping (offline reference).

        Use these UUIDs when constructing scope items for assets_manager_import_scope
        or when interpreting raw API responses that return policy IDs rather than
        human-readable names.
        """
        return {
            "status_code": 200,
            "data": {
                "protection_levels": PROTECTION_LEVEL_IDS,
                "note": (
                    "Additional non-policy levels returned by export: "
                    "'excluded' (asset explicitly removed from scope), "
                    "'inherited' (asset inherits parent's policy)."
                ),
            },
        }


def setup(server: FastMCP) -> None:
    mod = AssetsManagerModule()
    mod.register_tools(server)
