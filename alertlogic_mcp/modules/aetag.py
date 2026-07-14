"""
AlertLogic Analytics Engine Tagset Service (AETAG).
Manages tagset definitions and tuning tagsets used by the analytics engine to
classify and annotate observations, detections, and analytics content.

Tagsets are key-value stores that enrich analytics output (e.g., MITRE ATT&CK
mappings, severity labels, visibility settings). Tuning tagsets control
analytic thresholds and suppression.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/aetag/aetag.v1.yaml
Host: api.global-services.global.alertlogic.com
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


class AetagModule(BaseModule):
    """
    Analytics Engine Tagset (AETAG) service.

    Three resource types:
      - Tagsets      — key-value tag definitions applied to analytics content
      - Tunings      — customer-specific threshold/suppression adjustments
      - Definitions  — schema definitions for tag keys/values
    Both global (platform-wide) and account-scoped variants are supported.
    """

    def register_tools(self, server: FastMCP):
        # ---- Audit ----
        self._add_tool(server, self.aetag_get_audit, "aetag_get_audit",
                       "Get AETAG audit — active content items at a given timestamp")

        # ---- Global tagsets ----
        self._add_tool(server, self.aetag_get_global_tagsets, "aetag_get_global_tagsets",
                       "List all global tagset definitions")
        self._add_tool(server, self.aetag_get_global_tagset_by_path,
                       "aetag_get_global_tagset_by_path",
                       "Get a global tagset definition by its path")
        self._add_tool(server, self.aetag_get_tagset_by_id, "aetag_get_tagset_by_id",
                       "Get any tagset definition by its UUID")
        self._add_tool(server, self.aetag_create_global_tagset, "aetag_create_global_tagset",
                       "Create or update a global tagset definition")
        self._add_tool(server, self.aetag_validate_tagset, "aetag_validate_tagset",
                       "Validate a tagset definition before creating it")

        # ---- Account tagsets ----
        self._add_tool(server, self.aetag_get_tagsets, "aetag_get_tagsets",
                       "List all tagset definitions for an account")
        self._add_tool(server, self.aetag_get_tagset_by_path, "aetag_get_tagset_by_path",
                       "Get an account-scoped tagset by path")
        self._add_tool(server, self.aetag_create_tagset, "aetag_create_tagset",
                       "Create or update an account-scoped tagset")
        self._add_tool(server, self.aetag_lookup_tagset, "aetag_lookup_tagset",
                       "Lookup keys or values in account tagsets or tuning paths")

        # ---- Global tuning tagsets ----
        self._add_tool(server, self.aetag_get_global_tuning_by_path,
                       "aetag_get_global_tuning_by_path",
                       "Get a global tuning tagset by path")
        self._add_tool(server, self.aetag_create_global_tuning,
                       "aetag_create_global_tuning",
                       "Create or update a global tuning tagset")
        self._add_tool(server, self.aetag_validate_tuning, "aetag_validate_tuning",
                       "Validate a tuning tagset definition before creating it")

        # ---- Account tuning tagsets ----
        self._add_tool(server, self.aetag_get_tuning_by_path, "aetag_get_tuning_by_path",
                       "Get an account-scoped tuning tagset by path")
        self._add_tool(server, self.aetag_create_tuning, "aetag_create_tuning",
                       "Create or update an account-scoped tuning tagset")

        # ---- Definitions ----
        self._add_tool(server, self.aetag_get_definitions, "aetag_get_definitions",
                       "List all tagset key/value schema definitions")
        self._add_tool(server, self.aetag_get_definition_by_path,
                       "aetag_get_definition_by_path",
                       "Get a tagset schema definition by path")
        self._add_tool(server, self.aetag_get_definition_by_id,
                       "aetag_get_definition_by_id",
                       "Get a tagset schema definition by UUID")
        self._add_tool(server, self.aetag_create_definition, "aetag_create_definition",
                       "Create a new tagset schema definition")
        self._add_tool(server, self.aetag_validate_definition, "aetag_validate_definition",
                       "Validate a tagset schema definition before creating it")

        # ---- Tuning metadata ----
        self._add_tool(server, self.aetag_get_tuning_for_account_ids,
                       "aetag_get_tuning_for_account_ids",
                       "Get tuning metadata for all account IDs")
        self._add_tool(server, self.aetag_get_tuning_for_tagset,
                       "aetag_get_tuning_for_tagset",
                       "Get tuning metadata for a specific tagset path")
        self._add_tool(server, self.aetag_get_tuning_for_analytic,
                       "aetag_get_tuning_for_analytic",
                       "Get tuning information for a specific analytic path")

    # ------------------------------------------------------------------ #
    #  Audit                                                               #
    # ------------------------------------------------------------------ #

    def aetag_get_audit(
        self,
        ts: Annotated[Optional[int], Field(
            description="Unix epoch timestamp; returns content active at that point"
        )] = None,
    ) -> dict:
        """Return active AETAG content items at the given timestamp.
        GET /aetag/v1/audit on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aetag/v1/audit", params=params or None)

    # ------------------------------------------------------------------ #
    #  Global tagsets                                                      #
    # ------------------------------------------------------------------ #

    def aetag_get_global_tagsets(
        self,
        ts: Annotated[Optional[int], Field(
            description="Filter to content active at this timestamp (Unix epoch)"
        )] = None,
    ) -> dict:
        """List all global tagset definitions.
        GET /aetag/v1/tags on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aetag/v1/tags", params=params or None)

    def aetag_get_global_tagset_by_path(
        self,
        path: Annotated[str, Field(
            description="Tagset path identifier, e.g. 'observations/SomeTagset'"
        )],
        compose: Annotated[Optional[bool], Field(
            description="Enable tagset composition (default: true)"
        )] = None,
    ) -> dict:
        """Get a global tagset definition by its path.
        GET /aetag/v1/tags/paths/{path} on global-services host.
        """
        params = {}
        if compose is not None:
            params["compose"] = str(compose).lower()
        return self._get_global(
            f"/aetag/v1/tags/paths/{url_quote(path)}",
            params=params or None,
        )

    def aetag_get_tagset_by_id(
        self,
        tagset_id: Annotated[str, Field(description="UUID of the tagset")],
    ) -> dict:
        """Get any tagset definition by its UUID.
        GET /aetag/v1/tags/ids/{id} on global-services host.
        """
        return self._get_global(f"/aetag/v1/tags/ids/{tagset_id}")

    def aetag_create_global_tagset(
        self,
        body: Annotated[dict, Field(
            description=(
                "Tagset definition object. Typical fields: "
                "{'path': str, 'content': {key: value, ...}}. "
                "Refer to the AETAG API spec for the full schema."
            )
        )],
    ) -> dict:
        """Create or update a global tagset definition.
        POST /aetag/v1/tags on global-services host.
        """
        return self._post_global("/aetag/v1/tags", json_body=body)

    def aetag_validate_tagset(
        self,
        body: Annotated[dict, Field(description="Tagset definition to validate")],
    ) -> dict:
        """Validate a tagset definition without persisting it.
        POST /aetag/v1/validate/tags on global-services host.
        """
        return self._post_global("/aetag/v1/validate/tags", json_body=body)

    # ------------------------------------------------------------------ #
    #  Account tagsets                                                     #
    # ------------------------------------------------------------------ #

    def aetag_get_tagsets(
        self,
        ts: Annotated[Optional[int], Field(
            description="Filter to content active at this timestamp (Unix epoch)"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List all tagset definitions for an account (includes inherited globals).
        GET /aetag/v1/{account_id}/tags on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aetag/v1/{account_id}/tags",
                                account_id=account_id, params=params or None)

    def aetag_get_tagset_by_path(
        self,
        path: Annotated[str, Field(description="Tagset path identifier")],
        compose: Annotated[Optional[bool], Field(
            description="Enable tagset composition (default: true)"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get an account-scoped tagset by path.
        GET /aetag/v1/{account_id}/tags/paths/{path} on global-services host.
        """
        params = {}
        if compose is not None:
            params["compose"] = str(compose).lower()
        return self._get_global(
            f"/aetag/v1/{{account_id}}/tags/paths/{url_quote(path)}",
            account_id=account_id,
            params=params or None,
        )

    def aetag_create_tagset(
        self,
        body: Annotated[dict, Field(description="Tagset definition object")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create or update an account-scoped tagset.
        POST /aetag/v1/{account_id}/tags on global-services host.
        """
        return self._post_global("/aetag/v1/{account_id}/tags",
                                 account_id=account_id, json_body=body)

    def aetag_lookup_tagset(
        self,
        lookup_body: Annotated[dict, Field(
            description=(
                "Lookup request body with keys/values to search for. "
                "Typical structure: {'paths': [...], 'keys': [...]}."
            )
        )],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Lookup keys or values in account tagsets or tuning paths.
        POST /aetag/v1/{account_id}/tags/lookup on global-services host.
        """
        return self._post_global("/aetag/v1/{account_id}/tags/lookup",
                                 account_id=account_id, json_body=lookup_body)

    # ------------------------------------------------------------------ #
    #  Global tuning tagsets                                               #
    # ------------------------------------------------------------------ #

    def aetag_get_global_tuning_by_path(
        self,
        path: Annotated[str, Field(description="Tuning tagset path identifier")],
    ) -> dict:
        """Get a global tuning tagset by path.
        GET /aetag/v1/tunings/paths/{path} on global-services host.
        """
        return self._get_global(f"/aetag/v1/tunings/paths/{url_quote(path)}")

    def aetag_create_global_tuning(
        self,
        body: Annotated[dict, Field(
            description=(
                "Global tuning tagset definition. Typical fields: "
                "{'path': str, 'content': {threshold_key: value, ...}}."
            )
        )],
    ) -> dict:
        """Create or update a global tuning tagset.
        POST /aetag/v1/tunings on global-services host.
        """
        return self._post_global("/aetag/v1/tunings", json_body=body)

    def aetag_validate_tuning(
        self,
        body: Annotated[dict, Field(description="Tuning tagset definition to validate")],
    ) -> dict:
        """Validate a tuning tagset definition without persisting it.
        POST /aetag/v1/validate/tunings on global-services host.
        """
        return self._post_global("/aetag/v1/validate/tunings", json_body=body)

    # ------------------------------------------------------------------ #
    #  Account tuning tagsets                                              #
    # ------------------------------------------------------------------ #

    def aetag_get_tuning_by_path(
        self,
        path: Annotated[str, Field(description="Tuning tagset path identifier")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get an account-scoped tuning tagset by path.
        GET /aetag/v1/{account_id}/tunings/paths/{path} on global-services host.
        """
        return self._get_global(
            f"/aetag/v1/{{account_id}}/tunings/paths/{url_quote(path)}",
            account_id=account_id,
        )

    def aetag_create_tuning(
        self,
        body: Annotated[dict, Field(description="Tuning tagset definition object")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create or update an account-scoped tuning tagset.
        POST /aetag/v1/{account_id}/tunings on global-services host.
        """
        return self._post_global("/aetag/v1/{account_id}/tunings",
                                 account_id=account_id, json_body=body)

    # ------------------------------------------------------------------ #
    #  Definitions (tag key/value schemas)                                 #
    # ------------------------------------------------------------------ #

    def aetag_get_definitions(
        self,
        ts: Annotated[Optional[int], Field(
            description="Filter to definitions active at this timestamp (Unix epoch)"
        )] = None,
    ) -> dict:
        """List all tagset key/value schema definitions.
        GET /aetag/v1/definitions on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aetag/v1/definitions", params=params or None)

    def aetag_get_definition_by_path(
        self,
        path: Annotated[str, Field(description="Definition path identifier")],
    ) -> dict:
        """Get a tagset schema definition by path.
        GET /aetag/v1/definitions/paths/{path} on global-services host.
        """
        return self._get_global(f"/aetag/v1/definitions/paths/{url_quote(path)}")

    def aetag_get_definition_by_id(
        self,
        definition_id: Annotated[str, Field(description="UUID of the definition")],
    ) -> dict:
        """Get a tagset schema definition by UUID.
        GET /aetag/v1/definitions/ids/{id} on global-services host.
        """
        return self._get_global(f"/aetag/v1/definitions/ids/{definition_id}")

    def aetag_create_definition(
        self,
        body: Annotated[dict, Field(
            description=(
                "Tagset schema definition object. Defines the allowed keys and "
                "value types for a category of tagsets."
            )
        )],
    ) -> dict:
        """Create a new tagset schema definition.
        POST /aetag/v1/definitions on global-services host.
        """
        return self._post_global("/aetag/v1/definitions", json_body=body)

    def aetag_validate_definition(
        self,
        body: Annotated[dict, Field(description="Definition to validate")],
    ) -> dict:
        """Validate a tagset schema definition without persisting it.
        POST /aetag/v1/validate/definitions on global-services host.
        """
        return self._post_global("/aetag/v1/validate/definitions", json_body=body)

    # ------------------------------------------------------------------ #
    #  Tuning metadata                                                     #
    # ------------------------------------------------------------------ #

    def aetag_get_tuning_for_account_ids(self) -> dict:
        """Get tuning metadata for all account IDs.
        GET /aetag/v1/metadata/tunings/account_ids/ on global-services host.
        """
        return self._get_global("/aetag/v1/metadata/tunings/account_ids/")

    def aetag_get_tuning_for_tagset(
        self,
        path: Annotated[str, Field(description="Tagset path to query tuning metadata for")],
    ) -> dict:
        """Get tuning metadata for a specific tagset path.
        GET /aetag/v1/metadata/tunings/tagsets/{path} on global-services host.
        """
        return self._get_global(f"/aetag/v1/metadata/tunings/tagsets/{url_quote(path)}")

    def aetag_get_tuning_for_analytic(
        self,
        path: Annotated[str, Field(description="Analytic path to query tuning info for")],
    ) -> dict:
        """Get tuning information for a specific analytic path.
        GET /aetag/v1/metadata/tunings/analytics/{path} on global-services host.
        """
        return self._get_global(f"/aetag/v1/metadata/tunings/analytics/{url_quote(path)}")


def setup(server: FastMCP):
    mod = AetagModule()
    mod.register_tools(server)
