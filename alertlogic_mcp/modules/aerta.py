"""
AlertLogic Analytics Engine RTA (Real-Time Aggregation) Service.
Manages RTA model definitions and fetches aggregated RTA data for accounts.
RTAs define how the analytics engine aggregates streaming event/log data
in real time.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/aerta/aerta.v1.yaml
Host: api.global-services.global.alertlogic.com
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


AertaDataType = Literal["logmsgs", "telemetry"]


class AertaModule(BaseModule):
    """
    Analytics Engine RTA — Real-Time Aggregation model management.

    Supports both global (platform-wide) and account-scoped RTA models,
    plus on-demand data fetch with optional re-aggregation.
    """

    def register_tools(self, server: FastMCP):
        # ---- Audit ----
        self._add_tool(server, self.aerta_get_audit, "aerta_get_audit",
                       "Get AERTA audit — active content items at a given timestamp")

        # ---- Global RTAs ----
        self._add_tool(server, self.aerta_get_global_rtas, "aerta_get_global_rtas",
                       "List all global RTA model definitions")
        self._add_tool(server, self.aerta_get_global_rtas_by_data_type,
                       "aerta_get_global_rtas_by_data_type",
                       "List global RTAs filtered by data type (logmsgs/telemetry)")
        self._add_tool(server, self.aerta_get_global_rta_by_path,
                       "aerta_get_global_rta_by_path",
                       "Get a global RTA model definition by its path")
        self._add_tool(server, self.aerta_get_global_rta_by_id,
                       "aerta_get_global_rta_by_id",
                       "Get a global RTA model definition by its UUID")
        self._add_tool(server, self.aerta_create_global_rta, "aerta_create_global_rta",
                       "Create a new global RTA model definition")
        self._add_tool(server, self.aerta_validate_rta, "aerta_validate_rta",
                       "Validate an RTA model definition without persisting it")

        # ---- Account RTAs ----
        self._add_tool(server, self.aerta_get_rtas, "aerta_get_rtas",
                       "List all RTA model definitions for an account")
        self._add_tool(server, self.aerta_get_rtas_by_data_type,
                       "aerta_get_rtas_by_data_type",
                       "List account RTA models filtered by data type")
        self._add_tool(server, self.aerta_get_rta_by_path, "aerta_get_rta_by_path",
                       "Get an account-scoped RTA model by path")
        self._add_tool(server, self.aerta_create_rta, "aerta_create_rta",
                       "Create a new account-scoped RTA model definition")

        # ---- Data fetch ----
        self._add_tool(server, self.aerta_fetch_rta_by_path, "aerta_fetch_rta_by_path",
                       "Fetch RTA aggregated data for an account by RTA path and time window")
        self._add_tool(server, self.aerta_fetch_rta_by_id, "aerta_fetch_rta_by_id",
                       "Fetch RTA aggregated data for an account by RTA UUID and time window")

    # ------------------------------------------------------------------ #
    #  Audit                                                               #
    # ------------------------------------------------------------------ #

    def aerta_get_audit(
        self,
        ts: Annotated[Optional[int], Field(
            description="Unix epoch timestamp; returns content active at that point"
        )] = None,
    ) -> dict:
        """Return the set of active AERTA content items at the given timestamp.
        GET /aerta/v1/audit on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aerta/v1/audit", params=params or None)

    # ------------------------------------------------------------------ #
    #  Global RTA models                                                   #
    # ------------------------------------------------------------------ #

    def aerta_get_global_rtas(self) -> dict:
        """List all global RTA model definitions.
        GET /aerta/v1/rtas on global-services host.
        """
        return self._get_global("/aerta/v1/rtas")

    def aerta_get_global_rtas_by_data_type(
        self,
        data_type: Annotated[AertaDataType, Field(
            description="Ingest data type: logmsgs | telemetry"
        )],
    ) -> dict:
        """List global RTA models for a specific data type.
        GET /aerta/v1/rtas/datatypes/{data_type} on global-services host.
        """
        return self._get_global(f"/aerta/v1/rtas/datatypes/{data_type}")

    def aerta_get_global_rta_by_path(
        self,
        path: Annotated[str, Field(
            description="URL-encoded RTA path (unique per account)"
        )],
    ) -> dict:
        """Get a global RTA model definition by its path.
        GET /aerta/v1/rtas/paths/{path} on global-services host.
        """
        return self._get_global(f"/aerta/v1/rtas/paths/{url_quote(path)}")

    def aerta_get_global_rta_by_id(
        self,
        rta_id: Annotated[str, Field(description="UUID of the RTA model")],
    ) -> dict:
        """Get a global RTA model definition by its UUID.
        GET /aerta/v1/rtas/ids/{id} on global-services host.
        """
        return self._get_global(f"/aerta/v1/rtas/ids/{rta_id}")

    def aerta_create_global_rta(
        self,
        body: Annotated[dict, Field(
            description=(
                "RTA model definition object. Typical fields: "
                "{'path': str, 'data_type': str, 'content': {...}}. "
                "Refer to the AERTA API spec for the full schema."
            )
        )],
    ) -> dict:
        """Create a new global RTA model definition.
        POST /aerta/v1/rtas on global-services host.
        """
        return self._post_global("/aerta/v1/rtas", json_body=body)

    def aerta_validate_rta(
        self,
        body: Annotated[dict, Field(description="RTA model definition to validate")],
    ) -> dict:
        """Validate an RTA model definition without persisting it.
        POST /aerta/v1/validations/rtas on global-services host.
        """
        return self._post_global("/aerta/v1/validations/rtas", json_body=body)

    # ------------------------------------------------------------------ #
    #  Account RTA models                                                  #
    # ------------------------------------------------------------------ #

    def aerta_get_rtas(
        self,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List all RTA model definitions for an account.
        GET /aerta/v1/{account_id}/rtas on global-services host.
        """
        return self._get_global("/aerta/v1/{account_id}/rtas", account_id=account_id)

    def aerta_get_rtas_by_data_type(
        self,
        data_type: Annotated[AertaDataType, Field(
            description="Ingest data type: logmsgs | telemetry"
        )],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List account RTA models for a specific data type.
        GET /aerta/v1/{account_id}/rtas/datatypes/{data_type} on global-services host.
        """
        return self._get_global(
            f"/aerta/v1/{{account_id}}/rtas/datatypes/{data_type}",
            account_id=account_id,
        )

    def aerta_get_rta_by_path(
        self,
        path: Annotated[str, Field(description="RTA path identifier")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get an account-scoped RTA model by path.
        GET /aerta/v1/{account_id}/rtas/paths/{path} on global-services host.
        """
        return self._get_global(
            f"/aerta/v1/{{account_id}}/rtas/paths/{url_quote(path)}",
            account_id=account_id,
        )

    def aerta_create_rta(
        self,
        body: Annotated[dict, Field(description="RTA model definition object")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create a new account-scoped RTA model definition.
        POST /aerta/v1/{account_id}/rtas on global-services host.
        """
        return self._post_global("/aerta/v1/{account_id}/rtas",
                                 account_id=account_id, json_body=body)

    # ------------------------------------------------------------------ #
    #  Data fetch                                                          #
    # ------------------------------------------------------------------ #

    def aerta_fetch_rta_by_path(
        self,
        data_type: Annotated[AertaDataType, Field(
            description="Ingest data type: logmsgs | telemetry"
        )],
        path: Annotated[str, Field(description="RTA path to fetch data for")],
        start_ts: Annotated[int, Field(
            description="Start of the fetch window (Unix epoch seconds)"
        )],
        end_ts: Annotated[int, Field(
            description="End of the fetch window (Unix epoch seconds)"
        )],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Fetch aggregated RTA data for an account by RTA path and time window.
        GET /aerta/v1/{account_id}/fetch/{data_type}/paths/{path} on global-services host.
        """
        return self._get_global(
            f"/aerta/v1/{{account_id}}/fetch/{data_type}/paths/{url_quote(path)}",
            account_id=account_id,
            params={"start_ts": start_ts, "end_ts": end_ts},
        )

    def aerta_fetch_rta_by_id(
        self,
        data_type: Annotated[AertaDataType, Field(
            description="Ingest data type: logmsgs | telemetry"
        )],
        rta_id: Annotated[str, Field(description="UUID of the RTA model")],
        start_ts: Annotated[int, Field(
            description="Start of the fetch window (Unix epoch seconds)"
        )],
        end_ts: Annotated[int, Field(
            description="End of the fetch window (Unix epoch seconds)"
        )],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Fetch aggregated RTA data for an account by RTA UUID and time window.
        GET /aerta/v1/{account_id}/fetch/{data_type}/{id} on global-services host.
        """
        return self._get_global(
            f"/aerta/v1/{{account_id}}/fetch/{data_type}/{rta_id}",
            account_id=account_id,
            params={"start_ts": start_ts, "end_ts": end_ts},
        )


def setup(server: FastMCP):
    mod = AertaModule()
    mod.register_tools(server)
