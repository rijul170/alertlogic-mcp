"""
AlertLogic Analytics Engine Filter Router (AEFR).
Manages evolution rules, triggers, and filters that control how the analytics
engine routes and transforms log/telemetry data.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/aefr/aefr.v1.yaml
Host: api.global-services.global.alertlogic.com
"""
import os
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule, url_quote


AefrDataType = Literal["logmsgs", "observations", "telemetry"]


class AefrModule(BaseModule):
    """
    Analytics Engine Filter Router.

    Manages three resource types across global and account scopes:
      - Evolution Rules  — define how data evolves/transforms between versions
      - Triggers         — conditions that activate analytics engine processing
      - Filters          — rules that allow/deny data from reaching analytics
    """

    def register_tools(self, server: FastMCP):
        # ---- Audit ----
        self._add_tool(server, self.aefr_get_audit, "aefr_get_audit",
                       "Get AEFR audit — active content items at a given timestamp")

        # ---- Global evolution rules ----
        self._add_tool(server, self.aefr_get_global_evolution_rules,
                       "aefr_get_global_evolution_rules",
                       "List all global evolution rules")
        self._add_tool(server, self.aefr_get_global_evolution_rules_by_data_type,
                       "aefr_get_global_evolution_rules_by_data_type",
                       "List global evolution rules filtered by data type (logmsgs/observations/telemetry)")
        self._add_tool(server, self.aefr_get_global_evolution_rule_by_path,
                       "aefr_get_global_evolution_rule_by_path",
                       "Get a global evolution rule by its path")
        self._add_tool(server, self.aefr_get_evolution_rule_by_id,
                       "aefr_get_evolution_rule_by_id",
                       "Get an evolution rule by its UUID")

        # ---- Account evolution rules ----
        self._add_tool(server, self.aefr_get_evolution_rules,
                       "aefr_get_evolution_rules",
                       "List evolution rules for a specific account")
        self._add_tool(server, self.aefr_get_evolution_rule_by_path,
                       "aefr_get_evolution_rule_by_path",
                       "Get an account-scoped evolution rule by path")

        # ---- Global triggers ----
        self._add_tool(server, self.aefr_get_global_triggers,
                       "aefr_get_global_triggers",
                       "List all global triggers")
        self._add_tool(server, self.aefr_get_global_triggers_by_data_type,
                       "aefr_get_global_triggers_by_data_type",
                       "List global triggers filtered by data type")
        self._add_tool(server, self.aefr_get_global_trigger_by_path,
                       "aefr_get_global_trigger_by_path",
                       "Get a global trigger by its path")
        self._add_tool(server, self.aefr_get_trigger_by_id,
                       "aefr_get_trigger_by_id",
                       "Get a trigger by its UUID")
        self._add_tool(server, self.aefr_create_global_trigger,
                       "aefr_create_global_trigger",
                       "Create or update a global trigger")
        self._add_tool(server, self.aefr_validate_trigger,
                       "aefr_validate_trigger",
                       "Validate a trigger definition before creating it")

        # ---- Account triggers ----
        self._add_tool(server, self.aefr_get_triggers,
                       "aefr_get_triggers",
                       "List triggers for a specific account")
        self._add_tool(server, self.aefr_create_trigger,
                       "aefr_create_trigger",
                       "Create or update an account-scoped trigger")

        # ---- Global filters ----
        self._add_tool(server, self.aefr_get_global_filters,
                       "aefr_get_global_filters",
                       "List all global filters")
        self._add_tool(server, self.aefr_get_global_filters_by_data_type,
                       "aefr_get_global_filters_by_data_type",
                       "List global filters by data type")
        self._add_tool(server, self.aefr_get_global_filter_by_path,
                       "aefr_get_global_filter_by_path",
                       "Get a global filter by path")
        self._add_tool(server, self.aefr_get_filter_by_id,
                       "aefr_get_filter_by_id",
                       "Get a filter by its UUID")
        self._add_tool(server, self.aefr_create_global_filter,
                       "aefr_create_global_filter",
                       "Create or update a global filter")
        self._add_tool(server, self.aefr_validate_filter,
                       "aefr_validate_filter",
                       "Validate a filter definition before creating it")

        # ---- Account filters ----
        self._add_tool(server, self.aefr_get_filters,
                       "aefr_get_filters",
                       "List filters for a specific account")
        self._add_tool(server, self.aefr_create_filter,
                       "aefr_create_filter",
                       "Create or update an account-scoped filter")

    # ------------------------------------------------------------------ #
    #  Audit                                                               #
    # ------------------------------------------------------------------ #

    def aefr_get_audit(
        self,
        ts: Annotated[Optional[int], Field(
            description="Unix epoch timestamp to retrieve active content at that point in time"
        )] = None,
    ) -> dict:
        """Return the set of active AEFR content items at the given timestamp.
        GET /aefr/v1/audit on global-services host.
        """
        params = {}
        if ts is not None:
            params["ts"] = ts
        return self._get_global("/aefr/v1/audit", params=params or None)

    # ------------------------------------------------------------------ #
    #  Global evolution rules                                              #
    # ------------------------------------------------------------------ #

    def aefr_get_global_evolution_rules(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account rules in the response"
        )] = None,
    ) -> dict:
        """List all global evolution rules.
        GET /aefr/v1/evolution_rules on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/evolution_rules", params=params or None)

    def aefr_get_global_evolution_rules_by_data_type(
        self,
        data_type: Annotated[AefrDataType, Field(
            description="Data type to filter by: logmsgs | observations | telemetry"
        )],
    ) -> dict:
        """List global evolution rules for a specific data type.
        GET /aefr/v1/evolution_rules/datatypes/{data_type} on global-services host.
        """
        return self._get_global(f"/aefr/v1/evolution_rules/datatypes/{data_type}")

    def aefr_get_global_evolution_rule_by_path(
        self,
        path: Annotated[str, Field(
            description="URL-encoded content path of the evolution rule"
        )],
    ) -> dict:
        """Get a global evolution rule by its path.
        GET /aefr/v1/evolution_rules/paths/{path} on global-services host.
        """
        return self._get_global(f"/aefr/v1/evolution_rules/paths/{url_quote(path)}")

    def aefr_get_evolution_rule_by_id(
        self,
        evolution_rule_id: Annotated[str, Field(
            description="UUID of the evolution rule"
        )],
    ) -> dict:
        """Get an evolution rule by its UUID.
        GET /aefr/v1/evolution_rules/ids/{evolution_rule_id} on global-services host.
        """
        return self._get_global(f"/aefr/v1/evolution_rules/ids/{evolution_rule_id}")

    # ------------------------------------------------------------------ #
    #  Account evolution rules                                            #
    # ------------------------------------------------------------------ #

    def aefr_get_evolution_rules(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account rules"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List evolution rules for a specific account (includes inherited global rules).
        GET /aefr/v1/{account_id}/evolution_rules on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/{account_id}/evolution_rules",
                                account_id=account_id, params=params or None)

    def aefr_get_evolution_rule_by_path(
        self,
        path: Annotated[str, Field(description="Content path of the evolution rule")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get an account-scoped evolution rule by path.
        GET /aefr/v1/{account_id}/evolution_rules/paths/{path} on global-services host.
        """
        return self._get_global(
            f"/aefr/v1/{{account_id}}/evolution_rules/paths/{url_quote(path)}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Global triggers                                                     #
    # ------------------------------------------------------------------ #

    def aefr_get_global_triggers(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account triggers"
        )] = None,
    ) -> dict:
        """List all global triggers.
        GET /aefr/v1/triggers on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/triggers", params=params or None)

    def aefr_get_global_triggers_by_data_type(
        self,
        data_type: Annotated[AefrDataType, Field(
            description="Data type: logmsgs | observations | telemetry"
        )],
    ) -> dict:
        """List global triggers filtered by data type.
        GET /aefr/v1/triggers/datatypes/{data_type} on global-services host.
        """
        return self._get_global(f"/aefr/v1/triggers/datatypes/{data_type}")

    def aefr_get_global_trigger_by_path(
        self,
        path: Annotated[str, Field(description="Content path of the trigger")],
    ) -> dict:
        """Get a global trigger by its path.
        GET /aefr/v1/triggers/paths/{path} on global-services host.
        """
        return self._get_global(f"/aefr/v1/triggers/paths/{url_quote(path)}")

    def aefr_get_trigger_by_id(
        self,
        trigger_id: Annotated[str, Field(description="UUID of the trigger")],
    ) -> dict:
        """Get a trigger by its UUID.
        GET /aefr/v1/triggers/ids/{trigger_id} on global-services host.
        """
        return self._get_global(f"/aefr/v1/triggers/ids/{trigger_id}")

    def aefr_create_global_trigger(
        self,
        path: Annotated[str, Field(description="Unique path for this trigger")],
        body: Annotated[dict, Field(
            description=(
                "Trigger definition object. Typical fields: "
                "{'data_type': str, 'path': str, 'content': {...}}. "
                "Refer to the AEFR API spec for the full schema."
            )
        )],
    ) -> dict:
        """Create or update a global trigger.
        POST /aefr/v1/triggers on global-services host.
        """
        return self._post_global("/aefr/v1/triggers", json_body=body)

    def aefr_validate_trigger(
        self,
        body: Annotated[dict, Field(
            description="Trigger definition to validate"
        )],
    ) -> dict:
        """Validate a trigger definition without persisting it.
        POST /aefr/v1/validations/triggers on global-services host.
        """
        return self._post_global("/aefr/v1/validations/triggers", json_body=body)

    # ------------------------------------------------------------------ #
    #  Account triggers                                                    #
    # ------------------------------------------------------------------ #

    def aefr_get_triggers(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account triggers"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List triggers for a specific account.
        GET /aefr/v1/{account_id}/triggers on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/{account_id}/triggers",
                                account_id=account_id, params=params or None)

    def aefr_create_trigger(
        self,
        body: Annotated[dict, Field(description="Trigger definition object")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create or update an account-scoped trigger.
        POST /aefr/v1/{account_id}/triggers on global-services host.
        """
        return self._post_global("/aefr/v1/{account_id}/triggers",
                                 account_id=account_id, json_body=body)

    # ------------------------------------------------------------------ #
    #  Global filters                                                      #
    # ------------------------------------------------------------------ #

    def aefr_get_global_filters(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account filters"
        )] = None,
    ) -> dict:
        """List all global filters.
        GET /aefr/v1/filters on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/filters", params=params or None)

    def aefr_get_global_filters_by_data_type(
        self,
        data_type: Annotated[AefrDataType, Field(
            description="Data type: logmsgs | observations | telemetry"
        )],
    ) -> dict:
        """List global filters filtered by data type.
        GET /aefr/v1/filters/datatypes/{data_type} on global-services host.
        """
        return self._get_global(f"/aefr/v1/filters/datatypes/{data_type}")

    def aefr_get_global_filter_by_path(
        self,
        path: Annotated[str, Field(description="Content path of the filter")],
    ) -> dict:
        """Get a global filter by its path.
        GET /aefr/v1/filters/paths/{path} on global-services host.
        """
        return self._get_global(f"/aefr/v1/filters/paths/{url_quote(path)}")

    def aefr_get_filter_by_id(
        self,
        filter_id: Annotated[str, Field(description="UUID of the filter")],
    ) -> dict:
        """Get a filter by its UUID.
        GET /aefr/v1/filters/ids/{filter_id} on global-services host.
        """
        return self._get_global(f"/aefr/v1/filters/ids/{filter_id}")

    def aefr_create_global_filter(
        self,
        body: Annotated[dict, Field(
            description=(
                "Filter definition object. Typical fields: "
                "{'data_type': str, 'path': str, 'content': {...}}. "
                "Refer to the AEFR API spec for the full schema."
            )
        )],
    ) -> dict:
        """Create or update a global filter.
        POST /aefr/v1/filters on global-services host.
        """
        return self._post_global("/aefr/v1/filters", json_body=body)

    def aefr_validate_filter(
        self,
        body: Annotated[dict, Field(description="Filter definition to validate")],
    ) -> dict:
        """Validate a filter definition without persisting it.
        POST /aefr/v1/validations/filters on global-services host.
        """
        return self._post_global("/aefr/v1/validations/filters", json_body=body)

    # ------------------------------------------------------------------ #
    #  Account filters                                                     #
    # ------------------------------------------------------------------ #

    def aefr_get_filters(
        self,
        include_parents: Annotated[Optional[bool], Field(
            description="Include parent account filters"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List filters for a specific account.
        GET /aefr/v1/{account_id}/filters on global-services host.
        """
        params = {}
        if include_parents is not None:
            params["include_parents"] = str(include_parents).lower()
        return self._get_global("/aefr/v1/{account_id}/filters",
                                account_id=account_id, params=params or None)

    def aefr_create_filter(
        self,
        body: Annotated[dict, Field(description="Filter definition object")],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create or update an account-scoped filter.
        POST /aefr/v1/{account_id}/filters on global-services host.
        """
        return self._post_global("/aefr/v1/{account_id}/filters",
                                 account_id=account_id, json_body=body)


def setup(server: FastMCP):
    mod = AefrModule()
    mod.register_tools(server)
