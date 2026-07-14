"""
AlertLogic Tacoma — Network Appliance & Collection Agent Management (v1).

"Tacoma" is Alert Logic's internal codename for their network IDS/sensor
appliance management service (Pacific Northwest city naming convention —
cf. the `otis` service). It manages the lifecycle of network collection
appliances: registration, configuration, health reporting, and firmware
assignment.

Console API reference: https://console.cloudinsight.alertlogic.com/api/tacoma/
Service host: https://tacoma.mdr.global.alertlogic.com

Endpoint surface (reverse-engineered from console docs and AL internal naming):

  GET    /tacoma/v1/{account_id}/appliances
  GET    /tacoma/v1/{account_id}/appliances/{appliance_id}
  PUT    /tacoma/v1/{account_id}/appliances/{appliance_id}
  DELETE /tacoma/v1/{account_id}/appliances/{appliance_id}
  GET    /tacoma/v1/{account_id}/appliances/{appliance_id}/status
  POST   /tacoma/v1/{account_id}/appliances/{appliance_id}/checkin
  GET    /tacoma/v1/{account_id}/configurations
  GET    /tacoma/v1/{account_id}/configurations/{config_id}
  POST   /tacoma/v1/{account_id}/configurations
  PUT    /tacoma/v1/{account_id}/configurations/{config_id}
  DELETE /tacoma/v1/{account_id}/configurations/{config_id}
  POST   /tacoma/v1/{account_id}/appliances/{appliance_id}/assign_configuration
"""
import os
from typing import Annotated, Literal, Optional

from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


ApplianceStatus = Literal[
    "ok",
    "warning",
    "error",
    "offline",
    "provisioning",
    "decommissioned",
]

ApplianceType = Literal[
    "ids",
    "scan",
    "ids_scan",
]


class TacomaModule(BaseModule):
    """
    Tacoma v1 — network collection appliance management and configuration.

    All endpoints are under https://tacoma.mdr.global.alertlogic.com.
    """

    def __init__(self):
        super().__init__()
        self.service_hosts["tacoma"] = os.environ.get(
            "ALERTLOGIC_TACOMA_BASE_URL",
            "https://tacoma.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        # Appliance queries
        self._add_tool(
            server, self.tacoma_list_appliances, "tacoma_list_appliances",
            "List all network collection appliances for an account, optionally filtered by deployment or status",
        )
        self._add_tool(
            server, self.tacoma_get_appliance, "tacoma_get_appliance",
            "Get full detail for a single network appliance by ID",
        )
        self._add_tool(
            server, self.tacoma_get_appliance_status, "tacoma_get_appliance_status",
            "Get the current health/connectivity status of a network appliance",
        )
        # Appliance management
        self._add_tool(
            server, self.tacoma_update_appliance, "tacoma_update_appliance",
            "Update metadata (name, tags, deployment assignment) on a network appliance",
        )
        self._add_tool(
            server, self.tacoma_delete_appliance, "tacoma_delete_appliance",
            "Decommission and delete a network appliance record",
        )
        self._add_tool(
            server, self.tacoma_checkin_appliance, "tacoma_checkin_appliance",
            "Trigger an immediate check-in for a network appliance (forces a config/firmware poll)",
        )
        self._add_tool(
            server, self.tacoma_assign_configuration, "tacoma_assign_configuration",
            "Assign a named configuration profile to a network appliance",
        )
        # Configuration profiles
        self._add_tool(
            server, self.tacoma_list_configurations, "tacoma_list_configurations",
            "List all appliance configuration profiles for an account",
        )
        self._add_tool(
            server, self.tacoma_get_configuration, "tacoma_get_configuration",
            "Get a single appliance configuration profile by ID",
        )
        self._add_tool(
            server, self.tacoma_create_configuration, "tacoma_create_configuration",
            "Create a new appliance configuration profile",
        )
        self._add_tool(
            server, self.tacoma_update_configuration, "tacoma_update_configuration",
            "Update an existing appliance configuration profile",
        )
        self._add_tool(
            server, self.tacoma_delete_configuration, "tacoma_delete_configuration",
            "Delete an appliance configuration profile (must not be assigned to any appliance)",
        )

    # ------------------------------------------------------------------ #
    #  Appliances                                                         #
    # ------------------------------------------------------------------ #

    def tacoma_list_appliances(
        self,
        deployment_id: Annotated[
            Optional[str],
            Field(description="Filter by deployment UUID"),
        ] = None,
        status: Annotated[
            Optional[ApplianceStatus],
            Field(
                description=(
                    "Filter by appliance health status: "
                    "ok | warning | error | offline | provisioning | decommissioned. "
                    "Omit to return all statuses."
                )
            ),
        ] = None,
        appliance_type: Annotated[
            Optional[ApplianceType],
            Field(
                description=(
                    "Filter by appliance function: ids | scan | ids_scan. "
                    "Omit to return all types."
                )
            ),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID (uses ALERTLOGIC_ACCOUNT_ID env var if omitted)"),
        ] = None,
    ) -> dict:
        """
        List network collection appliances for the account.

        GET /tacoma/v1/{account_id}/appliances
        """
        params: dict = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        if status:
            params["status"] = status
        if appliance_type:
            params["type"] = appliance_type
        return self._get_at(
            "tacoma",
            "/tacoma/v1/{account_id}/appliances",
            account_id=account_id,
            params=params or None,
        )

    def tacoma_get_appliance(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Get full detail for a single network appliance.
        Includes deployment assignment, configuration profile, firmware version,
        network interfaces, and last check-in timestamp.

        GET /tacoma/v1/{account_id}/appliances/{appliance_id}
        """
        return self._get_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}",
            account_id=account_id,
        )

    def tacoma_get_appliance_status(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Get the current health and connectivity status of a network appliance.
        Returns status code, last_seen timestamp, and any active alerts.

        GET /tacoma/v1/{account_id}/appliances/{appliance_id}/status
        """
        return self._get_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}/status",
            account_id=account_id,
        )

    def tacoma_update_appliance(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID to update")],
        name: Annotated[
            Optional[str],
            Field(description="New human-readable name for the appliance"),
        ] = None,
        deployment_id: Annotated[
            Optional[str],
            Field(description="Reassign the appliance to a different deployment UUID"),
        ] = None,
        tags: Annotated[
            Optional[dict],
            Field(
                description=(
                    "Key/value tag dict to set on the appliance. "
                    "Replaces the existing tag set entirely."
                )
            ),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Update metadata on a network appliance.
        Only fields provided are updated; omitted fields are unchanged.

        PUT /tacoma/v1/{account_id}/appliances/{appliance_id}
        """
        body: dict = {}
        if name is not None:
            body["name"] = name
        if deployment_id is not None:
            body["deployment_id"] = deployment_id
        if tags is not None:
            body["tags"] = tags
        return self._put_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}",
            account_id=account_id,
            json_body=body,
        )

    def tacoma_delete_appliance(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID to decommission")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Decommission and delete a network appliance record.
        The physical/virtual appliance will stop receiving configuration
        updates after deletion. Returns 204 No Content on success.

        DELETE /tacoma/v1/{account_id}/appliances/{appliance_id}
        """
        return self._delete_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}",
            account_id=account_id,
        )

    def tacoma_checkin_appliance(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID to trigger check-in for")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Trigger an immediate check-in for a network appliance.
        Forces the appliance to poll for updated configuration and firmware.
        Useful after pushing a configuration change when you don't want to
        wait for the next scheduled check-in cycle.

        POST /tacoma/v1/{account_id}/appliances/{appliance_id}/checkin
        """
        return self._post_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}/checkin",
            account_id=account_id,
        )

    def tacoma_assign_configuration(
        self,
        appliance_id: Annotated[str, Field(description="Appliance UUID")],
        configuration_id: Annotated[
            str,
            Field(description="Configuration profile UUID to assign to this appliance"),
        ],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Assign a configuration profile to a network appliance.
        The new configuration will be applied at the next check-in.
        Trigger tacoma_checkin_appliance immediately after to force a prompt update.

        POST /tacoma/v1/{account_id}/appliances/{appliance_id}/assign_configuration
        """
        return self._post_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/appliances/{appliance_id}/assign_configuration",
            account_id=account_id,
            json_body={"configuration_id": configuration_id},
        )

    # ------------------------------------------------------------------ #
    #  Configuration Profiles                                             #
    # ------------------------------------------------------------------ #

    def tacoma_list_configurations(
        self,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        List all appliance configuration profiles for the account.
        Each profile contains network capture settings, IDS rule sets,
        firmware channel, and monitoring parameters.

        GET /tacoma/v1/{account_id}/configurations
        """
        return self._get_at(
            "tacoma",
            "/tacoma/v1/{account_id}/configurations",
            account_id=account_id,
        )

    def tacoma_get_configuration(
        self,
        config_id: Annotated[str, Field(description="Configuration profile UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Get a single appliance configuration profile by UUID.

        GET /tacoma/v1/{account_id}/configurations/{config_id}
        """
        return self._get_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/configurations/{config_id}",
            account_id=account_id,
        )

    def tacoma_create_configuration(
        self,
        name: Annotated[str, Field(description="Human-readable name for the configuration profile")],
        settings: Annotated[
            dict,
            Field(
                description=(
                    "Configuration settings object. Common keys: "
                    "'firmware_channel' (string, e.g. 'stable'|'beta'), "
                    "'capture_interfaces' (list of interface names), "
                    "'ids_ruleset' (string, ruleset ID), "
                    "'monitoring_interval_seconds' (integer). "
                    "Pass only the keys relevant to your appliance type."
                )
            ),
        ],
        description: Annotated[
            Optional[str],
            Field(description="Optional human-readable description of the profile's purpose"),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Create a new appliance configuration profile.
        The profile can then be assigned to one or more appliances via
        tacoma_assign_configuration.

        POST /tacoma/v1/{account_id}/configurations
        """
        body: dict = {"name": name, "settings": settings}
        if description is not None:
            body["description"] = description
        return self._post_at(
            "tacoma",
            "/tacoma/v1/{account_id}/configurations",
            account_id=account_id,
            json_body=body,
        )

    def tacoma_update_configuration(
        self,
        config_id: Annotated[str, Field(description="Configuration profile UUID to update")],
        name: Annotated[
            Optional[str],
            Field(description="New name for the configuration profile"),
        ] = None,
        description: Annotated[
            Optional[str],
            Field(description="Updated description"),
        ] = None,
        settings: Annotated[
            Optional[dict],
            Field(
                description=(
                    "Updated settings object. Replaces the entire settings block. "
                    "Same key set as tacoma_create_configuration."
                )
            ),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Update an existing appliance configuration profile.
        Only fields provided are updated; omitted fields are unchanged.
        Assigned appliances pick up the change at their next check-in.

        PUT /tacoma/v1/{account_id}/configurations/{config_id}
        """
        body: dict = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if settings is not None:
            body["settings"] = settings
        return self._put_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/configurations/{config_id}",
            account_id=account_id,
            json_body=body,
        )

    def tacoma_delete_configuration(
        self,
        config_id: Annotated[str, Field(description="Configuration profile UUID to delete")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Delete an appliance configuration profile.
        Returns 409 Conflict if the profile is currently assigned to one
        or more appliances — unassign them first.
        Returns 204 No Content on success.

        DELETE /tacoma/v1/{account_id}/configurations/{config_id}
        """
        return self._delete_at(
            "tacoma",
            f"/tacoma/v1/{{account_id}}/configurations/{config_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = TacomaModule()
    mod.register_tools(server)
