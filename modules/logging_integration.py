"""
AlertLogic Logging & Data Integration.
Log sources, ingest configuration, and search.

Maps to: Sources API, Ingest API, Search API
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class LoggingIntegrationModule(BaseModule):
    """Log source and data integration management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.sources_list, "sources_list",
                        "List all log/data sources for an account")
        self._add_tool(server, self.sources_get, "sources_get",
                        "Get details of a specific data source")
        self._add_tool(server, self.sources_create, "sources_create",
                        "Create a new log source")
        self._add_tool(server, self.sources_update, "sources_update",
                        "Update a log source configuration")
        self._add_tool(server, self.sources_delete, "sources_delete",
                        "Delete a log source")
        self._add_tool(server, self.connectors_update, "connectors_update",
                        "Update an existing connection")
        self._add_tool(server, self.connectors_list_targets, "connectors_list_targets",
                        "List connection targets (configured endpoints/destinations)")
        self._add_tool(server, self.connectors_get_target, "connectors_get_target",
                        "Get a specific connection target")
        self._add_tool(server, self.connectors_create_target, "connectors_create_target",
                        "Create a new connection target")
        self._add_tool(server, self.connectors_update_target, "connectors_update_target",
                        "Update an existing connection target")
        self._add_tool(server, self.connectors_delete_target, "connectors_delete_target",
                        "Delete a connection target")
        self._add_tool(server, self.connectors_list_targets_full, "connectors_list_targets_full",
                        "List connection targets with full configuration details")
        self._add_tool(server, self.connectors_list_notifications, "connectors_list_notifications",
                        "List notifications sent by connectors")
        self._add_tool(server, self.connectors_get_notification, "connectors_get_notification",
                        "Get a specific connector notification")
        self._add_tool(server, self.connectors_list_integration_definitions,
                        "connectors_list_integration_definitions",
                        "List available connection target type definitions")
        self._add_tool(server, self.connectors_get_payload_types, "connectors_get_payload_types",
                        "List supported payload types")
        self._add_tool(server, self.connectors_send_notification, "connectors_send_notification",
                        "Send a test/direct notification to a connection")

    # -------------------------------------------------------------------------
    # Sources
    # -------------------------------------------------------------------------

    def sources_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        source_type: Annotated[Optional[str], Field(description="Filter by source type")] = None,
    ) -> dict:
        """List sources. GET /sources/v1/{account_id}/sources"""
        params = {}
        if source_type:
            params["type"] = source_type
        return self._get("/sources/v1/{account_id}/sources", account_id=account_id, params=params or None)

    def sources_get(
        self,
        source_id: Annotated[str, Field(description="Source UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get source. GET /sources/v1/{account_id}/sources/{source_id}"""
        return self._get(
            f"/sources/v1/{{account_id}}/sources/{source_id}",
            account_id=account_id,
        )

    def sources_create(
        self,
        name: Annotated[str, Field(description="Source name")],
        source_type: Annotated[str, Field(
            description="Source type (e.g., 'environment', 'log_source')"
        )],
        config: Annotated[dict, Field(
            description=(
                "Source-type-specific config object. Must include 'collection_method' and "
                "'collection_type' for environment sources, e.g. "
                "{'collection_method': 'api', 'collection_type': 'aws', ...}"
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create source. POST /sources/v1/{account_id}/sources"""
        body = {"source": {"name": name, "type": source_type, "config": config}}
        return self._post("/sources/v1/{account_id}/sources", account_id=account_id, json_body=body)

    def sources_update(
        self,
        source_id: Annotated[str, Field(description="Source UUID")],
        name: Annotated[Optional[str], Field(description="New name")] = None,
        config: Annotated[Optional[dict], Field(description="Updated configuration object")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update source. PUT /sources/v1/{account_id}/sources/{source_id}"""
        source_body: dict = {}
        if name:
            source_body["name"] = name
        if config:
            source_body["config"] = config
        return self._put(
            f"/sources/v1/{{account_id}}/sources/{source_id}",
            account_id=account_id,
            json_body={"source": source_body},
        )

    def sources_delete(
        self,
        source_id: Annotated[str, Field(description="Source UUID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete source. DELETE /sources/v1/{account_id}/sources/{source_id}"""
        return self._delete(
            f"/sources/v1/{{account_id}}/sources/{source_id}",
            account_id=account_id,
        )

    # -------------------------------------------------------------------------
    # Connectors — connections
    # -------------------------------------------------------------------------

    def connectors_update(
        self,
        connection_id: Annotated[str, Field(description="Connection UUID to update")],
        name: Annotated[Optional[str], Field(description="New connection name")] = None,
        type: Annotated[Optional[str], Field(description="Connection type")] = None,
        targets: Annotated[Optional[list], Field(description="List of target IDs for this connection")] = None,
        body: Annotated[Optional[dict], Field(description="Full update body (overrides individual fields if provided)")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update an existing connection. PUT /v1/{account_id}/connections/{connection_id}"""
        if body is None:
            body = {}
            if name is not None:
                body["name"] = name
            if type is not None:
                body["type"] = type
            if targets is not None:
                body["targets"] = targets
        return self._request_at(
            "connectors", "PUT",
            f"/v1/{{account_id}}/connections/{connection_id}",
            account_id=account_id,
            json_body=body,
        )

    # -------------------------------------------------------------------------
    # Connectors — connection targets
    # -------------------------------------------------------------------------

    def connectors_list_targets(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List connection targets. GET /v1/{account_id}/connection_targets"""
        return self._request_at(
            "connectors", "GET",
            "/v1/{account_id}/connection_targets",
            account_id=account_id,
        )

    def connectors_get_target(
        self,
        target_id: Annotated[str, Field(description="Connection target UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a specific connection target. GET /v1/{account_id}/connection_targets/{target_id}"""
        return self._request_at(
            "connectors", "GET",
            f"/v1/{{account_id}}/connection_targets/{target_id}",
            account_id=account_id,
        )

    def connectors_create_target(
        self,
        name: Annotated[str, Field(description="Target name")],
        type: Annotated[str, Field(description="Target type (e.g., 'webhook', 'sns', 'email')")],
        configuration: Annotated[dict, Field(description="Type-specific configuration object")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create a connection target. POST /v1/{account_id}/connection_targets"""
        body = {"name": name, "type": type, "configuration": configuration}
        return self._request_at(
            "connectors", "POST",
            "/v1/{account_id}/connection_targets",
            account_id=account_id,
            json_body=body,
        )

    def connectors_update_target(
        self,
        target_id: Annotated[str, Field(description="Connection target UUID to update")],
        name: Annotated[Optional[str], Field(description="New target name")] = None,
        type: Annotated[Optional[str], Field(description="Target type")] = None,
        configuration: Annotated[Optional[dict], Field(description="Updated type-specific configuration")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update a connection target. PUT /v1/{account_id}/connection_targets/{target_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if type is not None:
            body["type"] = type
        if configuration is not None:
            body["configuration"] = configuration
        return self._request_at(
            "connectors", "PUT",
            f"/v1/{{account_id}}/connection_targets/{target_id}",
            account_id=account_id,
            json_body=body,
        )

    def connectors_delete_target(
        self,
        target_id: Annotated[str, Field(description="Connection target UUID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete a connection target. DELETE /v1/{account_id}/connection_targets/{target_id}"""
        return self._request_at(
            "connectors", "DELETE",
            f"/v1/{{account_id}}/connection_targets/{target_id}",
            account_id=account_id,
        )

    def connectors_list_targets_full(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List connection targets with full config details. GET /v1/{account_id}/connection_targets_full"""
        return self._request_at(
            "connectors", "GET",
            "/v1/{account_id}/connection_targets_full",
            account_id=account_id,
        )

    # -------------------------------------------------------------------------
    # Connectors — notifications
    # -------------------------------------------------------------------------

    def connectors_list_notifications(
        self,
        connection_id: Annotated[Optional[str], Field(description="Filter by connection UUID")] = None,
        from_ts: Annotated[Optional[str], Field(description="Start timestamp (ISO-8601 or epoch seconds)")] = None,
        to_ts: Annotated[Optional[str], Field(description="End timestamp (ISO-8601 or epoch seconds)")] = None,
        page: Annotated[Optional[int], Field(description="Page number (1-based)")] = None,
        page_size: Annotated[Optional[int], Field(description="Results per page")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List connector-sent notifications. GET /v1/{account_id}/notifications"""
        params: dict = {}
        if connection_id is not None:
            params["connection_id"] = connection_id
        if from_ts is not None:
            params["from_ts"] = from_ts
        if to_ts is not None:
            params["to_ts"] = to_ts
        if page is not None:
            params["page"] = page
        if page_size is not None:
            params["page_size"] = page_size
        return self._request_at(
            "connectors", "GET",
            "/v1/{account_id}/notifications",
            account_id=account_id,
            params=params or None,
        )

    def connectors_get_notification(
        self,
        notification_id: Annotated[str, Field(description="Notification UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a specific notification. GET /v1/{account_id}/notifications/{notification_id}"""
        return self._request_at(
            "connectors", "GET",
            f"/v1/{{account_id}}/notifications/{notification_id}",
            account_id=account_id,
        )

    # -------------------------------------------------------------------------
    # Connectors — definitions and payload types (no account_id in path)
    # -------------------------------------------------------------------------

    def connectors_list_integration_definitions(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List available connection target type definitions. GET /v1/{account_id}/definitions/connection_targets"""
        return self._request_at(
            "connectors", "GET",
            "/v1/{account_id}/definitions/connection_targets",
            account_id=account_id,
        )

    def connectors_get_payload_types(self) -> dict:
        """List supported payload types. GET /v1/payload_types"""
        return self._request_at("connectors", "GET", "/v1/payload_types")

    def connectors_send_notification(
        self,
        connection_id: Annotated[str, Field(description="Connection UUID to send the notification to")],
        payload: Annotated[dict, Field(description="Notification payload data")],
    ) -> dict:
        """Send a test/direct notification to a connection. POST /v1/connections/{connection_id}/notification"""
        return self._request_at(
            "connectors", "POST",
            f"/v1/connections/{connection_id}/notification",
            json_body=payload,
        )


def setup(server: FastMCP):
    mod = LoggingIntegrationModule()
    mod.register_tools(server)
