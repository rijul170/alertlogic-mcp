"""
AlertLogic Common / Cross-Team Tools.
Herald v2 (notifications + subscriptions), Connectors v1, Endpoints discovery,
Feature Flags v1, Dashboards v2.

Specs:
  - herald.v2 (file is named herald.v1.yaml but content is /herald/v2/...)
      Host: api.global-services.global.alertlogic.com (the "global" service host)
  - connectors.v1
      Host: connectors.mdr.global.alertlogic.com (its own host)
  - endpoints.v1
      Host: api.cloudinsight.alertlogic.com (regional default)
  - flags.v1
      Host: api.cloudinsight.alertlogic.com (regional default)
  - dashboards.v2
      Host: api.cloudinsight.alertlogic.com (regional default)

Notes:
  - Herald has NO delete-notification endpoint. Notifications are sent records;
    subscriptions are the deletable thing. This module exposes both.
  - Connectors uses oneOf body; we split create into webhook vs email tools so
    parameters stay typed.
"""
from typing import Annotated, Any, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


WebhookType = Literal[
    "webhook", "jsd", "jira", "snow", "msteams",
    "ms_power_automate", "pagerduty", "slack",
]
WebhookPayloadType = Literal["incident", "observation", "scheduled_report", "health"]
WebhookPayloadConversion = Literal["jq", "json", "default"]
WebhookMethod = Literal["POST", "PUT", "GET", "DELETE", "PATCH", "OPTIONS", "HEAD"]
EmailPayloadType = Literal["incident", "observation"]
SubscriberType = Literal["user", "connection"]


class CommonModule(BaseModule):
    """Notifications, subscriptions, integrations, endpoint discovery."""

    def register_tools(self, server: FastMCP):
        # ---- Herald v2: notifications (read-only) ----
        self._add_tool(server, self.herald_list_notification_types, "herald_list_notification_types",
                        "List available notification types (account-agnostic)")
        self._add_tool(server, self.herald_send_notification, "herald_send_notification",
                        "Send/dispatch a notification of a given type")
        self._add_tool(server, self.herald_get_notification, "herald_get_notification",
                        "Get a single notification record by ID")
        # ---- Herald v2: subscriptions (CRUD) ----
        self._add_tool(server, self.herald_list_subscriptions, "herald_list_subscriptions",
                        "List notification subscriptions")
        self._add_tool(server, self.herald_create_subscription, "herald_create_subscription",
                        "Create a notification subscription")
        self._add_tool(server, self.herald_get_subscription, "herald_get_subscription",
                        "Get a subscription by ID")
        self._add_tool(server, self.herald_delete_subscription, "herald_delete_subscription",
                        "Delete a subscription")
        # ---- Connectors v1 ----
        self._add_tool(server, self.connectors_list, "connectors_list",
                        "List integration connections")
        self._add_tool(server, self.connectors_create_webhook, "connectors_create_webhook",
                        "Create a webhook-style connection (slack/teams/snow/jira/pagerduty/etc.)")
        self._add_tool(server, self.connectors_create_email, "connectors_create_email",
                        "Create an email connection")
        self._add_tool(server, self.connectors_get, "connectors_get",
                        "Get a connection by ID")
        self._add_tool(server, self.connectors_delete, "connectors_delete",
                        "Delete a connection by ID")
        self._add_tool(server, self.connectors_list_integration_types, "connectors_list_integration_types",
                        "List available integration types")
        # ---- Endpoints discovery ----
        self._add_tool(server, self.endpoints_get, "endpoints_get",
                        "Discover the FQDN of an AlertLogic service in your region")
        # ---- Feature Flags v1 ----
        self._add_tool(server, self.flags_list, "flags_list",
                        "List all feature flags for an account")
        self._add_tool(server, self.flags_get, "flags_get",
                        "Get a specific feature flag value")
        self._add_tool(server, self.flags_set, "flags_set",
                        "Set a feature flag value")
        # ---- Dashboards v2 ----
        self._add_tool(server, self.dashboards_list, "dashboards_list",
                        "List dashboards for an account")
        self._add_tool(server, self.dashboards_get, "dashboards_get",
                        "Get a dashboard by ID")
        self._add_tool(server, self.dashboards_create, "dashboards_create",
                        "Create a new dashboard")
        self._add_tool(server, self.dashboards_update, "dashboards_update",
                        "Update an existing dashboard")
        self._add_tool(server, self.dashboards_delete, "dashboards_delete",
                        "Delete a dashboard by ID")

    # =========================================================== #
    #  Herald v2 (global host)                                     #
    # =========================================================== #

    def herald_list_notification_types(self) -> dict:
        """GET /herald/v2/notification_types (no account scope)."""
        return self._get_global("/herald/v2/notification_types")

    def herald_send_notification(
        self,
        notification_type: Annotated[str, Field(
            description="Notification type, e.g. 'incidents/notification'"
        )],
        notification_data: Annotated[dict, Field(
            description="Per-type metadata (class, threat_level, attackers, status, …)"
        )],
        asset_data: Annotated[dict, Field(
            description="Affected assets: {deployment_id, tags, tag_keys}"
        )],
        payload: Annotated[dict, Field(
            description="Rendered payload fields (incident_id, customer_name, threat, …)"
        )],
        attachments: Annotated[Optional[List[dict]], Field(
            description="Optional list of {name, description, url}"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /herald/v2/{account_id}/notifications"""
        body = {
            "type": notification_type,
            "notification_data": notification_data,
            "asset_data": asset_data,
            "payload": payload,
        }
        if attachments:
            body["attachments"] = attachments
        return self._post_global(
            "/herald/v2/{account_id}/notifications",
            account_id=account_id,
            json_body=body,
        )

    def herald_get_notification(
        self,
        notification_id: Annotated[str, Field(description="Notification record ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /herald/v2/{account_id}/notifications/{notification_id}"""
        return self._get_global(
            f"/herald/v2/{{account_id}}/notifications/{notification_id}",
            account_id=account_id,
        )

    def herald_list_subscriptions(
        self,
        notification_type: Annotated[Optional[str], Field(description="Filter by type")] = None,
        subscription_class: Annotated[Optional[str], Field(description="Filter by class")] = None,
        external_id: Annotated[Optional[str], Field(description="Forces class=schedule")] = None,
        include_subscribers: Annotated[bool, Field(description="Include subscriber list")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /herald/v2/{account_id}/subscriptions"""
        params = {"include_subscribers": str(include_subscribers).lower()}
        if notification_type:
            params["notification_type"] = notification_type
        if subscription_class:
            params["class"] = subscription_class
        if external_id:
            params["external_id"] = external_id
        return self._get_global(
            "/herald/v2/{account_id}/subscriptions",
            account_id=account_id,
            params=params,
        )

    def herald_create_subscription(
        self,
        name: Annotated[str, Field(description="Subscription name")],
        subscription_class: Annotated[str, Field(description="Subscription class")],
        notification_type: Annotated[str, Field(
            description="Type, must match pattern 'category/name'"
        )],
        subscribers: Annotated[Optional[List[dict]], Field(
            description="[{subscriber: <id|email>, subscriber_type: 'user'|'connection'}]"
        )] = None,
        active: Annotated[Optional[bool], Field(description="Whether subscription is active")] = None,
        options: Annotated[Optional[dict], Field(
            description="{include_attachments, email_subject, …}"
        )] = None,
        filters: Annotated[Optional[dict], Field(description="Type-specific filters")] = None,
        template: Annotated[Optional[str], Field(
            description="Template name (log_review_created, fim_report_template, scheduled_report_template, observation_template, incidents_template)"
        )] = None,
        suppression_interval: Annotated[Optional[int], Field(
            description="Minutes (0..10080)"
        )] = None,
        external_id: Annotated[Optional[str], Field(description="External correlation ID")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /herald/v2/{account_id}/subscriptions"""
        body = {
            "name": name,
            "class": subscription_class,
            "notification_type": notification_type,
        }
        if subscribers is not None:
            body["subscribers"] = subscribers
        if active is not None:
            body["active"] = active
        if options is not None:
            body["options"] = options
        if filters is not None:
            body["filters"] = filters
        if template is not None:
            body["template"] = template
        if suppression_interval is not None:
            body["suppression_interval"] = suppression_interval
        if external_id is not None:
            body["external_id"] = external_id
        return self._post_global(
            "/herald/v2/{account_id}/subscriptions",
            account_id=account_id,
            json_body=body,
        )

    def herald_get_subscription(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        include_subscribers: Annotated[bool, Field(description="Include subscriber list")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /herald/v2/{account_id}/subscriptions/{subscription_id}"""
        return self._get_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}",
            account_id=account_id,
            params={"include_subscribers": str(include_subscribers).lower()},
        )

    def herald_delete_subscription(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /herald/v2/{account_id}/subscriptions/{subscription_id}"""
        return self._delete_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}",
            account_id=account_id,
        )

    # =========================================================== #
    #  Connectors v1 (dedicated host)                              #
    # =========================================================== #

    def connectors_list(
        self,
        connection_target_id: Annotated[Optional[str], Field(
            description="Filter by target ID"
        )] = None,
        include_sample_payload: Annotated[bool, Field(
            description="Include rendered sample payload"
        )] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/connections on connectors host"""
        params = {"include_sample_payload": str(include_sample_payload).lower()}
        if connection_target_id:
            params["connection_target_id"] = connection_target_id
        return self._get_at(
            "connectors",
            "/v1/{account_id}/connections",
            account_id=account_id,
            params=params,
        )

    def connectors_create_webhook(
        self,
        name: Annotated[str, Field(description="Connection name")],
        webhook_type: Annotated[WebhookType, Field(
            description="Connector type: webhook/jsd/jira/snow/msteams/ms_power_automate/pagerduty/slack"
        )],
        target_url: Annotated[str, Field(description="Webhook URL")],
        payload_template: Annotated[str, Field(description="Body template (jq or JSON)")],
        payload_conversion_type: Annotated[WebhookPayloadConversion, Field(
            description="jq / json / default"
        )],
        payload_type: Annotated[Optional[WebhookPayloadType], Field(
            description="incident/observation/scheduled_report/health"
        )] = None,
        method: Annotated[WebhookMethod, Field(description="HTTP method")] = "POST",
        headers: Annotated[Optional[str], Field(
            description="Comma-separated 'key: value' pairs"
        )] = None,
        auth_header: Annotated[Optional[str], Field(description="Auth header value")] = None,
        dry_run: Annotated[bool, Field(description="Validate only, don't create")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/connections (webhook variant)"""
        body = {
            "name": name,
            "type": webhook_type,
            "target_url": target_url,
            "payload_template": payload_template,
            "payload_conversion_type": payload_conversion_type,
            "method": method,
        }
        if payload_type:
            body["payload_type"] = payload_type
        if headers:
            body["headers"] = headers
        if auth_header:
            body["auth_header"] = auth_header
        return self._post_at(
            "connectors",
            "/v1/{account_id}/connections",
            account_id=account_id,
            json_body=body,
            params={"dry_run": str(dry_run).lower()} if dry_run else None,
        )

    def connectors_create_email(
        self,
        name: Annotated[str, Field(description="Connection name")],
        email: Annotated[str, Field(description="Destination email address")],
        subject_template: Annotated[str, Field(description="Email subject template")],
        payload_type: Annotated[EmailPayloadType, Field(description="incident or observation")],
        dry_run: Annotated[bool, Field(description="Validate only, don't create")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/connections (email variant)"""
        body = {
            "name": name,
            "type": "email",
            "email": email,
            "subject_template": subject_template,
            "payload_type": payload_type,
        }
        return self._post_at(
            "connectors",
            "/v1/{account_id}/connections",
            account_id=account_id,
            json_body=body,
            params={"dry_run": str(dry_run).lower()} if dry_run else None,
        )

    def connectors_get(
        self,
        connection_id: Annotated[str, Field(description="Connection UUID")],
        include_sample_payload: Annotated[bool, Field(description="Include sample payload")] = False,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/connections/{id}"""
        return self._get_at(
            "connectors",
            f"/v1/{{account_id}}/connections/{connection_id}",
            account_id=account_id,
            params={"include_sample_payload": str(include_sample_payload).lower()},
        )

    def connectors_delete(
        self,
        connection_id: Annotated[str, Field(description="Connection UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /v1/{account_id}/connections/{id}"""
        return self._delete_at(
            "connectors",
            f"/v1/{{account_id}}/connections/{connection_id}",
            account_id=account_id,
        )

    def connectors_list_integration_types(
        self,
        category: Annotated[Optional[Literal["email", "webhook"]], Field(
            description="Filter by category"
        )] = None,
    ) -> dict:
        """GET /v1/integration_types (account-agnostic)"""
        params = {}
        if category:
            params["category"] = category
        return self._get_at(
            "connectors",
            "/v1/integration_types",
            params=params or None,
        )

    # =========================================================== #
    #  Endpoints discovery                                         #
    # =========================================================== #

    def endpoints_get(
        self,
        service_name: Annotated[str, Field(
            description="Service name (e.g., 'aims', 'assets_query', 'iris', 'search')"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /endpoints/v1/{account_id}/services/{service_name}/endpoint"""
        return self._get(
            f"/endpoints/v1/{{account_id}}/services/{service_name}/endpoint",
            account_id=account_id,
        )

    # =========================================================== #
    #  Feature Flags v1 (default host)                            #
    # =========================================================== #

    def flags_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /flags/v1/{account_id} — list all feature flags for an account."""
        return self._get(
            "/flags/v1/{account_id}",
            account_id=account_id,
        )

    def flags_get(
        self,
        flag_name: Annotated[str, Field(description="Feature flag name")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /flags/v1/{account_id}/{flag_name} — get a specific feature flag value."""
        return self._get(
            f"/flags/v1/{{account_id}}/{flag_name}",
            account_id=account_id,
        )

    def flags_set(
        self,
        flag_name: Annotated[str, Field(description="Feature flag name")],
        value: Annotated[Any, Field(description="Value to set for the flag")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /flags/v1/{account_id}/{flag_name} — set a feature flag value."""
        return self._put(
            f"/flags/v1/{{account_id}}/{flag_name}",
            account_id=account_id,
            json_body={"value": value},
        )

    # =========================================================== #
    #  Dashboards v2 (default host)                               #
    # =========================================================== #

    def dashboards_list(
        self,
        group_id: Annotated[Optional[str], Field(description="Filter by group ID")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /dashboards/v2/{account_id}/dashboards — list dashboards."""
        params = {}
        if group_id:
            params["group_id"] = group_id
        return self._get(
            "/dashboards/v2/{account_id}/dashboards",
            account_id=account_id,
            params=params or None,
        )

    def dashboards_get(
        self,
        dashboard_id: Annotated[str, Field(description="Dashboard ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /dashboards/v2/{account_id}/dashboards/{dashboard_id}"""
        return self._get(
            f"/dashboards/v2/{{account_id}}/dashboards/{dashboard_id}",
            account_id=account_id,
        )

    def dashboards_create(
        self,
        name: Annotated[str, Field(description="Dashboard name")],
        layout_id: Annotated[str, Field(description="Layout template ID")],
        widgets: Annotated[Optional[List[dict]], Field(
            description="List of widget configuration dicts"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /dashboards/v2/{account_id}/dashboards — create a dashboard."""
        body: dict = {
            "name": name,
            "layout_id": layout_id,
            "widgets": widgets if widgets is not None else [],
        }
        return self._post(
            "/dashboards/v2/{account_id}/dashboards",
            account_id=account_id,
            json_body=body,
        )

    def dashboards_update(
        self,
        dashboard_id: Annotated[str, Field(description="Dashboard ID to update")],
        name: Annotated[Optional[str], Field(description="Updated dashboard name")] = None,
        layout_id: Annotated[Optional[str], Field(description="Updated layout ID")] = None,
        widgets: Annotated[Optional[List[dict]], Field(description="Updated widget list")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /dashboards/v2/{account_id}/dashboards/{dashboard_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if layout_id is not None:
            body["layout_id"] = layout_id
        if widgets is not None:
            body["widgets"] = widgets
        return self._put(
            f"/dashboards/v2/{{account_id}}/dashboards/{dashboard_id}",
            account_id=account_id,
            json_body=body,
        )

    def dashboards_delete(
        self,
        dashboard_id: Annotated[str, Field(description="Dashboard ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /dashboards/v2/{account_id}/dashboards/{dashboard_id}"""
        return self._delete(
            f"/dashboards/v2/{{account_id}}/dashboards/{dashboard_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = CommonModule()
    mod.register_tools(server)
