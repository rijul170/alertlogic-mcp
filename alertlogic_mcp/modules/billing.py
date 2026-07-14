"""
AlertLogic Billing & Subscriptions.
View and manage subscription entitlements.

Maps to: Subscriptions API
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class BillingModule(BaseModule):
    """Subscription and entitlement management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.subscriptions_list, "subscriptions_list",
                        "List all subscriptions/entitlements for an account")
        self._add_tool(server, self.subscriptions_get, "subscriptions_get",
                        "Get subscription details")
        self._add_tool(server, self.herald_list_notifications_by_type,
                        "herald_list_notifications_by_type",
                        "List notifications filtered by type (e.g. incidents, health, scheduled_report)")
        self._add_tool(server, self.herald_get_incident_notifications,
                        "herald_get_incident_notifications",
                        "Get all notifications sent for a specific incident")
        self._add_tool(server, self.herald_update_subscription,
                        "herald_update_subscription",
                        "Update a notification subscription")
        self._add_tool(server, self.herald_delete_subscriptions_batch,
                        "herald_delete_subscriptions_batch",
                        "Delete multiple notification subscriptions at once")
        self._add_tool(server, self.herald_list_subscribers,
                        "herald_list_subscribers",
                        "List all subscribers for a notification subscription")
        self._add_tool(server, self.herald_add_subscriber,
                        "herald_add_subscriber",
                        "Add a subscriber to a notification subscription")
        self._add_tool(server, self.herald_remove_subscriber,
                        "herald_remove_subscriber",
                        "Remove a specific subscriber from a notification subscription")
        self._add_tool(server, self.herald_update_subscribers_batch,
                        "herald_update_subscribers_batch",
                        "Bulk add/remove subscribers for a notification subscription")
        self._add_tool(server, self.subscriptions_list_entitlements,
                        "subscriptions_list_entitlements",
                        "List account entitlements (what the account is licensed for)")
        self._add_tool(server, self.subscriptions_get_accounts_with_entitlement,
                        "subscriptions_get_accounts_with_entitlement",
                        "Find all accounts that have a given product entitlement")

    # ------------------------------------------------------------------ #
    # Existing endpoints                                                   #
    # ------------------------------------------------------------------ #

    def subscriptions_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List subscriptions. GET /subscriptions/v1/{account_id}/subscriptions"""
        return self._get_global("/subscriptions/v1/{account_id}/subscriptions", account_id=account_id)

    def subscriptions_get(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get subscription. GET /subscriptions/v1/{account_id}/subscription/{subscription_id}"""
        return self._get_global(
            f"/subscriptions/v1/{{account_id}}/subscription/{subscription_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    # Herald v2 — notification endpoints                                   #
    # ------------------------------------------------------------------ #

    def herald_list_notifications_by_type(
        self,
        notification_type: Annotated[str, Field(
            description="Notification type, e.g. 'incidents', 'health', 'scheduled_report'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List notifications filtered by type.
        GET /herald/v2/{account_id}/notifications/{notification_type}"""
        return self._get_global(
            f"/herald/v2/{{account_id}}/notifications/{notification_type}",
            account_id=account_id,
        )

    def herald_get_incident_notifications(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get all notifications sent for a specific incident.
        GET /herald/v2/{account_id}/notifications/type/incidents/alerts/{incident_id}"""
        return self._get_global(
            f"/herald/v2/{{account_id}}/notifications/type/incidents/alerts/{incident_id}",
            account_id=account_id,
        )

    def herald_update_subscription(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID to update")],
        body: Annotated[dict, Field(
            description="Update payload (e.g. {name, enabled, filters})")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Update a notification subscription.
        POST /herald/v2/{account_id}/subscriptions/{subscription_id}"""
        return self._post_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}",
            json=body,
            account_id=account_id,
        )

    def herald_delete_subscriptions_batch(
        self,
        ids: Annotated[list, Field(description="List of subscription IDs to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete multiple subscriptions at once.
        POST /herald/v2/{account_id}/subscriptions/batch/delete"""
        return self._post_global(
            "/herald/v2/{account_id}/subscriptions/batch/delete",
            json={"ids": ids},
            account_id=account_id,
        )

    def herald_list_subscribers(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List all subscribers for a subscription.
        GET /herald/v2/{account_id}/subscriptions/{subscription_id}/subscribers"""
        return self._get_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}/subscribers",
            account_id=account_id,
        )

    def herald_add_subscriber(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        subscriber_type: Annotated[str, Field(
            description="Subscriber type: 'user', 'email', or 'webhook'")],
        subscriber: Annotated[str, Field(
            description="User ID, email address, or webhook URL depending on type")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Add a subscriber to a subscription.
        POST /herald/v2/{account_id}/subscriptions/{subscription_id}/subscribers"""
        return self._post_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}/subscribers",
            json={"type": subscriber_type, "subscriber": subscriber},
            account_id=account_id,
        )

    def herald_remove_subscriber(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        subscriber_type: Annotated[str, Field(
            description="Subscriber type: 'user', 'email', or 'webhook'")],
        subscriber_id: Annotated[str, Field(
            description="Subscriber identifier (user ID, email, or webhook URL)")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Remove a specific subscriber from a subscription.
        DELETE /herald/v2/{account_id}/subscriptions/{subscription_id}/subscribers/{subscriber_type}/{subscriber_id}"""
        return self._delete_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}/subscribers/{subscriber_type}/{subscriber_id}",
            account_id=account_id,
        )

    def herald_update_subscribers_batch(
        self,
        subscription_id: Annotated[str, Field(description="Subscription ID")],
        add: Annotated[Optional[list], Field(
            description="List of subscriber objects to add")] = None,
        remove: Annotated[Optional[list], Field(
            description="List of subscriber objects to remove")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Bulk add/remove subscribers for a subscription.
        POST /herald/v2/{account_id}/subscriptions/{subscription_id}/subscribers/batch/update"""
        body: dict = {}
        if add is not None:
            body["add"] = add
        if remove is not None:
            body["remove"] = remove
        return self._post_global(
            f"/herald/v2/{{account_id}}/subscriptions/{subscription_id}/subscribers/batch/update",
            json=body,
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    # Subscriptions v1 — entitlement endpoints                            #
    # ------------------------------------------------------------------ #

    def subscriptions_list_entitlements(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List account entitlements (what the account is licensed for).
        GET /subscriptions/v1/{account_id}/entitlements"""
        return self._get_global(
            "/subscriptions/v1/{account_id}/entitlements",
            account_id=account_id,
        )

    def subscriptions_get_accounts_with_entitlement(
        self,
        product_family: Annotated[str, Field(
            description="Product family to filter by, e.g. 'cloud_defender', 'threat_manager'")],
    ) -> dict:
        """Find all accounts that have a given product entitlement.
        GET /subscriptions/v1/account_ids/entitlement/{product_family}"""
        return self._request_global(
            "GET",
            f"/subscriptions/v1/account_ids/entitlement/{product_family}",
        )


def setup(server: FastMCP):
    mod = BillingModule()
    mod.register_tools(server)
