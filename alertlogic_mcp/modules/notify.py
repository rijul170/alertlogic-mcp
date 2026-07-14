"""
AlertLogic Notify Service — Email Notification.
Sends email notifications to Alert Logic users or arbitrary email addresses
using pre-defined templates, with support for template variable substitution
and optional attachments.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/notify/notify.v3.yaml
Host: api.cloudinsight.alertlogic.com (default)
"""
from typing import Annotated, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class NotifyModule(BaseModule):
    """
    Alert Logic Notify v3 — email notification service.

    Two sending modes:
      - Single recipient : user_id (AIMS user) or arbitrary to_email_address
      - Batch recipients : list of arbitrary to_email_addresses
    Both modes use named templates and support variable substitution.
    """

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server,
            self.notify_send_email,
            "notify_send_email",
            (
                "Send an email notification to an AIMS user (by user_id) or an "
                "arbitrary email address using a named template"
            ),
        )
        self._add_tool(
            server,
            self.notify_send_emails,
            "notify_send_emails",
            (
                "Send an email notification to multiple arbitrary email addresses "
                "using a named template"
            ),
        )

    # ------------------------------------------------------------------ #
    #  POST /notify/v3/{account_id}/email                                 #
    # ------------------------------------------------------------------ #

    def notify_send_email(
        self,
        template_name: Annotated[str, Field(
            description="Name of the email template to render (e.g. 'incident_notification')"
        )],
        template_variables: Annotated[dict, Field(
            description=(
                "Key-value pairs used to populate the template. "
                "Keys depend on the template being used."
            )
        )],
        user_id: Annotated[Optional[str], Field(
            description=(
                "AIMS user ID to send the email to. "
                "Provide either user_id or to_email_address, not both."
            )
        )] = None,
        to_email_address: Annotated[Optional[str], Field(
            description=(
                "Arbitrary recipient email address. "
                "Provide either to_email_address or user_id, not both."
            )
        )] = None,
        subject: Annotated[Optional[str], Field(
            description="Custom subject line (overrides the template default)"
        )] = None,
        from_email_address: Annotated[Optional[str], Field(
            description="Verified sender email address (overrides the template default)"
        )] = None,
        attachments: Annotated[Optional[List[dict]], Field(
            description=(
                "List of attachment objects. Each object should have: "
                "{'name': str, 'url': str, 'description': str (optional)}."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Send an email to an AIMS user or arbitrary address using a template.
        POST /notify/v3/{account_id}/email on default host.

        Exactly one of user_id or to_email_address is required.
        """
        body: dict = {
            "template_name": template_name,
            "template_variables": template_variables,
        }
        if user_id:
            body["user_id"] = user_id
        if to_email_address:
            body["to_email_address"] = to_email_address
        if subject:
            body["subject"] = subject
        if from_email_address:
            body["from_email_address"] = from_email_address
        if attachments:
            body["attachments"] = attachments

        return self._post("/notify/v3/{account_id}/email", account_id=account_id, json_body=body)

    # ------------------------------------------------------------------ #
    #  POST /notify/v3/{account_id}/emails                                #
    # ------------------------------------------------------------------ #

    def notify_send_emails(
        self,
        to_email_addresses: Annotated[List[str], Field(
            description="List of recipient email addresses"
        )],
        template_name: Annotated[str, Field(
            description="Name of the email template to render"
        )],
        template_variables: Annotated[dict, Field(
            description="Key-value pairs used to populate the template"
        )],
        subject: Annotated[Optional[str], Field(
            description="Custom subject line (overrides the template default)"
        )] = None,
        from_email_address: Annotated[Optional[str], Field(
            description="Verified sender email address"
        )] = None,
        attachments: Annotated[Optional[List[dict]], Field(
            description=(
                "List of attachment objects. Each: "
                "{'name': str, 'url': str, 'description': str (optional)}."
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Send an email to multiple arbitrary addresses using a template.
        POST /notify/v3/{account_id}/emails on default host.
        """
        body: dict = {
            "to_email_addresses": to_email_addresses,
            "template_name": template_name,
            "template_variables": template_variables,
        }
        if subject:
            body["subject"] = subject
        if from_email_address:
            body["from_email_address"] = from_email_address
        if attachments:
            body["attachments"] = attachments

        return self._post("/notify/v3/{account_id}/emails", account_id=account_id, json_body=body)


def setup(server: FastMCP):
    mod = NotifyModule()
    mod.register_tools(server)
