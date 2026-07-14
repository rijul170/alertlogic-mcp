"""
AlertLogic Tickets / Ticketmaster Service.
Case management for security incidents — create, update, comment on, and
transition support tickets via the Ticketmaster v1 API.

Spec: https://console.cloudinsight.alertlogic.com/api/ticketmaster/
Host: https://api.cloudinsight.alertlogic.com  (default base URL)
Base path: /ticketmaster/v1/{account_id}/tickets
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


TicketStatus = Literal["open", "pending", "resolved", "closed"]
TicketPriority = Literal["low", "medium", "high", "critical"]


class TicketsModule(BaseModule):
    """Ticketmaster v1: list, create, update, comment, and transition tickets."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.ticket_list, "ticket_list",
                       "List tickets for an account with optional status/priority filtering")
        self._add_tool(server, self.ticket_get, "ticket_get",
                       "Get a single ticket by ID")
        self._add_tool(server, self.ticket_create, "ticket_create",
                       "Create a new support ticket")
        self._add_tool(server, self.ticket_update, "ticket_update",
                       "Update ticket fields (summary, description, priority, status)")
        self._add_tool(server, self.ticket_add_comment, "ticket_add_comment",
                       "Add a comment to a ticket")
        self._add_tool(server, self.ticket_list_comments, "ticket_list_comments",
                       "List all comments on a ticket")
        self._add_tool(server, self.ticket_close, "ticket_close",
                       "Close a ticket")
        self._add_tool(server, self.ticket_reopen, "ticket_reopen",
                       "Reopen a previously closed ticket")

    # ------------------------------------------------------------------ #
    #  Read operations                                                    #
    # ------------------------------------------------------------------ #

    def ticket_list(
        self,
        status: Annotated[Optional[TicketStatus], Field(
            description="Filter by ticket status: open, pending, resolved, or closed"
        )] = None,
        priority: Annotated[Optional[TicketPriority], Field(
            description="Filter by priority: low, medium, high, or critical"
        )] = None,
        page: Annotated[Optional[int], Field(
            description="Page number (1-based) for pagination"
        )] = None,
        page_size: Annotated[Optional[int], Field(
            description="Number of tickets per page"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List tickets. GET /ticketmaster/v1/{account_id}/tickets"""
        params = {}
        if status is not None:
            params["status"] = status
        if priority is not None:
            params["priority"] = priority
        if page is not None:
            params["page"] = page
        if page_size is not None:
            params["page_size"] = page_size
        return self._get(
            "/ticketmaster/v1/{account_id}/tickets",
            account_id=account_id,
            params=params or None,
        )

    def ticket_get(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID")],
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Get a single ticket. GET /ticketmaster/v1/{account_id}/tickets/{ticket_id}"""
        return self._get(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}",
            account_id=account_id,
        )

    def ticket_list_comments(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID")],
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """List comments on a ticket. GET /ticketmaster/v1/{account_id}/tickets/{ticket_id}/comments"""
        return self._get(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}/comments",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Write operations                                                   #
    # ------------------------------------------------------------------ #

    def ticket_create(
        self,
        summary: Annotated[str, Field(description="Short summary / title of the ticket")],
        description: Annotated[str, Field(description="Full description of the issue")],
        priority: Annotated[TicketPriority, Field(
            description="Ticket priority: low, medium, high, or critical"
        )] = "medium",
        incident_id: Annotated[Optional[str], Field(
            description="Alert Logic incident ID to link this ticket to"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Create a new ticket. POST /ticketmaster/v1/{account_id}/tickets"""
        body: dict = {
            "summary": summary,
            "description": description,
            "priority": priority,
        }
        if incident_id is not None:
            body["incident_id"] = incident_id
        return self._post(
            "/ticketmaster/v1/{account_id}/tickets",
            account_id=account_id,
            json_body=body,
        )

    def ticket_update(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID to update")],
        summary: Annotated[Optional[str], Field(
            description="Updated summary / title"
        )] = None,
        description: Annotated[Optional[str], Field(
            description="Updated description"
        )] = None,
        priority: Annotated[Optional[TicketPriority], Field(
            description="Updated priority: low, medium, high, or critical"
        )] = None,
        status: Annotated[Optional[TicketStatus], Field(
            description="Updated status: open, pending, resolved, or closed"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Update ticket fields. PUT /ticketmaster/v1/{account_id}/tickets/{ticket_id}"""
        body: dict = {}
        if summary is not None:
            body["summary"] = summary
        if description is not None:
            body["description"] = description
        if priority is not None:
            body["priority"] = priority
        if status is not None:
            body["status"] = status
        return self._put(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}",
            account_id=account_id,
            json_body=body,
        )

    def ticket_add_comment(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID to comment on")],
        content: Annotated[str, Field(description="Comment text")],
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Add a comment. POST /ticketmaster/v1/{account_id}/tickets/{ticket_id}/comments"""
        return self._post(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}/comments",
            account_id=account_id,
            json_body={"content": content},
        )

    # ------------------------------------------------------------------ #
    #  State transitions                                                  #
    # ------------------------------------------------------------------ #

    def ticket_close(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID to close")],
        reason: Annotated[Optional[str], Field(
            description="Optional closing reason or notes"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Close a ticket. POST /ticketmaster/v1/{account_id}/tickets/{ticket_id}/close"""
        body: dict = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}/close",
            account_id=account_id,
            json_body=body or None,
        )

    def ticket_reopen(
        self,
        ticket_id: Annotated[str, Field(description="Ticket ID to reopen")],
        reason: Annotated[Optional[str], Field(
            description="Optional reason for reopening"
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Reopen a ticket. POST /ticketmaster/v1/{account_id}/tickets/{ticket_id}/reopen"""
        body: dict = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(
            f"/ticketmaster/v1/{{account_id}}/tickets/{ticket_id}/reopen",
            account_id=account_id,
            json_body=body or None,
        )


def setup(server: FastMCP):
    mod = TicketsModule()
    mod.register_tools(server)
