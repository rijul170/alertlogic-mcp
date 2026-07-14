"""
AlertLogic Incident Management (IRIS Service v3).
Query, complete, reopen, and add feedback to security incidents.

Spec: https://github.com/alertlogic/alertlogic-sdk-definitions
       (apis/iris/iris.v3.yaml)

Note: IRIS v3 paths are /iris/v3/{account_id}/{incident_id}/... — there is no
/incidents segment after account_id, despite the URL pattern looking unusual.
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


# Per spec: customer_feedback_reason and reason_code share this enum.
ReasonCode = Literal[
    "further_action",
    "acceptable_risk",
    "compensating_control",
    "threat_not_valid",
    "not_concluded",
    "other",
]


class IncidentsModule(BaseModule):
    """IRIS v3 incident management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.incidents_list, "incidents_list",
                        "List incidents within a time window (incidents_by_time)")
        self._add_tool(server, self.incidents_get, "incidents_get",
                        "Get a single incident by ID")
        self._add_tool(server, self.incident_get_by_friendly_id, "incident_get_by_friendly_id",
                        "Look up an incident by its short friendly ID")
        self._add_tool(server, self.incidents_complete, "incidents_complete",
                        "Complete (close) an incident with a reason_code")
        self._add_tool(server, self.incidents_reopen, "incidents_reopen",
                        "Reopen a previously completed incident")
        self._add_tool(server, self.incidents_add_feedback, "incidents_add_feedback",
                        "Add customer feedback to an incident")
        self._add_tool(server, self.incidents_get_elaborations, "incidents_get_elaborations",
                        "Fetch raw logs/events (elaborations) associated with an incident")
        self._add_tool(server, self.incidents_list_partner, "incidents_list_partner",
                        "List incidents across all managed sub-accounts (MSSP partner view)")
        self._add_tool(server, self.incidents_list_filters, "incidents_list_filters",
                        "Get available filter options for incident queries")
        self._add_tool(server, self.incidents_get_notes, "incidents_get_notes",
                        "List notes/comments on an incident")
        self._add_tool(server, self.incidents_add_note, "incidents_add_note",
                        "Add a note/comment to an incident")

    # ---- Read ----

    def incidents_list(
        self,
        start_time: Annotated[str, Field(
            description="Start of time window as epoch seconds integer (e.g. 1748736000). Max span: 7 days for incidents_list, 1 day for incidents_list_partner."
        )],
        end_time: Annotated[str, Field(
            description="End of time window as epoch seconds integer (e.g. 1748822400)."
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        limit: Annotated[int, Field(description="Max results")] = 100,
        offset: Annotated[int, Field(description="Result offset")] = 0,
    ) -> dict:
        """List incidents in window. GET /iris/v3/{account_id}/incidents_by_time"""
        params = {
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
            "offset": offset,
            "pagination": "true",
        }
        return self._get(
            "/iris/v3/{account_id}/incidents_by_time",
            account_id=account_id,
            params=params,
        )

    def incidents_get(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get incident. GET /iris/v3/{account_id}/{incident_id}"""
        return self._get(
            f"/iris/v3/{{account_id}}/{incident_id}",
            account_id=account_id,
        )

    def incident_get_by_friendly_id(
        self,
        friendly_id: Annotated[str, Field(description="Short human-readable incident ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get by friendly ID. GET /iris/v3/{account_id}/friendly/{friendly_id}"""
        return self._get(
            f"/iris/v3/{{account_id}}/friendly/{friendly_id}",
            account_id=account_id,
        )

    # ---- Write ----

    def incidents_complete(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        notes: Annotated[str, Field(description="Closing notes (required)")],
        reason_code: Annotated[ReasonCode, Field(description="Reason for closing")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Complete incident. POST /iris/v3/{account_id}/{incident_id}/complete"""
        body = {"notes": notes, "reason_code": reason_code}
        return self._post(
            f"/iris/v3/{{account_id}}/{incident_id}/complete",
            account_id=account_id,
            json_body=body,
        )

    def incidents_reopen(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        notes: Annotated[str, Field(description="Reopen reason (required)")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Reopen incident. POST /iris/v3/{account_id}/{incident_id}/reopen"""
        return self._post(
            f"/iris/v3/{{account_id}}/{incident_id}/reopen",
            account_id=account_id,
            json_body={"notes": notes},
        )

    def incidents_add_feedback(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        customer_feedback: Annotated[str, Field(description="Feedback text")],
        customer_feedback_reason: Annotated[ReasonCode, Field(description="Reason code")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Add feedback. POST /iris/v3/{account_id}/{incident_id}/feedback"""
        body = {
            "customer_feedback": customer_feedback,
            "customer_feedback_reason": customer_feedback_reason,
        }
        return self._post(
            f"/iris/v3/{{account_id}}/{incident_id}/feedback",
            account_id=account_id,
            json_body=body,
        )

    # ---- Elaborations / raw evidence ----

    def incidents_get_elaborations(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        elaboration_type: Annotated[
            Optional[Literal["observation", "event", "log"]],
            Field(description="Filter by elaboration type: observation, event, or log"),
        ] = None,
        limit: Annotated[int, Field(description="Max results")] = 100,
        offset: Annotated[int, Field(description="Result offset")] = 0,
    ) -> dict:
        """Fetch raw logs/events associated with an incident (CRITICAL for SOC investigation).
        GET /iris/v3/{account_id}/{incident_id}/elaborations/associated"""
        params: dict = {"limit": limit, "offset": offset}
        if elaboration_type is not None:
            params["elaboration_type"] = elaboration_type
        return self._get(
            f"/iris/v3/{{account_id}}/{incident_id}/elaborations/associated",
            account_id=account_id,
            params=params,
        )

    # ---- MSSP / partner ----

    def incidents_list_partner(
        self,
        start_time: Annotated[str, Field(
            description="Start of time window as epoch seconds integer (e.g. 1748736000). Max span: 7 days for incidents_list, 1 day for incidents_list_partner."
        )],
        end_time: Annotated[str, Field(
            description="End of time window as epoch seconds integer (e.g. 1748822400)."
        )],
        account_id: Annotated[Optional[str], Field(
            description="Authenticating account ID (used for auth only, not in path)"
        )] = None,
        account_ids: Annotated[Optional[list[str]], Field(
            description="Optional list of managed sub-account IDs to filter results"
        )] = None,
        limit: Annotated[int, Field(description="Max results")] = 100,
        offset: Annotated[int, Field(description="Result offset")] = 0,
    ) -> dict:
        """List incidents across ALL managed sub-accounts (CRITICAL for MSSP).
        GET /iris/v3/partner_incidents — no {account_id} in path; uses parent
        account relationship to retrieve incidents from all managed child accounts."""
        params: dict = {
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
            "offset": offset,
        }
        if account_ids:
            params["account_ids"] = account_ids
        return self._get(
            "/iris/v3/partner_incidents",
            account_id=account_id,
            params=params,
        )

    # ---- Filter discovery ----

    def incidents_list_filters(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get available filter options for incident queries.
        GET /iris/v3/incident_filters"""
        return self._get(
            "/iris/v3/incident_filters",
            account_id=account_id,
        )

    # ---- Notes ----

    def incidents_get_notes(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List notes/comments on an incident.
        GET /iris/v3/{account_id}/{incident_id}/notes"""
        return self._get(
            f"/iris/v3/{{account_id}}/{incident_id}/notes",
            account_id=account_id,
        )

    def incidents_add_note(
        self,
        incident_id: Annotated[str, Field(description="Incident ID")],
        note: Annotated[str, Field(description="Note text to add to the incident")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Add a note/comment to an incident.
        POST /iris/v3/{account_id}/{incident_id}/notes"""
        return self._post(
            f"/iris/v3/{{account_id}}/{incident_id}/notes",
            account_id=account_id,
            json_body={"note": note},
        )


def setup(server: FastMCP):
    mod = IncidentsModule()
    mod.register_tools(server)
