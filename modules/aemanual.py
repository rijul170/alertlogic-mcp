"""
AlertLogic AEManual — Manual Incident Creation Service.
Allows MDR analysts and integrations to manually create incidents
(observations) outside of the normal analytics engine pipeline. Useful
for documenting analyst-identified threats, threat-hunt findings, or
test incidents.

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/aemanual/aemanual.v1.yaml
Host: https://aemanual.mdr.global.alertlogic.com
"""
import os
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


AemanualThreatRating = Literal["Low", "Medium", "High", "Critical"]
AemanualSource = Literal["MANL", "MANI"]  # MANL=logs, MANI=IDS
AemanualGenType = Literal["analytic", "guardduty", "manual", "threatintel"]


class AemanualModule(BaseModule):
    """
    AEManual — manually create incidents/observations in Alert Logic MDR.

    Bypasses the analytics engine and posts an observation directly to
    the ingest subsystem. Intended for analyst-driven threat documentation
    and integration-sourced findings.
    """

    def __init__(self):
        super().__init__()
        self.service_hosts["aemanual"] = os.environ.get(
            "ALERTLOGIC_AEMANUAL_BASE_URL",
            "https://aemanual.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server,
            self.aemanual_healthcheck,
            "aemanual_healthcheck",
            "Check the health status of the AEManual service",
        )
        self._add_tool(
            server,
            self.aemanual_create_incident,
            "aemanual_create_incident",
            (
                "Manually create an MDR incident observation. "
                "Use for analyst threat-hunt findings, test incidents, or "
                "integration-sourced detections that bypass the analytics engine."
            ),
        )

    # ------------------------------------------------------------------ #
    #  GET /healthcheck                                                    #
    # ------------------------------------------------------------------ #

    def aemanual_healthcheck(self) -> dict:
        """Check the health status of the AEManual service.
        GET /healthcheck on aemanual host.
        """
        return self._get_at("aemanual", "/healthcheck")

    # ------------------------------------------------------------------ #
    #  POST /aemanual/v1/{account_id}/create                              #
    # ------------------------------------------------------------------ #

    def aemanual_create_incident(
        self,
        summary: Annotated[str, Field(
            description="Short summary/title for the incident (displayed in the console)"
        )],
        description: Annotated[str, Field(
            description=(
                "Detailed description of the incident including analyst findings, "
                "attack narrative, and recommended response actions"
            )
        )],
        classification: Annotated[str, Field(
            description=(
                "Incident classification (e.g. 'brute-force', 'ransomware', "
                "'lateral-movement', 'data-exfiltration', 'policy-violation')"
            )
        )],
        time_frame: Annotated[int, Field(
            description="Duration of the incident activity in minutes",
            ge=1,
        )],
        facts: Annotated[List[dict], Field(
            description=(
                "List of supporting evidence/events for the incident. "
                "Each fact object should contain message IDs or log references. "
                "Minimum one fact required. Example: "
                "[{'id': 'msg-uuid-123', 'ts': 1700000000}]"
            )
        )],
        threat_rating: Annotated[Optional[AemanualThreatRating], Field(
            description="Threat severity rating: Low | Medium | High | Critical"
        )] = None,
        sources: Annotated[Optional[List[AemanualSource]], Field(
            description=(
                "Data sources for this incident: "
                "'MANL' (log-based) or 'MANI' (IDS-based). "
                "Defaults to ['MANL'] if omitted."
            )
        )] = None,
        datacenter: Annotated[Optional[str], Field(
            description="Origin datacenter or deployment identifier"
        )] = None,
        gen_type: Annotated[Optional[AemanualGenType], Field(
            description=(
                "Generator type: analytic | guardduty | manual | threatintel. "
                "Use 'manual' for analyst-created incidents."
            )
        )] = None,
        keyedon_value: Annotated[Optional[str], Field(
            description=(
                "Base incident key value — the primary entity this incident keys on "
                "(e.g. source IP, hostname, user account)"
            )
        )] = None,
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Manually create an MDR incident observation.

        Posts a manually-authored observation directly to the Alert Logic
        ingest subsystem, bypassing the analytics engine. The observation
        appears in the Alert Logic console as a customer incident.

        Required fields: summary, description, classification, time_frame, facts.
        At least one fact/evidence item is required.

        POST /aemanual/v1/{account_id}/create on aemanual host.
        """
        acct = account_id or self.account_id
        body: dict = {
            "customer_id": int(acct) if acct and acct.isdigit() else acct,
            "summary": summary,
            "description": description,
            "classification": classification,
            "time_frame": time_frame,
            "facts": facts,
        }
        if threat_rating:
            body["threat_rating"] = threat_rating
        if sources:
            body["sources"] = sources
        if datacenter:
            body["datacenter"] = datacenter
        if gen_type:
            body["gen_type"] = gen_type
        if keyedon_value:
            body["keyedon_value"] = keyedon_value

        return self._post_at(
            "aemanual",
            "/aemanual/v1/{account_id}/create",
            account_id=account_id,
            json_body=body,
        )


def setup(server: FastMCP):
    mod = AemanualModule()
    mod.register_tools(server)
