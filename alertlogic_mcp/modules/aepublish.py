"""
AlertLogic Analytics Engine Observation Publisher (AEPublish).
Publishes observations to the Alert Logic Ingest subsystem and returns
per-observation publication outcomes (success, retry, suppressed, etc.).

Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/aepublish/aepublish.v1.yaml
Host: api.global-services.global.alertlogic.com
"""
from typing import Annotated, List, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class AepublishModule(BaseModule):
    """
    AEPublish — observation publication to the Alert Logic Ingest subsystem.

    Accepts a batch of observation objects and returns a per-observation
    outcome:
      - success    : ingest_id + optional checkpoint marker
      - retry      : recommended delay in seconds
      - error      : caller error with optional detail
      - suppressed : duplicate detected within recent period
      - throttled  : quota limit exceeded
      - duplicate  : progress marker already processed
    """

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server,
            self.aepublish_publish_observations,
            "aepublish_publish_observations",
            (
                "Publish one or more observations to the Alert Logic Ingest subsystem. "
                "Returns per-observation outcomes: success/retry/error/suppressed/throttled/duplicate."
            ),
        )

    # ------------------------------------------------------------------ #
    #  POST /aepublish/v1/{account_id}/observation                        #
    # ------------------------------------------------------------------ #

    def aepublish_publish_observations(
        self,
        observations: Annotated[List[dict], Field(
            description=(
                "List of observation objects to publish. Each object must conform to "
                "the Alert Logic observation schema. Typical fields per observation: "
                "{'id': str, 'ts': int, 'type': str, 'severity': str, 'data': {...}}. "
                "Refer to the AIMS/IRIS documentation for the full observation schema."
            )
        )],
        account_id: Annotated[Optional[str], Field(
            description="Alert Logic account ID (uses env default if omitted)"
        )] = None,
    ) -> dict:
        """Publish observations to the Alert Logic Ingest subsystem.

        Sends a batch of observations and returns a publication outcome for
        each one. Outcomes include: success (with ingest_id), retry (with
        recommended delay), error (caller error), suppressed (recent duplicate),
        throttled (quota exceeded), or duplicate (already processed marker).

        POST /aepublish/v1/{account_id}/observation on global-services host.
        """
        return self._post_global(
            "/aepublish/v1/{account_id}/observation",
            account_id=account_id,
            json_body={"observations": observations},
        )


def setup(server: FastMCP):
    mod = AepublishModule()
    mod.register_tools(server)
