"""
AlertLogic Strawboss — Scan Job Orchestration Service (v1).

Strawboss is Alert Logic's background scan-job orchestration service.
It manages the lifecycle of scan jobs dispatched to scan appliances:
queuing, execution state, worker assignment, results retrieval, and
manual control (cancel/retry).

Console API reference: https://console.cloudinsight.alertlogic.com/api/strawboss/
Service host: https://strawboss.mdr.global.alertlogic.com

Endpoint surface (reverse-engineered from console docs and AL internal naming):

  GET    /strawboss/v1/{account_id}/jobs
  GET    /strawboss/v1/{account_id}/jobs/{job_id}
  DELETE /strawboss/v1/{account_id}/jobs/{job_id}
  POST   /strawboss/v1/{account_id}/jobs/{job_id}/cancel
  POST   /strawboss/v1/{account_id}/jobs/{job_id}/retry
  GET    /strawboss/v1/{account_id}/jobs/{job_id}/results
  GET    /strawboss/v1/{account_id}/workers
  GET    /strawboss/v1/{account_id}/workers/{worker_id}
  GET    /strawboss/v1/{account_id}/queue
  DELETE /strawboss/v1/{account_id}/queue/{job_id}
"""
import os
from typing import Annotated, Literal, Optional

from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


JobStatus = Literal[
    "queued",
    "assigned",
    "running",
    "completed",
    "failed",
    "cancelled",
    "timeout",
]

ScanJobType = Literal[
    "vulnerability",
    "external",
    "discovery",
    "abs",
]


class StrawbossModule(BaseModule):
    """
    Strawboss v1 — scan job orchestration, worker state, and queue management.

    All endpoints are under https://strawboss.mdr.global.alertlogic.com.
    """

    def __init__(self):
        super().__init__()
        self.service_hosts["strawboss"] = os.environ.get(
            "ALERTLOGIC_STRAWBOSS_BASE_URL",
            "https://strawboss.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        # Job queries
        self._add_tool(
            server, self.strawboss_list_jobs, "strawboss_list_jobs",
            "List scan jobs for an account, optionally filtered by status, scan type, or deployment",
        )
        self._add_tool(
            server, self.strawboss_get_job, "strawboss_get_job",
            "Get the full detail of a single scan job by ID",
        )
        self._add_tool(
            server, self.strawboss_get_job_results, "strawboss_get_job_results",
            "Retrieve the results payload for a completed scan job",
        )
        # Job control
        self._add_tool(
            server, self.strawboss_cancel_job, "strawboss_cancel_job",
            "Cancel a queued or running scan job",
        )
        self._add_tool(
            server, self.strawboss_retry_job, "strawboss_retry_job",
            "Retry a failed or cancelled scan job",
        )
        self._add_tool(
            server, self.strawboss_delete_job, "strawboss_delete_job",
            "Delete a scan job record (terminal state only)",
        )
        # Worker queries
        self._add_tool(
            server, self.strawboss_list_workers, "strawboss_list_workers",
            "List all scan workers/appliances known to the orchestrator for an account",
        )
        self._add_tool(
            server, self.strawboss_get_worker, "strawboss_get_worker",
            "Get the state and current assignment of a single scan worker by ID",
        )
        # Queue
        self._add_tool(
            server, self.strawboss_get_queue, "strawboss_get_queue",
            "Inspect the current scan job queue — shows queued depth and pending job summaries",
        )
        self._add_tool(
            server, self.strawboss_remove_from_queue, "strawboss_remove_from_queue",
            "Remove a specific job from the queue before it is assigned to a worker",
        )

    # ------------------------------------------------------------------ #
    #  Jobs                                                               #
    # ------------------------------------------------------------------ #

    def strawboss_list_jobs(
        self,
        status: Annotated[
            Optional[JobStatus],
            Field(
                description=(
                    "Filter by job status: queued | assigned | running | "
                    "completed | failed | cancelled | timeout. "
                    "Omit to return jobs in all states."
                )
            ),
        ] = None,
        scan_type: Annotated[
            Optional[ScanJobType],
            Field(
                description=(
                    "Filter by scan type: vulnerability | external | discovery | abs. "
                    "Omit to return all scan types."
                )
            ),
        ] = None,
        deployment_id: Annotated[
            Optional[str],
            Field(description="Filter by deployment UUID"),
        ] = None,
        limit: Annotated[
            Optional[int],
            Field(description="Maximum number of jobs to return (default: server-defined)"),
        ] = None,
        offset: Annotated[
            Optional[int],
            Field(description="Pagination offset (number of records to skip)"),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID (uses ALERTLOGIC_ACCOUNT_ID env var if omitted)"),
        ] = None,
    ) -> dict:
        """
        List scan jobs for the account.

        GET /strawboss/v1/{account_id}/jobs
        """
        params: dict = {}
        if status:
            params["status"] = status
        if scan_type:
            params["scan_type"] = scan_type
        if deployment_id:
            params["deployment_id"] = deployment_id
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        return self._get_at(
            "strawboss",
            "/strawboss/v1/{account_id}/jobs",
            account_id=account_id,
            params=params or None,
        )

    def strawboss_get_job(
        self,
        job_id: Annotated[str, Field(description="Scan job UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Get the full detail of a scan job.

        GET /strawboss/v1/{account_id}/jobs/{job_id}
        """
        return self._get_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/jobs/{job_id}",
            account_id=account_id,
        )

    def strawboss_get_job_results(
        self,
        job_id: Annotated[str, Field(description="Scan job UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Retrieve the results payload for a completed scan job.
        Returns 404 if the job is not yet in a terminal state.

        GET /strawboss/v1/{account_id}/jobs/{job_id}/results
        """
        return self._get_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/jobs/{job_id}/results",
            account_id=account_id,
        )

    def strawboss_cancel_job(
        self,
        job_id: Annotated[str, Field(description="Scan job UUID to cancel")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Cancel a queued or running scan job.
        Returns 409 if the job is already in a terminal state.

        POST /strawboss/v1/{account_id}/jobs/{job_id}/cancel
        """
        return self._post_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/jobs/{job_id}/cancel",
            account_id=account_id,
        )

    def strawboss_retry_job(
        self,
        job_id: Annotated[str, Field(description="Scan job UUID to retry")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Retry a failed or cancelled scan job.
        The job is re-queued and assigned a new execution attempt.
        Returns 409 if the job is not in a retryable state.

        POST /strawboss/v1/{account_id}/jobs/{job_id}/retry
        """
        return self._post_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/jobs/{job_id}/retry",
            account_id=account_id,
        )

    def strawboss_delete_job(
        self,
        job_id: Annotated[str, Field(description="Scan job UUID to delete")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Delete a scan job record.
        Only allowed for jobs in a terminal state (completed, failed, cancelled).
        Returns 204 No Content on success.

        DELETE /strawboss/v1/{account_id}/jobs/{job_id}
        """
        return self._delete_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/jobs/{job_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Workers                                                            #
    # ------------------------------------------------------------------ #

    def strawboss_list_workers(
        self,
        deployment_id: Annotated[
            Optional[str],
            Field(description="Filter workers by deployment UUID"),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        List scan workers (appliances) registered to the orchestrator.
        Each worker includes its current assignment, health state, and
        the deployment it belongs to.

        GET /strawboss/v1/{account_id}/workers
        """
        params: dict = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        return self._get_at(
            "strawboss",
            "/strawboss/v1/{account_id}/workers",
            account_id=account_id,
            params=params or None,
        )

    def strawboss_get_worker(
        self,
        worker_id: Annotated[str, Field(description="Worker/appliance UUID")],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Get the state and current job assignment of a single scan worker.

        GET /strawboss/v1/{account_id}/workers/{worker_id}
        """
        return self._get_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/workers/{worker_id}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  Queue                                                              #
    # ------------------------------------------------------------------ #

    def strawboss_get_queue(
        self,
        deployment_id: Annotated[
            Optional[str],
            Field(description="Filter queue view by deployment UUID"),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Inspect the current scan job queue.
        Returns queue depth and the list of pending job summaries in
        dispatch order.

        GET /strawboss/v1/{account_id}/queue
        """
        params: dict = {}
        if deployment_id:
            params["deployment_id"] = deployment_id
        return self._get_at(
            "strawboss",
            "/strawboss/v1/{account_id}/queue",
            account_id=account_id,
            params=params or None,
        )

    def strawboss_remove_from_queue(
        self,
        job_id: Annotated[
            str,
            Field(description="Job UUID to remove from the queue"),
        ],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID"),
        ] = None,
    ) -> dict:
        """
        Remove a specific job from the queue before it is picked up by a worker.
        Returns 404 if the job is no longer in a queued state.
        Returns 204 No Content on success.

        DELETE /strawboss/v1/{account_id}/queue/{job_id}
        """
        return self._delete_at(
            "strawboss",
            f"/strawboss/v1/{{account_id}}/queue/{job_id}",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = StrawbossModule()
    mod.register_tools(server)
