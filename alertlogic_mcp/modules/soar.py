"""
AlertLogic SOAR (Responder v1).
Playbooks, executions, inquiries, triggers.

Spec: responder.v1.yaml — host: api.responder.alertlogic.com
       Paths start at /v1/{account_id}/... (no /responder prefix).

Notes:
  - Listing executions is a POST /executions/history (the spec has no GET
    collection endpoint).
  - Creating an execution requires a `payload.type` that matches the
    playbook's declared type. Use responder_get_playbook to discover it.
"""
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


PayloadType = Literal[
    "incident", "observation", "vulnerability", "remediation", "generic", "action",
]
ExecutionStatus = Literal[
    "new", "requested", "scheduled", "delayed", "running",
    "succeeded", "failed", "timeout", "canceled", "pending",
]
InquiryStatus = Literal["pending", "completed"]
SortOrder = Literal["asc", "desc"]


class SOARModule(BaseModule):
    """Responder v1: playbooks, executions, inquiries, triggers."""

    def register_tools(self, server: FastMCP):
        # Playbooks
        self._add_tool(server, self.responder_list_playbooks, "responder_list_playbooks",
                        "List playbooks for an account")
        self._add_tool(server, self.responder_get_playbook, "responder_get_playbook",
                        "Get a playbook by ID or name")
        self._add_tool(server, self.responder_create_playbook, "responder_create_playbook",
                        "Create a new playbook")
        self._add_tool(server, self.responder_update_playbook, "responder_update_playbook",
                        "Update an existing playbook")
        self._add_tool(server, self.responder_delete_playbook, "responder_delete_playbook",
                        "Delete a playbook by ID")
        self._add_tool(server, self.responder_get_playbook_stats, "responder_get_playbook_stats",
                        "Get playbook summary statistics")
        # Playbook templates
        self._add_tool(server, self.responder_list_playbook_templates, "responder_list_playbook_templates",
                        "List available playbook templates")
        self._add_tool(server, self.responder_get_playbook_template, "responder_get_playbook_template",
                        "Get a playbook template by ID")
        self._add_tool(server, self.responder_create_playbook_from_template, "responder_create_playbook_from_template",
                        "Create a playbook from a template")
        # Actions
        self._add_tool(server, self.responder_list_actions, "responder_list_actions",
                        "List available actions")
        self._add_tool(server, self.responder_get_action, "responder_get_action",
                        "Get an action by ref")
        # Executions
        self._add_tool(server, self.responder_create_execution, "responder_create_execution",
                        "Run a playbook or action — POST /executions")
        self._add_tool(server, self.responder_get_execution, "responder_get_execution",
                        "Get an execution by ID")
        self._add_tool(server, self.responder_query_executions, "responder_query_executions",
                        "Query execution history (POST /executions/history)")
        self._add_tool(server, self.responder_cancel_execution, "responder_cancel_execution",
                        "Cancel a running execution")
        self._add_tool(server, self.responder_rerun_execution, "responder_rerun_execution",
                        "Re-run a completed or failed execution")
        self._add_tool(server, self.responder_pause_execution, "responder_pause_execution",
                        "Pause a running execution")
        self._add_tool(server, self.responder_resume_execution, "responder_resume_execution",
                        "Resume a paused execution")
        # Inquiries
        self._add_tool(server, self.responder_list_inquiries, "responder_list_inquiries",
                        "List inquiries (paused playbooks awaiting input)")
        self._add_tool(server, self.responder_get_inquiry, "responder_get_inquiry",
                        "Get an inquiry by ID")
        self._add_tool(server, self.responder_respond_to_inquiry, "responder_respond_to_inquiry",
                        "Submit a response to an inquiry")
        self._add_tool(server, self.responder_query_inquiry_history, "responder_query_inquiry_history",
                        "Query inquiry history with filters")
        # Triggers
        self._add_tool(server, self.responder_list_triggers, "responder_list_triggers",
                        "List triggers wired to playbooks/actions")
        self._add_tool(server, self.responder_create_trigger, "responder_create_trigger",
                        "Create a new trigger")
        self._add_tool(server, self.responder_get_trigger, "responder_get_trigger",
                        "Get a trigger by ID")
        self._add_tool(server, self.responder_update_trigger, "responder_update_trigger",
                        "Update an existing trigger")
        self._add_tool(server, self.responder_delete_trigger, "responder_delete_trigger",
                        "Delete a trigger by ID")
        # Managed Response configs
        self._add_tool(server, self.responder_list_mr_configs, "responder_list_mr_configs",
                        "List Managed Response configurations")
        self._add_tool(server, self.responder_get_mr_config, "responder_get_mr_config",
                        "Get a Managed Response configuration by ID")
        self._add_tool(server, self.responder_create_mr_config, "responder_create_mr_config",
                        "Create a Managed Response configuration")
        self._add_tool(server, self.responder_update_mr_config, "responder_update_mr_config",
                        "Update a Managed Response configuration")
        self._add_tool(server, self.responder_delete_mr_config, "responder_delete_mr_config",
                        "Delete a Managed Response configuration")
        # Limits
        self._add_tool(server, self.responder_get_limits, "responder_get_limits",
                        "Get execution rate limits for an account")

    # ---- Playbooks ----

    def responder_list_playbooks(
        self,
        playbook_type: Annotated[Optional[str], Field(
            description="Comma-separated playbook types"
        )] = None,
        vendors: Annotated[Optional[str], Field(description="Comma-separated vendors")] = None,
        enabled: Annotated[Optional[bool], Field(description="Filter by enabled flag")] = None,
        deleted: Annotated[bool, Field(description="Include deleted playbooks")] = False,
        sort_order: Annotated[SortOrder, Field(description="Sort order")] = "desc",
        limit: Annotated[Optional[int], Field(description="Max results")] = None,
        marker: Annotated[Optional[str], Field(description="Pagination marker")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/playbooks on responder host"""
        params = {"sort_order": sort_order, "deleted": str(deleted).lower()}
        if playbook_type:
            params["type"] = playbook_type
        if vendors:
            params["vendors"] = vendors
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        if limit is not None:
            params["limit"] = limit
        if marker:
            params["marker"] = marker
        return self._get_at(
            "responder",
            "/v1/{account_id}/playbooks",
            account_id=account_id,
            params=params,
        )

    def responder_get_playbook(
        self,
        playbook: Annotated[str, Field(description="Playbook ID or name")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/playbooks/{id_or_name}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/playbooks/{playbook}",
            account_id=account_id,
        )

    def responder_create_playbook(
        self,
        name: Annotated[str, Field(description="Playbook name")],
        playbook_type: Annotated[str, Field(description="Playbook type (e.g. incident, observation, generic)")],
        enabled: Annotated[bool, Field(description="Whether the playbook is enabled")] = True,
        description: Annotated[Optional[str], Field(description="Human-readable description")] = None,
        payload_type: Annotated[Optional[PayloadType], Field(description="Expected payload type")] = None,
        tags: Annotated[Optional[List[str]], Field(description="List of tags")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/playbooks"""
        body: dict = {"name": name, "type": playbook_type, "enabled": enabled}
        if description is not None:
            body["description"] = description
        if payload_type is not None:
            body["payload_type"] = payload_type
        if tags is not None:
            body["tags"] = tags
        return self._post_at(
            "responder",
            "/v1/{account_id}/playbooks",
            account_id=account_id,
            json_body=body,
        )

    def responder_update_playbook(
        self,
        playbook_id: Annotated[str, Field(description="Playbook ID to update")],
        name: Annotated[Optional[str], Field(description="New playbook name")] = None,
        playbook_type: Annotated[Optional[str], Field(description="New playbook type")] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable or disable the playbook")] = None,
        description: Annotated[Optional[str], Field(description="New description")] = None,
        payload_type: Annotated[Optional[PayloadType], Field(description="New payload type")] = None,
        tags: Annotated[Optional[List[str]], Field(description="New list of tags")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /v1/{account_id}/playbooks/{playbook_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if playbook_type is not None:
            body["type"] = playbook_type
        if enabled is not None:
            body["enabled"] = enabled
        if description is not None:
            body["description"] = description
        if payload_type is not None:
            body["payload_type"] = payload_type
        if tags is not None:
            body["tags"] = tags
        return self._put_at(
            "responder",
            f"/v1/{{account_id}}/playbooks/{playbook_id}",
            account_id=account_id,
            json_body=body,
        )

    def responder_delete_playbook(
        self,
        playbook_id: Annotated[str, Field(description="Playbook ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /v1/{account_id}/playbooks/{playbook_id}"""
        return self._delete_at(
            "responder",
            f"/v1/{{account_id}}/playbooks/{playbook_id}",
            account_id=account_id,
        )

    def responder_get_playbook_stats(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/summary/playbooks"""
        return self._get_at(
            "responder",
            "/v1/{account_id}/summary/playbooks",
            account_id=account_id,
        )

    # ---- Playbook templates ----

    def responder_list_playbook_templates(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/playbook_templates"""
        return self._get_at(
            "responder",
            "/v1/{account_id}/playbook_templates",
            account_id=account_id,
        )

    def responder_get_playbook_template(
        self,
        template_id: Annotated[str, Field(description="Playbook template ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/playbook_templates/{template_id}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/playbook_templates/{template_id}",
            account_id=account_id,
        )

    def responder_create_playbook_from_template(
        self,
        template_id: Annotated[str, Field(description="Template ID to instantiate")],
        name: Annotated[Optional[str], Field(description="Name for the new playbook")] = None,
        enabled: Annotated[Optional[bool], Field(description="Whether the new playbook is enabled")] = None,
        description: Annotated[Optional[str], Field(description="Description for the new playbook")] = None,
        tags: Annotated[Optional[List[str]], Field(description="Tags for the new playbook")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/playbook_templates/{template_id}/playbooks"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if enabled is not None:
            body["enabled"] = enabled
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        return self._post_at(
            "responder",
            f"/v1/{{account_id}}/playbook_templates/{template_id}/playbooks",
            account_id=account_id,
            json_body=body,
        )

    # ---- Actions ----

    def responder_list_actions(
        self,
        action_type: Annotated[Optional[str], Field(description="Filter by action type")] = None,
        vendor: Annotated[Optional[str], Field(description="Filter by vendor")] = None,
        enabled: Annotated[Optional[bool], Field(description="Filter by enabled flag")] = None,
        limit: Annotated[Optional[int], Field(description="Max results")] = None,
        marker: Annotated[Optional[str], Field(description="Pagination marker")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/actions"""
        params: dict = {}
        if action_type:
            params["type"] = action_type
        if vendor:
            params["vendor"] = vendor
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        if limit is not None:
            params["limit"] = limit
        if marker:
            params["marker"] = marker
        return self._get_at(
            "responder",
            "/v1/{account_id}/actions",
            account_id=account_id,
            params=params or None,
        )

    def responder_get_action(
        self,
        action_ref: Annotated[str, Field(description="Action ref or ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/actions/{action_ref}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/actions/{action_ref}",
            account_id=account_id,
        )

    # ---- Executions ----

    def responder_create_execution(
        self,
        ref: Annotated[str, Field(
            description="Playbook ID, playbook name, action ID, or action ref"
        )],
        payload: Annotated[dict, Field(
            description=(
                "Payload object. Must include `type` matching the playbook's "
                "declared payload type. Variants: "
                "{type:'incident', incident: {...}}, "
                "{type:'observation', observation: {...}}, "
                "{type:'action', parameters: {...}}, "
                "{type:'generic', parameters: {...}}, "
                "{type:'vulnerability'|'remediation', parameters: {...}}"
            )
        )],
        trigger_id: Annotated[Optional[str], Field(description="Trigger UUID")] = None,
        target_account_id: Annotated[Optional[str], Field(description="Target account for cross-account execution")] = None,
        account_id: Annotated[Optional[str], Field(description="Caller account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/executions"""
        body = {"ref": ref, "payload": payload}
        if trigger_id:
            body["trigger_id"] = trigger_id
        if target_account_id:
            body["target_account_id"] = target_account_id
        return self._post_at(
            "responder",
            "/v1/{account_id}/executions",
            account_id=account_id,
            json_body=body,
        )

    def responder_get_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/executions/{execution_id}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/executions/{execution_id}",
            account_id=account_id,
        )

    def responder_query_executions(
        self,
        query: Annotated[dict, Field(
            description=(
                "Query body. REQUIRED field: 'execution_type' — one of 'playbook', 'task', or 'action'. "
                "Example: {execution_type: 'playbook', start_timestamp: 1700000000, limit: 50}"
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/executions/history"""
        return self._post_at(
            "responder",
            "/v1/{account_id}/executions/history",
            account_id=account_id,
            json_body=query,
        )

    def responder_cancel_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution ID to cancel")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /v1/{account_id}/executions/{execution_id}"""
        return self._delete_at(
            "responder",
            f"/v1/{{account_id}}/executions/{execution_id}",
            account_id=account_id,
        )

    def responder_rerun_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution ID to re-run")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/executions/{execution_id}/re_run"""
        return self._post_at(
            "responder",
            f"/v1/{{account_id}}/executions/{execution_id}/re_run",
            account_id=account_id,
            json_body={},
        )

    def responder_pause_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution ID to pause")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/executions/{execution_id}/pause"""
        return self._post_at(
            "responder",
            f"/v1/{{account_id}}/executions/{execution_id}/pause",
            account_id=account_id,
            json_body={},
        )

    def responder_resume_execution(
        self,
        execution_id: Annotated[str, Field(description="Execution ID to resume")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/executions/{execution_id}/resume"""
        return self._post_at(
            "responder",
            f"/v1/{{account_id}}/executions/{execution_id}/resume",
            account_id=account_id,
            json_body={},
        )

    # ---- Inquiries ----

    def responder_list_inquiries(
        self,
        status: Annotated[Optional[InquiryStatus], Field(description="pending/completed")] = None,
        deployment_id: Annotated[Optional[str], Field(description="Filter by deployment")] = None,
        inquiry_type: Annotated[Optional[str], Field(description="Filter by inquiry type")] = None,
        start_timestamp: Annotated[Optional[int], Field(description="Epoch lower bound")] = None,
        end_timestamp: Annotated[Optional[int], Field(description="Epoch upper bound")] = None,
        sort_by: Annotated[Optional[str], Field(description="Sort field")] = None,
        sort_order: Annotated[SortOrder, Field(description="Sort order")] = "desc",
        limit: Annotated[Optional[int], Field(description="Max results")] = None,
        marker: Annotated[Optional[str], Field(description="Pagination marker")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/inquiries"""
        params = {"sort_order": sort_order}
        if status:
            params["status"] = status
        if deployment_id:
            params["deployment_id"] = deployment_id
        if inquiry_type:
            params["type"] = inquiry_type
        if start_timestamp is not None:
            params["start_timestamp"] = start_timestamp
        if end_timestamp is not None:
            params["end_timestamp"] = end_timestamp
        if sort_by:
            params["sort_by"] = sort_by
        if limit is not None:
            params["limit"] = limit
        if marker:
            params["marker"] = marker
        return self._get_at(
            "responder",
            "/v1/{account_id}/inquiries",
            account_id=account_id,
            params=params,
        )

    def responder_get_inquiry(
        self,
        inquiry_id: Annotated[str, Field(description="Inquiry ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/inquiries/{inquiry_id}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/inquiries/{inquiry_id}",
            account_id=account_id,
        )

    def responder_respond_to_inquiry(
        self,
        inquiry_id: Annotated[str, Field(description="Inquiry ID to respond to")],
        response: Annotated[dict, Field(
            description=(
                "Response data. Shape varies by inquiry type — typically contains "
                "fields such as `answer`, `approved`, or custom parameters "
                "defined by the playbook step that raised the inquiry."
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /v1/{account_id}/inquiries/{inquiry_id}"""
        return self._put_at(
            "responder",
            f"/v1/{{account_id}}/inquiries/{inquiry_id}",
            account_id=account_id,
            json_body=response,
        )

    def responder_query_inquiry_history(
        self,
        query: Annotated[dict, Field(
            description=(
                "Query filter body. Supported fields vary by implementation; "
                "common keys include playbook_id, execution_id, "
                "start_timestamp, end_timestamp, limit, marker."
            )
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/inquiries/history"""
        return self._post_at(
            "responder",
            "/v1/{account_id}/inquiries/history",
            account_id=account_id,
            json_body=query,
        )

    # ---- Triggers ----

    def responder_list_triggers(
        self,
        trigger_type: Annotated[Optional[str], Field(description="Comma-separated trigger types")] = None,
        enabled: Annotated[Optional[bool], Field(description="Filter by enabled flag")] = None,
        playbooks: Annotated[Optional[str], Field(description="Comma-separated playbook IDs")] = None,
        actions: Annotated[Optional[str], Field(description="Comma-separated action refs")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/triggers"""
        params = {}
        if trigger_type:
            params["type"] = trigger_type
        if enabled is not None:
            params["enabled"] = str(enabled).lower()
        if playbooks:
            params["playbooks"] = playbooks
        if actions:
            params["actions"] = actions
        return self._get_at(
            "responder",
            "/v1/{account_id}/triggers",
            account_id=account_id,
            params=params or None,
        )

    def responder_create_trigger(
        self,
        name: Annotated[str, Field(description="Trigger name")],
        trigger_type: Annotated[str, Field(description="Trigger type (e.g. scheduled, event)")],
        enabled: Annotated[bool, Field(description="Whether the trigger is enabled")] = True,
        playbook_id: Annotated[Optional[str], Field(description="Playbook ID to fire")] = None,
        action_ref: Annotated[Optional[str], Field(description="Action ref to fire (alternative to playbook_id)")] = None,
        filters: Annotated[Optional[dict], Field(description="Trigger filter conditions")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/triggers"""
        body: dict = {"name": name, "type": trigger_type, "enabled": enabled}
        if playbook_id is not None:
            body["playbook_id"] = playbook_id
        if action_ref is not None:
            body["action_ref"] = action_ref
        if filters is not None:
            body["filters"] = filters
        return self._post_at(
            "responder",
            "/v1/{account_id}/triggers",
            account_id=account_id,
            json_body=body,
        )

    def responder_get_trigger(
        self,
        trigger_id: Annotated[str, Field(description="Trigger ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/triggers/{trigger_id}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/triggers/{trigger_id}",
            account_id=account_id,
        )

    def responder_update_trigger(
        self,
        trigger_id: Annotated[str, Field(description="Trigger ID to update")],
        name: Annotated[Optional[str], Field(description="New trigger name")] = None,
        enabled: Annotated[Optional[bool], Field(description="Enable or disable the trigger")] = None,
        filters: Annotated[Optional[dict], Field(description="New filter conditions")] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /v1/{account_id}/triggers/{trigger_id}"""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if enabled is not None:
            body["enabled"] = enabled
        if filters is not None:
            body["filters"] = filters
        return self._put_at(
            "responder",
            f"/v1/{{account_id}}/triggers/{trigger_id}",
            account_id=account_id,
            json_body=body,
        )

    def responder_delete_trigger(
        self,
        trigger_id: Annotated[str, Field(description="Trigger ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /v1/{account_id}/triggers/{trigger_id}"""
        return self._delete_at(
            "responder",
            f"/v1/{{account_id}}/triggers/{trigger_id}",
            account_id=account_id,
        )

    # ---- Managed Response configs ----

    def responder_list_mr_configs(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/mr_configs"""
        return self._get_at(
            "responder",
            "/v1/{account_id}/mr_configs",
            account_id=account_id,
        )

    def responder_get_mr_config(
        self,
        config_id: Annotated[str, Field(description="MR config ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/mr_configs/{config_id}"""
        return self._get_at(
            "responder",
            f"/v1/{{account_id}}/mr_configs/{config_id}",
            account_id=account_id,
        )

    def responder_create_mr_config(
        self,
        config: Annotated[dict, Field(description="Managed Response configuration object")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """POST /v1/{account_id}/mr_configs"""
        return self._post_at(
            "responder",
            "/v1/{account_id}/mr_configs",
            account_id=account_id,
            json_body=config,
        )

    def responder_update_mr_config(
        self,
        config_id: Annotated[str, Field(description="MR config ID to update")],
        config: Annotated[dict, Field(description="Updated Managed Response configuration fields")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /v1/{account_id}/mr_configs/{config_id}"""
        return self._put_at(
            "responder",
            f"/v1/{{account_id}}/mr_configs/{config_id}",
            account_id=account_id,
            json_body=config,
        )

    def responder_delete_mr_config(
        self,
        config_id: Annotated[str, Field(description="MR config ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /v1/{account_id}/mr_configs/{config_id}"""
        return self._delete_at(
            "responder",
            f"/v1/{{account_id}}/mr_configs/{config_id}",
            account_id=account_id,
        )

    # ---- Limits ----

    def responder_get_limits(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /v1/{account_id}/limits"""
        return self._get_at(
            "responder",
            "/v1/{account_id}/limits",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = SOARModule()
    mod.register_tools(server)
