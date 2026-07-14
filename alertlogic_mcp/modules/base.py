"""
AlertLogic MCP Base Module.
Provides common auth, HTTP helpers, and tool registration for all modules.
"""
import os
import threading
import time
from typing import Callable, Optional
from urllib.parse import quote

import backoff
import requests
from mcp.server import FastMCP
from mcp.types import ToolAnnotations

# ------------------------------------------------------------------ #
#  Safety gating                                                      #
#                                                                     #
#  ALERTLOGIC_MCP_READONLY=true                                       #
#      Register only read tools. Write and destructive tools are      #
#      never exposed to the AI client, regardless of what is asked.   #
#                                                                     #
#  ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE=true | tool1,tool2,...            #
#      Destructive tools (deletes, playbook execution, scans, ...)    #
#      are suppressed by default even with writes enabled. Set to     #
#      'true' to arm all of them, or list specific tool names.        #
# ------------------------------------------------------------------ #

READONLY_ENV = "ALERTLOGIC_MCP_READONLY"
ALLOW_DESTRUCTIVE_ENV = "ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE"

_TRUTHY = {"1", "true", "yes", "on", "all"}

# Words that signal an irreversible or high-impact operation.
_DESTRUCTIVE_WORDS = {
    "delete", "remove", "terminate", "revoke", "execute", "run", "launch",
    "deploy", "reset", "expire", "purge", "destroy", "cancel", "stop",
    "halt", "deprovision", "release",
}
# Words that signal a state-changing (but recoverable) operation.
_WRITE_WORDS = {
    "create", "update", "set", "add", "complete", "reopen", "assign",
    "unassign", "upload", "publish", "enable", "disable", "modify", "patch",
    "put", "post", "import", "register", "schedule", "reschedule", "start",
    "submit", "send", "apply", "associate", "attach", "detach", "tune",
    "move", "rename", "restore", "acknowledge", "snooze", "claim",
    "authenticate", "change", "initiate", "trigger", "retry", "rerun",
    "clone", "copy", "new", "save", "write", "enroll", "grant", "declare",
    "conclude", "dispose", "undispose", "pause", "resume", "respond",
    "checkin", "close",
}
# Words that signal a pure read. Only used when no mutating word matched.
_READ_WORDS = {
    "list", "get", "search", "query", "show", "describe", "fetch", "read",
    "count", "status", "summary", "export", "download", "check", "lookup",
    "find", "view", "topology", "details", "history", "types", "filters",
    "aggregations", "stats", "info", "metadata", "validate", "test", "poll",
    "healthcheck", "guide", "hunt", "templates",
}
# Tools whose names look mutating but are actually reads (or vice versa).
_TIER_OVERRIDES = {
    "aims_authenticate": "read",        # diagnostic; auth happens implicitly anyway
    "inquisitor_submit_search": "read", # submits a read-only log search query
    "soc_ir_start": "read",             # static IR playbook guide
    "aefr_get_triggers": "read",
    "aefr_get_trigger_by_id": "read",
    "aefr_get_global_triggers": "read",
    "aefr_get_global_trigger_by_path": "read",
    "aefr_get_global_triggers_by_data_type": "read",
    "responder_get_trigger": "read",
    "responder_list_triggers": "read",
    "aefr_validate_trigger": "read",
}


def classify_tool(name: str) -> str:
    """Classify a tool name as 'read', 'write', or 'destructive'.

    Fail-safe: a name containing no known verb is treated as 'write' so it
    is suppressed in read-only mode rather than accidentally exposed.
    """
    override = _TIER_OVERRIDES.get(name)
    if override:
        return override
    words = set(name.split("_"))
    if words & _DESTRUCTIVE_WORDS:
        return "destructive"
    if words & _WRITE_WORDS:
        return "write"
    if words & _READ_WORDS:
        return "read"
    return "write"


def _is_readonly_mode() -> bool:
    return os.getenv(READONLY_ENV, "").strip().lower() in _TRUTHY


def _destructive_allowed(name: str) -> bool:
    value = os.getenv(ALLOW_DESTRUCTIVE_ENV, "").strip()
    if not value:
        return False
    if value.lower() in _TRUTHY:
        return True
    allowed = {t.strip() for t in value.split(",")}
    return name in allowed


def url_quote(value: str) -> str:
    """Percent-encode a path segment, including '/'.

    AlertLogic asset keys look like '/aws/us-west-2/host/i-123' — those slashes
    must be encoded or the URL routes to the wrong endpoint.
    """
    return quote(value or "", safe="")


class BaseModule:
    """
    Base class for all AlertLogic MCP modules.
    Handles authentication token management, HTTP helpers, and tool registration.
    """

    # Re-auth this many seconds before the token actually expires.
    _TOKEN_REFRESH_LEEWAY = 60

    def __init__(self):
        self.api_key = os.getenv("ALERTLOGIC_API_KEY", "")
        self.account_id = os.getenv("ALERTLOGIC_ACCOUNT_ID", "")
        self.base_url = os.getenv(
            "ALERTLOGIC_BASE_URL",
            "https://api.cloudinsight.alertlogic.com",
        )
        self.service_hosts = {
            "default": self.base_url,
            "global": os.getenv(
                "ALERTLOGIC_GLOBAL_BASE_URL",
                "https://api.global-services.global.alertlogic.com",
            ),
            "aetuner": os.getenv(
                "ALERTLOGIC_AETUNER_BASE_URL",
                "https://aetuner.mdr.global.alertlogic.com",
            ),
            "connectors": os.getenv(
                "ALERTLOGIC_CONNECTORS_BASE_URL",
                "https://connectors.mdr.global.alertlogic.com",
            ),
            "responder": os.getenv(
                "ALERTLOGIC_RESPONDER_BASE_URL",
                "https://api.responder.alertlogic.com",
            ),
        }
        # Backwards-compat alias used by existing _request_global helpers.
        self.global_base_url = self.service_hosts["global"]
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._auth_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    #  Auth helpers                                                       #
    # ------------------------------------------------------------------ #

    def authenticate(self) -> dict:
        """
        Authenticate using the API access key (access_key_id:secret_key).
        Returns the full AIMS authentication response including token.
        Also auto-discovers account_id if not already set.
        """
        if not self.api_key or ":" not in self.api_key:
            return {"error": "ALERTLOGIC_API_KEY must be in access_key_id:secret_key format"}

        access_key_id, secret_key = self.api_key.split(":", 1)
        try:
            resp = requests.post(
                f"{self.base_url}/aims/v1/authenticate",
                auth=(access_key_id, secret_key),
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                auth_info = data.get("authentication", {})
                self._token = auth_info.get("token", "")
                # token_expiration is a Unix epoch (seconds). Refresh shortly before it.
                exp = auth_info.get("token_expiration")
                self._token_expires_at = float(exp) if exp else 0.0
                # Auto-discover account_id from auth response
                if not self.account_id:
                    self.account_id = str(auth_info.get("account", {}).get("id", ""))
                return data
            return {
                "error": "Authentication failed",
                "status_code": resp.status_code,
                "details": resp.text,
            }
        except Exception as e:
            return {"error": "Authentication request failed", "details": str(e)}

    def _token_is_valid(self) -> bool:
        if not self._token:
            return False
        if not self._token_expires_at:
            # No expiry info — assume valid for the session.
            return True
        return time.time() < (self._token_expires_at - self._TOKEN_REFRESH_LEEWAY)

    def get_token(self) -> Optional[str]:
        """Get a valid auth token, authenticating (or refreshing) if needed."""
        if self._token_is_valid():
            return self._token
        with self._auth_lock:
            if self._token_is_valid():
                return self._token
            result = self.authenticate()
            if "error" in result:
                return None
        return self._token

    def get_headers(self) -> Optional[dict]:
        """Get headers with a fresh/valid token, or None if auth failed."""
        token = self.get_token()
        if not token:
            return None
        return {
            "x-aims-auth-token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------ #
    #  HTTP helpers with retry                                            #
    # ------------------------------------------------------------------ #

    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException,),
        max_tries=3,
        max_time=30,
    )
    def _request(
        self,
        method: str,
        path: str,
        account_id: str = None,
        params: dict = None,
        json_body: dict = None,
        data: str = None,
        base_url: str = None,
        content_type: str = None,
    ) -> dict:
        """
        Make an authenticated HTTP request to the AlertLogic API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            path: API path (e.g., '/aims/v1/{account_id}/users')
            account_id: Override account ID (for MSSP cross-account)
            params: Query parameters
            json_body: JSON request body
            data: Raw request body
            base_url: Override base URL (used for global-services endpoints)
            content_type: Override Content-Type (e.g., 'text/plain' for AL-SQL search)
        """
        acct = account_id or self.account_id
        if not acct and "{account_id}" in path:
            self.authenticate()
            acct = account_id or self.account_id
            if not acct:
                return {"error": "No account_id available — authenticate or pass account_id explicitly"}

        host = base_url or self.base_url
        url = f"{host}{path}".replace("{account_id}", acct or "")

        headers = self.get_headers()
        if headers is None:
            return {"error": "Authentication failed — could not obtain AIMS token"}
        if content_type:
            headers["Content-Type"] = content_type

        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=data,
                timeout=30,
            )

            try:
                body = resp.json()
            except ValueError:
                body = {"raw_response": resp.text}

            if resp.status_code >= 400:
                return {
                    "error": f"API returned {resp.status_code}",
                    "status_code": resp.status_code,
                    "details": body,
                }

            return {
                "status_code": resp.status_code,
                "data": body,
            }
        except requests.exceptions.RequestException as e:
            return {"error": "Request failed", "details": str(e)}

    def _get(self, path: str, account_id: str = None, params: dict = None) -> dict:
        return self._request("GET", path, account_id, params=params)

    def _post(self, path: str, account_id: str = None, json_body: dict = None, params: dict = None) -> dict:
        return self._request("POST", path, account_id, params=params, json_body=json_body)

    def _put(self, path: str, account_id: str = None, json_body: dict = None) -> dict:
        return self._request("PUT", path, account_id, json_body=json_body)

    def _delete(self, path: str, account_id: str = None, params: dict = None, json_body: dict = None) -> dict:
        return self._request("DELETE", path, account_id, params=params, json_body=json_body)

    # ------------------------------------------------------------------ #
    #  Global-services endpoint helpers                                   #
    #  (Herald, Subscriptions, etc. are on a different API host)          #
    # ------------------------------------------------------------------ #

    def _request_global(self, method: str, path: str, account_id: str = None,
                        params: dict = None, json_body: dict = None) -> dict:
        """Make a request to the global-services API endpoint."""
        return self._request(
            method, path, account_id,
            params=params, json_body=json_body,
            base_url=self.global_base_url,
        )

    def _get_global(self, path: str, account_id: str = None, params: dict = None) -> dict:
        return self._request_global("GET", path, account_id, params=params)

    def _post_global(self, path: str, account_id: str = None, json_body: dict = None, params: dict = None) -> dict:
        return self._request_global("POST", path, account_id, params=params, json_body=json_body)

    def _put_global(self, path: str, account_id: str = None, json_body: dict = None) -> dict:
        return self._request_global("PUT", path, account_id, json_body=json_body)

    def _delete_global(self, path: str, account_id: str = None) -> dict:
        return self._request_global("DELETE", path, account_id)

    # ------------------------------------------------------------------ #
    #  Per-service routed helpers                                         #
    #  (pass a service key that maps to self.service_hosts[key])          #
    # ------------------------------------------------------------------ #

    def _request_at(
        self,
        service: str,
        method: str,
        path: str,
        account_id: str = None,
        params: dict = None,
        json_body: dict = None,
        data: str = None,
        content_type: str = None,
    ) -> dict:
        host = self.service_hosts.get(service)
        if not host:
            return {"error": f"Unknown service host '{service}'"}
        return self._request(
            method, path, account_id,
            params=params, json_body=json_body, data=data,
            base_url=host, content_type=content_type,
        )

    def _get_at(self, service: str, path: str, account_id: str = None, params: dict = None) -> dict:
        return self._request_at(service, "GET", path, account_id, params=params)

    def _post_at(self, service: str, path: str, account_id: str = None,
                 json_body: dict = None, params: dict = None,
                 data: str = None, content_type: str = None) -> dict:
        return self._request_at(service, "POST", path, account_id,
                                params=params, json_body=json_body,
                                data=data, content_type=content_type)

    def _put_at(self, service: str, path: str, account_id: str = None, json_body: dict = None) -> dict:
        return self._request_at(service, "PUT", path, account_id, json_body=json_body)

    def _delete_at(self, service: str, path: str, account_id: str = None, params: dict = None) -> dict:
        return self._request_at(service, "DELETE", path, account_id, params=params)

    # ------------------------------------------------------------------ #
    #  Tool registration                                                  #
    # ------------------------------------------------------------------ #

    def _add_tool(self, server: FastMCP, method: Callable, name: str, description: str, annotations=None):
        """Register a method as an MCP tool, applying safety gating.

        Read-only mode suppresses write and destructive tools entirely;
        destructive tools additionally require explicit opt-in via
        ALERTLOGIC_MCP_ALLOW_DESTRUCTIVE. Suppressed tools are never
        registered, so the AI client cannot call them regardless of intent.
        """
        tier = classify_tool(name)
        if _is_readonly_mode() and tier != "read":
            return
        if tier == "destructive" and not _destructive_allowed(name):
            return
        kwargs = {"name": name, "description": description}
        kwargs["annotations"] = annotations or ToolAnnotations(
            readOnlyHint=(tier == "read"),
            destructiveHint=(tier == "destructive"),
            openWorldHint=True,
        )
        server.tool(**kwargs)(method)

    def register_tools(self, server: FastMCP):
        """Override in subclasses to register tools."""
        raise NotImplementedError("Subclasses must implement register_tools()")
