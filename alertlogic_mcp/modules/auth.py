"""
AlertLogic Authentication & MSSP Scoping (AIMS Service).
Handles API key authentication, token management, and cross-account operations.

Official API: https://console.cloudinsight.alertlogic.com/api/aims/
"""
import os
from typing import Annotated, Optional
import requests
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class AuthModule(BaseModule):
    """AlertLogic AIMS Authentication & Account Management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server=server,
            method=self.aims_authenticate,
            name="aims_authenticate",
            description="Authenticate to AlertLogic AIMS and obtain an auth token",
        )
        self._add_tool(
            server=server,
            method=self.aims_token_info,
            name="aims_token_info",
            description="Get information about the current auth token (account, user, roles)",
        )
        self._add_tool(
            server=server,
            method=self.aims_list_managed_accounts,
            name="aims_list_managed_accounts",
            description="List all managed (child) accounts for an MSSP parent account",
        )
        self._add_tool(
            server=server,
            method=self.aims_get_account,
            name="aims_get_account",
            description="Get account details by account ID",
        )
        self._add_tool(
            server=server,
            method=self.aims_list_account_ids,
            name="aims_list_account_ids",
            description="List account IDs by relationship (managed/managing)",
        )
        self._add_tool(
            server=server,
            method=self.aims_update_account,
            name="aims_update_account",
            description="Update account details (e.g., MFA requirement)",
        )

    # ------------------------------------------------------------------ #
    #  Authentication                                                     #
    # ------------------------------------------------------------------ #

    def aims_authenticate(self) -> dict:
        """
        Authenticate using the configured API access key.
        Uses POST /aims/v1/authenticate with Basic auth (access_key_id:secret_key).
        """
        return self.authenticate()

    def aims_token_info(self) -> dict:
        """
        Get information about the current authentication token.
        Uses GET /aims/v1/token_info.
        Returns account info, user details, and granted roles.
        """
        return self._get("/aims/v1/token_info")

    # ------------------------------------------------------------------ #
    #  Account Management                                                 #
    # ------------------------------------------------------------------ #

    def aims_list_managed_accounts(
        self,
        account_id: Annotated[Optional[str], Field(
            description="Parent account ID (defaults to configured account)"
        )] = None,
        active: Annotated[Optional[bool], Field(
            description="Filter by active status"
        )] = None,
    ) -> dict:
        """
        List all managed (child) accounts for an MSSP parent.
        Uses GET /aims/v1/{account_id}/accounts/managed.
        """
        params = {}
        if active is not None:
            params["active"] = str(active).lower()
        return self._get(
            "/aims/v1/{account_id}/accounts/managed",
            account_id=account_id,
            params=params or None,
        )

    def aims_get_account(
        self,
        account_id: Annotated[str, Field(description="AIMS Account ID to look up")],
    ) -> dict:
        """
        Get account details by account ID.
        Uses GET /aims/v1/{account_id}/account.
        """
        return self._get("/aims/v1/{account_id}/account", account_id=account_id)

    def aims_list_account_ids(
        self,
        relationship: Annotated[str, Field(
            description="Account relationship type: 'managed' or 'managing'"
        )],
        account_id: Annotated[Optional[str], Field(
            description="Account ID (defaults to configured account)"
        )] = None,
        active: Annotated[Optional[bool], Field(
            description="Filter by active status"
        )] = None,
    ) -> dict:
        """
        List account IDs by relationship.
        Uses GET /aims/v1/{account_id}/account_ids/{relationship}.
        """
        params = {}
        if active is not None:
            params["active"] = str(active).lower()
        return self._get(
            f"/aims/v1/{{account_id}}/account_ids/{relationship}",
            account_id=account_id,
            params=params or None,
        )

    def aims_update_account(
        self,
        account_id: Annotated[str, Field(description="Account ID to update")],
        mfa_required: Annotated[Optional[bool], Field(
            description="Whether MFA is required for users of this account"
        )] = None,
    ) -> dict:
        """
        Update account details.
        Uses POST /aims/v1/{account_id}/account.
        """
        body = {}
        if mfa_required is not None:
            body["mfa_required"] = mfa_required
        return self._post(
            "/aims/v1/{account_id}/account",
            account_id=account_id,
            json_body=body,
        )


def setup(server: FastMCP):
    mod = AuthModule()
    mod.register_tools(server)
