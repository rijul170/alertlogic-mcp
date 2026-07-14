"""
AlertLogic AIMS User Management.
User CRUD, role assignment, access keys, and MFA management.

Official API: https://console.cloudinsight.alertlogic.com/api/aims/
"""
from typing import Annotated, Optional, List
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class UsersModule(BaseModule):
    """AIMS User & Role Management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.aims_list_users, "aims_list_users",
                        "List all users for an account")
        self._add_tool(server, self.aims_get_user, "aims_get_user",
                        "Get user details by user ID")
        self._add_tool(server, self.aims_create_user, "aims_create_user",
                        "Create a new user in an account")
        self._add_tool(server, self.aims_update_user, "aims_update_user",
                        "Update user details (name, email, active status)")
        self._add_tool(server, self.aims_delete_user, "aims_delete_user",
                        "Delete a user from an account")
        self._add_tool(server, self.aims_get_user_permissions, "aims_get_user_permissions",
                        "Get a user's effective permissions")
        self._add_tool(server, self.aims_list_roles, "aims_list_roles",
                        "List all roles for an account (including global roles)")
        self._add_tool(server, self.aims_create_role, "aims_create_role",
                        "Create a new role with specified permissions")
        self._add_tool(server, self.aims_delete_role, "aims_delete_role",
                        "Delete a role from an account")
        self._add_tool(server, self.aims_get_role, "aims_get_role",
                        "Get details for a specific role in an account")
        self._add_tool(server, self.aims_update_role, "aims_update_role",
                        "Update a role's name or permissions")
        self._add_tool(server, self.aims_list_global_roles, "aims_list_global_roles",
                        "List system-wide global roles (no account scope)")
        self._add_tool(server, self.aims_get_global_role, "aims_get_global_role",
                        "Get a specific system-wide global role")
        self._add_tool(server, self.aims_grant_role, "aims_grant_role",
                        "Grant a role to a user")
        self._add_tool(server, self.aims_revoke_role, "aims_revoke_role",
                        "Revoke a role from a user")
        self._add_tool(server, self.aims_get_user_roles, "aims_get_user_roles",
                        "Get all roles assigned to a user")
        self._add_tool(server, self.aims_list_user_role_ids, "aims_list_user_role_ids",
                        "List IDs of roles assigned to a user")
        self._add_tool(server, self.aims_get_user_by_email, "aims_get_user_by_email",
                        "Find users in an account by email address")
        self._add_tool(server, self.aims_get_user_by_username, "aims_get_user_by_username",
                        "Cross-account user lookup by username")
        self._add_tool(server, self.aims_get_user_global, "aims_get_user_global",
                        "Cross-account user lookup by user ID (no account scope)")
        self._add_tool(server, self.aims_list_access_keys, "aims_list_access_keys",
                        "List access keys for a user")
        self._add_tool(server, self.aims_create_access_key, "aims_create_access_key",
                        "Create an access key for a user")
        self._add_tool(server, self.aims_get_access_key, "aims_get_access_key",
                        "Get details for a specific access key")
        self._add_tool(server, self.aims_update_access_key, "aims_update_access_key",
                        "Update the label of an access key")
        self._add_tool(server, self.aims_delete_access_key, "aims_delete_access_key",
                        "Delete a user's access key")
        self._add_tool(server, self.aims_enroll_mfa, "aims_enroll_mfa",
                        "Enroll an MFA device for the authenticated user")
        self._add_tool(server, self.aims_remove_mfa, "aims_remove_mfa",
                        "Remove a user's MFA device enrollment")
        self._add_tool(server, self.aims_change_password, "aims_change_password",
                        "Change the authenticated user's own password")
        self._add_tool(server, self.aims_initiate_password_reset, "aims_initiate_password_reset",
                        "Initiate password reset for a user (sends email)")
        self._add_tool(server, self.aims_complete_password_reset, "aims_complete_password_reset",
                        "Complete a password reset using a reset token")

    # ---- User CRUD ----

    def aims_list_users(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        role_id: Annotated[Optional[str], Field(description="Filter by role ID")] = None,
        include_role_ids: Annotated[bool, Field(description="Include role IDs in response")] = True,
    ) -> dict:
        """List all users. GET /aims/v1/{account_id}/users"""
        params = {}
        if role_id:
            params["role_id"] = role_id
        if include_role_ids:
            params["include_role_ids"] = "true"
        return self._get("/aims/v1/{account_id}/users", account_id=account_id, params=params or None)

    def aims_get_user(
        self,
        user_id: Annotated[str, Field(description="AIMS User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        include_role_ids: Annotated[bool, Field(description="Include role IDs")] = True,
    ) -> dict:
        """Get user details. GET /aims/v1/{account_id}/users/{user_id}"""
        params = {}
        if include_role_ids:
            params["include_role_ids"] = "true"
        return self._get(
            f"/aims/v1/{{account_id}}/users/{user_id}",
            account_id=account_id,
            params=params or None,
        )

    def aims_create_user(
        self,
        name: Annotated[str, Field(description="User's full name")],
        email: Annotated[str, Field(description="User's email address")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        role_id: Annotated[Optional[str], Field(description="Role ID to grant")] = None,
        active: Annotated[bool, Field(description="Whether user is active")] = True,
        mobile_phone: Annotated[Optional[str], Field(description="Mobile phone number")] = None,
    ) -> dict:
        """Create a new user. POST /aims/v1/{account_id}/users"""
        body = {"name": name, "email": email, "active": active}
        if role_id:
            body["role_id"] = role_id
        if mobile_phone:
            body["mobile_phone"] = mobile_phone
        return self._post("/aims/v1/{account_id}/users", account_id=account_id, json_body=body)

    def aims_update_user(
        self,
        user_id: Annotated[str, Field(description="User ID to update")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        name: Annotated[Optional[str], Field(description="New name")] = None,
        email: Annotated[Optional[str], Field(description="New email")] = None,
        active: Annotated[Optional[bool], Field(description="Active status")] = None,
        mobile_phone: Annotated[Optional[str], Field(description="Mobile phone")] = None,
    ) -> dict:
        """Update user details. POST /aims/v1/{account_id}/users/{user_id}"""
        body = {}
        if name is not None:
            body["name"] = name
        if email is not None:
            body["email"] = email
        if active is not None:
            body["active"] = active
        if mobile_phone is not None:
            body["mobile_phone"] = mobile_phone
        return self._post(f"/aims/v1/{{account_id}}/users/{user_id}", account_id=account_id, json_body=body)

    def aims_delete_user(
        self,
        user_id: Annotated[str, Field(description="User ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete a user. DELETE /aims/v1/{account_id}/users/{user_id}"""
        return self._delete(f"/aims/v1/{{account_id}}/users/{user_id}", account_id=account_id)

    # ---- User lookups (no account scope) ----

    def aims_get_user_by_email(
        self,
        email: Annotated[str, Field(description="Email address to search for")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Find users by email. GET /aims/v1/{account_id}/users/email/{email}"""
        from alertlogic_mcp.modules.base import url_quote
        return self._get(
            f"/aims/v1/{{account_id}}/users/email/{url_quote(email)}",
            account_id=account_id,
        )

    def aims_get_user_by_username(
        self,
        username: Annotated[str, Field(description="Username (typically an email address) to look up")],
    ) -> dict:
        """Cross-account user lookup by username. GET /aims/v1/user/username/{username}"""
        from alertlogic_mcp.modules.base import url_quote
        return self._request("GET", f"/aims/v1/user/username/{url_quote(username)}")

    def aims_get_user_global(
        self,
        user_id: Annotated[str, Field(description="User ID for cross-account lookup")],
    ) -> dict:
        """Cross-account user lookup by ID. GET /aims/v1/user/{user_id}"""
        return self._request("GET", f"/aims/v1/user/{user_id}")

    # ---- Permissions & Roles ----

    def aims_get_user_permissions(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get user permissions. GET /aims/v1/{account_id}/users/{user_id}/permissions"""
        return self._get(f"/aims/v1/{{account_id}}/users/{user_id}/permissions", account_id=account_id)

    def aims_list_roles(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List all roles. GET /aims/v1/{account_id}/roles"""
        return self._get("/aims/v1/{account_id}/roles", account_id=account_id)

    def aims_create_role(
        self,
        name: Annotated[str, Field(description="Role name")],
        permissions: Annotated[dict, Field(description="Role permissions object")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create a role. POST /aims/v1/{account_id}/roles"""
        body = {"name": name, "permissions": permissions}
        return self._post("/aims/v1/{account_id}/roles", account_id=account_id, json_body=body)

    def aims_delete_role(
        self,
        role_id: Annotated[str, Field(description="Role ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete a role. DELETE /aims/v1/{account_id}/roles/{role_id}"""
        return self._delete(f"/aims/v1/{{account_id}}/roles/{role_id}", account_id=account_id)

    def aims_get_role(
        self,
        role_id: Annotated[str, Field(description="Role ID to retrieve")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a specific role. GET /aims/v1/{account_id}/roles/{role_id}"""
        return self._get(f"/aims/v1/{{account_id}}/roles/{role_id}", account_id=account_id)

    def aims_update_role(
        self,
        role_id: Annotated[str, Field(description="Role ID to update")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        name: Annotated[Optional[str], Field(description="New role name")] = None,
        permissions: Annotated[Optional[dict], Field(description="Updated permissions object")] = None,
    ) -> dict:
        """Update a role. POST /aims/v1/{account_id}/roles/{role_id}"""
        body = {}
        if name is not None:
            body["name"] = name
        if permissions is not None:
            body["permissions"] = permissions
        return self._post(f"/aims/v1/{{account_id}}/roles/{role_id}", account_id=account_id, json_body=body)

    def aims_list_global_roles(self) -> dict:
        """List system-wide global roles. GET /aims/v1/roles"""
        return self._request("GET", "/aims/v1/roles")

    def aims_get_global_role(
        self,
        role_id: Annotated[str, Field(description="Global role ID to retrieve")],
    ) -> dict:
        """Get a system-wide global role. GET /aims/v1/roles/{role_id}"""
        return self._request("GET", f"/aims/v1/roles/{role_id}")

    def aims_grant_role(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        role_id: Annotated[str, Field(description="Role ID to grant")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Grant a role to a user. PUT /aims/v1/{account_id}/users/{user_id}/roles/{role_id}"""
        return self._put(f"/aims/v1/{{account_id}}/users/{user_id}/roles/{role_id}", account_id=account_id)

    def aims_revoke_role(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        role_id: Annotated[str, Field(description="Role ID to revoke")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Revoke a role. DELETE /aims/v1/{account_id}/users/{user_id}/roles/{role_id}"""
        return self._delete(f"/aims/v1/{{account_id}}/users/{user_id}/roles/{role_id}", account_id=account_id)

    def aims_get_user_roles(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get user's roles. GET /aims/v1/{account_id}/users/{user_id}/roles"""
        return self._get(f"/aims/v1/{{account_id}}/users/{user_id}/roles", account_id=account_id)

    def aims_list_user_role_ids(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List role IDs assigned to a user. GET /aims/v1/{account_id}/users/{user_id}/role_ids"""
        return self._get(f"/aims/v1/{{account_id}}/users/{user_id}/role_ids", account_id=account_id)

    # ---- Access Keys ----

    def aims_list_access_keys(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List access keys. GET /aims/v1/{account_id}/users/{user_id}/access_keys"""
        return self._get(f"/aims/v1/{{account_id}}/users/{user_id}/access_keys", account_id=account_id)

    def aims_create_access_key(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
        label: Annotated[Optional[str], Field(description="Label for the access key")] = None,
    ) -> dict:
        """Create access key. POST /aims/v1/{account_id}/users/{user_id}/access_keys"""
        body = {}
        if label:
            body["label"] = label
        return self._post(
            f"/aims/v1/{{account_id}}/users/{user_id}/access_keys",
            account_id=account_id,
            json_body=body if body else None,
        )

    def aims_get_access_key(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        access_key_id: Annotated[str, Field(description="Access key ID to retrieve")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get a specific access key. GET /aims/v1/{account_id}/users/{user_id}/access_keys/{access_key_id}"""
        return self._get(
            f"/aims/v1/{{account_id}}/users/{user_id}/access_keys/{access_key_id}",
            account_id=account_id,
        )

    def aims_update_access_key(
        self,
        access_key_id: Annotated[str, Field(description="Access key ID to update")],
        label: Annotated[str, Field(description="New label for the access key")],
    ) -> dict:
        """Update access key label. POST /aims/v1/access_keys/{access_key_id}"""
        return self._request("POST", f"/aims/v1/access_keys/{access_key_id}", json_body={"label": label})

    def aims_delete_access_key(
        self,
        user_id: Annotated[str, Field(description="User ID")],
        access_key_id: Annotated[str, Field(description="Access key ID to delete")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete access key. DELETE /aims/v1/{account_id}/users/{user_id}/access_keys/{access_key_id}"""
        return self._delete(
            f"/aims/v1/{{account_id}}/users/{user_id}/access_keys/{access_key_id}",
            account_id=account_id,
        )

    # ---- Password & MFA ----

    def aims_enroll_mfa(
        self,
        mfa_uri: Annotated[Optional[str], Field(description="MFA URI (otpauth:// provisioning URI)")] = None,
        totp_secret: Annotated[Optional[str], Field(description="TOTP secret (alternative to mfa_uri)")] = None,
    ) -> dict:
        """Enroll an MFA device. POST /aims/v1/user/mfa/enroll"""
        body = {}
        if mfa_uri is not None:
            body["mfa_uri"] = mfa_uri
        if totp_secret is not None:
            body["totp_secret"] = totp_secret
        return self._request("POST", "/aims/v1/user/mfa/enroll", json_body=body)

    def aims_remove_mfa(
        self,
        username: Annotated[str, Field(description="User's email/username (URL-encoded automatically)")],
    ) -> dict:
        """Remove MFA device. DELETE /aims/v1/user/mfa/{username}"""
        from alertlogic_mcp.modules.base import url_quote
        return self._delete(f"/aims/v1/user/mfa/{url_quote(username)}")

    def aims_change_password(
        self,
        email: Annotated[str, Field(description="User's email address")],
        current_password: Annotated[str, Field(description="Current password")],
        new_password: Annotated[str, Field(description="New password")],
    ) -> dict:
        """Change own password. POST /aims/v1/change_password"""
        body = {
            "email": email,
            "current_password": current_password,
            "new_password": new_password,
        }
        return self._request("POST", "/aims/v1/change_password", json_body=body)

    def aims_initiate_password_reset(
        self,
        email: Annotated[str, Field(description="User's email address")],
        return_to: Annotated[Optional[str], Field(description="URL to return to after reset")] = None,
    ) -> dict:
        """Initiate password reset. POST /aims/v1/reset_password"""
        body = {"email": email}
        if return_to:
            body["return_to"] = return_to
        return self._post("/aims/v1/reset_password", json_body=body)

    def aims_complete_password_reset(
        self,
        token: Annotated[str, Field(description="Password reset token from the reset email")],
        password: Annotated[str, Field(description="New password to set")],
    ) -> dict:
        """Complete password reset using a token. PUT /aims/v1/reset_password/{token}"""
        return self._request("PUT", f"/aims/v1/reset_password/{token}", json_body={"password": password})


def setup(server: FastMCP):
    mod = UsersModule()
    mod.register_tools(server)
