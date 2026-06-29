"""
AlertLogic Credentials Management.
Create, list, update, and delete credentials for scanning and cloud discovery.

Official API: https://console.cloudinsight.alertlogic.com/api/credentials/
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule, url_quote


class CredentialsModule(BaseModule):
    """Cloud and scanning credentials management."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.credentials_list, "credentials_list",
                        "List all credentials for an account")
        self._add_tool(server, self.credentials_get, "credentials_get",
                        "Get credential details by ID")
        self._add_tool(server, self.credentials_create_iam_role, "credentials_create_iam_role",
                        "Create an AWS IAM role credential")
        self._add_tool(server, self.credentials_create_azure_ad, "credentials_create_azure_ad",
                        "Create an Azure AD client credential")
        self._add_tool(server, self.credentials_delete, "credentials_delete",
                        "Delete a credential")
        self._add_tool(server, self.credentials_get_scan, "credentials_get_scan",
                        "Get scanning credentials for an asset in an environment")
        self._add_tool(server, self.credentials_set_scan, "credentials_set_scan",
                        "Set scanning credentials for an asset")
        self._add_tool(server, self.credentials_delete_scan, "credentials_delete_scan",
                        "Remove scanning credentials from an asset")
        self._add_tool(server, self.credentials_get_all_scan, "credentials_get_all_scan",
                        "Get all scanning credentials for an environment")
        self._add_tool(server, self.credentials_get_decrypted, "credentials_get_decrypted",
                        "Get a credential with secrets decrypted (v2)")

    def credentials_list(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List credentials. GET /credentials/v2/{account_id}/credentials"""
        return self._get("/credentials/v2/{account_id}/credentials", account_id=account_id)

    def credentials_get(
        self,
        credential_id: Annotated[str, Field(description="Credential UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get credential. GET /credentials/v2/{account_id}/credentials/{credential_id}"""
        return self._get(
            f"/credentials/v2/{{account_id}}/credentials/{credential_id}",
            account_id=account_id,
        )

    def credentials_create_iam_role(
        self,
        name: Annotated[str, Field(description="Credential name")],
        arn: Annotated[str, Field(description="AWS IAM Role ARN")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create AWS IAM role credential. POST /credentials/v2/{account_id}/credentials"""
        body = {
            "name": name,
            "secrets": {
                "type": "aws_iam_role",
                "arn": arn,
            },
        }
        return self._post("/credentials/v2/{account_id}/credentials", account_id=account_id, json_body=body)

    def credentials_create_azure_ad(
        self,
        name: Annotated[str, Field(description="Credential name")],
        active_directory_id: Annotated[str, Field(description="Azure AD tenant ID")],
        client_id: Annotated[str, Field(description="Azure AD client/app ID")],
        client_secret: Annotated[str, Field(description="Azure AD client secret")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Create Azure AD credential. POST /credentials/v2/{account_id}/credentials"""
        body = {
            "name": name,
            "secrets": {
                "type": "azure_ad_client",
                "active_directory_id": active_directory_id,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        }
        return self._post("/credentials/v2/{account_id}/credentials", account_id=account_id, json_body=body)

    def credentials_delete(
        self,
        credential_id: Annotated[str, Field(description="Credential UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Delete credential. DELETE /credentials/v2/{account_id}/credentials/{credential_id}"""
        return self._delete(
            f"/credentials/v2/{{account_id}}/credentials/{credential_id}",
            account_id=account_id,
        )

    # ---- Scanning Credentials (v1) ----
    # Per AlertLogic docs, asset keys are sent WITHOUT a leading slash
    # (e.g. 'aws/us-west-2/host/i-123'), but internal '/' must be URL-encoded.
    @staticmethod
    def _key(asset_key: str) -> str:
        return url_quote(asset_key.lstrip("/"))

    def credentials_get_scan(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        asset_type: Annotated[str, Field(description="Asset type (e.g., 'host', 'vpc')")],
        asset_key: Annotated[str, Field(description="Asset key, e.g. 'aws/us-west-2/host/i-123'")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /credentials/v1/{aid}/{env}/{type}/scan/{key}"""
        return self._get(
            f"/credentials/v1/{{account_id}}/{environment_id}/{url_quote(asset_type)}/scan/{self._key(asset_key)}",
            account_id=account_id,
        )

    def credentials_set_scan(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        asset_type: Annotated[str, Field(description="Asset type (e.g., 'host', 'vpc')")],
        asset_key: Annotated[str, Field(description="Asset key (no leading slash)")],
        credential_type: Annotated[Literal["ssh", "windows", "snmp_community_string"], Field(
            description="ssh / windows / snmp_community_string"
        )],
        name: Annotated[str, Field(description="Credential name")],
        sub_type: Annotated[Optional[Literal["user", "key"]], Field(
            description="Required when type=ssh: 'user' (username+password) or 'key' (private key)"
        )] = None,
        username: Annotated[Optional[str], Field(description="Username (max 127 bytes)")] = None,
        password: Annotated[Optional[str], Field(description="Password (max 127 bytes)")] = None,
        ssh_key: Annotated[Optional[str], Field(description="Unencrypted RSA/DSA private key")] = None,
        snmp_community_string: Annotated[Optional[str], Field(
            description="SNMP community string"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """PUT /credentials/v1/{aid}/{env}/{type}/scan/{key}"""
        body = {"name": name, "type": credential_type}
        if sub_type:
            body["sub_type"] = sub_type
        if username:
            body["username"] = username
        if password:
            body["password"] = password
        if ssh_key:
            body["key"] = ssh_key
        if snmp_community_string:
            body["snmp_community_string"] = snmp_community_string
        return self._put(
            f"/credentials/v1/{{account_id}}/{environment_id}/{url_quote(asset_type)}/scan/{self._key(asset_key)}",
            account_id=account_id,
            json_body=body,
        )

    def credentials_delete_scan(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        asset_type: Annotated[str, Field(description="Asset type")],
        asset_key: Annotated[str, Field(description="Asset key (no leading slash)")],
        credential_type: Annotated[Literal["ssh", "windows"], Field(
            description="ssh or windows (path segment, not query)"
        )],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """DELETE /credentials/v1/{aid}/{env}/{type}/scan/{credential_type}/{key}"""
        return self._delete(
            f"/credentials/v1/{{account_id}}/{environment_id}/{url_quote(asset_type)}/scan/{credential_type}/{self._key(asset_key)}",
            account_id=account_id,
        )

    def credentials_get_all_scan(
        self,
        environment_id: Annotated[str, Field(description="Environment UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /credentials/v1/{aid}/{env}/host/scan — all hosts in environment."""
        return self._get(
            f"/credentials/v1/{{account_id}}/{environment_id}/host/scan",
            account_id=account_id,
        )

    # ---- v2 bonus: decrypted credential ----

    def credentials_get_decrypted(
        self,
        credential_id: Annotated[str, Field(description="Credential UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """GET /credentials/v2/{aid}/credentials/{id}/decrypted"""
        return self._get(
            f"/credentials/v2/{{account_id}}/credentials/{credential_id}/decrypted",
            account_id=account_id,
        )


def setup(server: FastMCP):
    mod = CredentialsModule()
    mod.register_tools(server)
