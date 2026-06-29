"""
AlertLogic Themis — External Permissions Management Service.
Validates and retrieves AWS/Azure IAM role configurations against Alert Logic's
required permissions definitions.

Official API: https://console.cloudinsight.alertlogic.com/api/themis/
Spec: alertlogic/alertlogic-sdk-definitions — alsdkdefs/apis/themis/themis.v1.yaml
"""
import os
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


# Supported platform types
ThemisPlatformType = Literal["aws"]

# Supported role types
ThemisRoleType = Literal[
    "ci_manual",
    "ci_full",
    "cd_full",
    "ci_x_account_ct",
    "ci_essentials",
    "ci_readonly",
]


class ThemisModule(BaseModule):
    """
    Themis MDR External Permissions Management.

    Exposes three operations from the Themis v1 API:
      - get_role       : fetch a specific role definition by platform/type/version
      - get_roles      : list all latest role definitions (optionally filtered by platform)
      - validate_creds : validate a customer-supplied IAM credential (ARN + external ID)
    """

    def __init__(self):
        super().__init__()
        self.service_hosts["themis"] = os.environ.get(
            "ALERTLOGIC_THEMIS_BASE_URL",
            "https://themis.mdr.global.alertlogic.com",
        )

    def register_tools(self, server: FastMCP):
        self._add_tool(
            server,
            self.themis_get_role,
            "themis_get_role",
            "Get a specific Themis role definition (policy document + CloudFormation template) "
            "by platform type, role type, and version",
        )
        self._add_tool(
            server,
            self.themis_get_roles,
            "themis_get_roles",
            "List all latest Themis role definitions for an account, optionally filtered by platform type",
        )
        self._add_tool(
            server,
            self.themis_validate_credentials,
            "themis_validate_credentials",
            "Validate a customer-supplied AWS IAM role ARN + external ID against Alert Logic's "
            "required permissions for a given role type",
        )

    # ------------------------------------------------------------------ #
    #  GET /themis/v1/{account_id}/roles/{platform_type}/{role_type}/{role_version}
    # ------------------------------------------------------------------ #

    def themis_get_role(
        self,
        platform_type: Annotated[
            ThemisPlatformType,
            Field(description="Cloud platform type — currently only 'aws'"),
        ],
        role_type: Annotated[
            ThemisRoleType,
            Field(
                description=(
                    "Alert Logic role type: "
                    "ci_manual | ci_full | cd_full | ci_x_account_ct | ci_essentials | ci_readonly"
                )
            ),
        ],
        role_version: Annotated[
            str,
            Field(description="Role definition version string (e.g. 'v1', 'v2')"),
        ],
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID (uses env default if omitted)"),
        ] = None,
    ) -> dict:
        """
        Retrieve a specific Themis role definition including its IAM policy document
        and the associated CloudFormation template S3 location.

        GET /themis/v1/{account_id}/roles/{platform_type}/{role_type}/{role_version}
        """
        return self._get_at(
            "themis",
            f"/themis/v1/{{account_id}}/roles/{platform_type}/{role_type}/{role_version}",
            account_id=account_id,
        )

    # ------------------------------------------------------------------ #
    #  GET /themis/v1/{account_id}/roles
    # ------------------------------------------------------------------ #

    def themis_get_roles(
        self,
        platform_type: Annotated[
            Optional[ThemisPlatformType],
            Field(
                description="Filter results to a specific platform type (e.g. 'aws'). "
                "Omit to return roles for all platforms."
            ),
        ] = None,
        account_id: Annotated[
            Optional[str],
            Field(description="Alert Logic account ID (uses env default if omitted)"),
        ] = None,
    ) -> dict:
        """
        List the latest Themis role definitions available for an account.
        Returns an array of role objects, each containing the policy document,
        external_id, aws_account_id, version, and CloudFormation template details.

        GET /themis/v1/{account_id}/roles
        """
        params = {}
        if platform_type:
            params["platform_type"] = platform_type
        return self._get_at(
            "themis",
            "/themis/v1/{account_id}/roles",
            account_id=account_id,
            params=params or None,
        )

    # ------------------------------------------------------------------ #
    #  POST /themis/v1/validate/{platform_type}/{role_type}
    # ------------------------------------------------------------------ #

    def themis_validate_credentials(
        self,
        platform_type: Annotated[
            ThemisPlatformType,
            Field(description="Cloud platform type — currently only 'aws'"),
        ],
        role_type: Annotated[
            ThemisRoleType,
            Field(
                description=(
                    "Alert Logic role type to validate against: "
                    "ci_manual | ci_full | cd_full | ci_x_account_ct | ci_essentials | ci_readonly"
                )
            ),
        ],
        arn: Annotated[
            str,
            Field(
                description=(
                    "AWS IAM Role ARN to validate "
                    "(e.g. 'arn:aws:iam::123456789012:role/AlertLogicRole')"
                )
            ),
        ],
        external_id: Annotated[
            str,
            Field(
                description=(
                    "External ID associated with the IAM role trust policy — "
                    "provided by Alert Logic when the role was created"
                )
            ),
        ],
        role_version: Annotated[
            Optional[str],
            Field(
                description=(
                    "Specific role definition version to validate against "
                    "(e.g. 'v1'). Omit to use the latest version."
                )
            ),
        ] = None,
    ) -> dict:
        """
        Validate a customer-supplied AWS IAM role credential against Alert Logic's
        required permissions for the specified role type.

        Alert Logic will assume the role using the provided ARN and external_id and
        verify that the correct permissions are in place.

        Returns:
          - status  : 'ok' on success, 'error' on failure
          - version : role definition version that was checked
          - message : human-readable validation result

        POST /themis/v1/validate/{platform_type}/{role_type}
        """
        credential: dict = {
            "platform_type": platform_type,
            "role_type": role_type,
            "arn": arn,
            "external_id": external_id,
        }
        if role_version is not None:
            credential["role_version"] = role_version

        return self._post_at(
            "themis",
            f"/themis/v1/validate/{platform_type}/{role_type}",
            json_body={"credential": credential},
        )


def setup(server: FastMCP):
    mod = ThemisModule()
    mod.register_tools(server)
