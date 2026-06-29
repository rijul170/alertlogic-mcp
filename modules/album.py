"""
AlertLogic Album — AMI Sharing Service.

Manages Amazon Machine Image (AMI) records and launch permissions used by
Alert Logic across AWS regions and product lines.  The service tracks both
current (enabled) and historical image sets, grouped by product type,
platform type, and version.

Spec source: alertlogic/alertlogic-sdk-definitions
  alsdkdefs/apis/album/album.v1.yaml  (OpenAPI 3.0.2, version 1.0.0)

Base URL: https://api.global.alertlogic.com  (routed via "global" host entry)

Endpoints implemented (10):
  v1:
    GET  /album/v1/images                              — get_current_images
    GET  /album/v1/all/images                          — get_all_images
    GET  /album/v1/all/images/{image_id}               — get_image
    GET  /album/v1/all/images/{image_id}/product_type  — get_image_product_type
    PUT  /album/v1/shares/{platform_type}/{platform_id} — add_launch_permission
  v2:
    GET  /album/v2/images/enabled                                          — get_enabled_image_set
    GET  /album/v2/images/all                                              — get_all_image_set
    GET  /album/v2/images/{product_type}/{platform_type}/{version}         — get_version_image_set
    POST /album/v2/images/{product_type}/{platform_type}/{version}         — add_new_images_and_create_version_set
    PUT  /album/v2/images/{product_type}/{platform_type}/{version}/enable  — enable_image_records_version_set
"""
from typing import Annotated, List, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule

# Enum literals from schemas.yaml
ProductType = Literal["ids", "scan", "wsm"]
PlatformType = Literal["aws"]


class AlbumModule(BaseModule):
    """AMI sharing service — image records and launch-permission management."""

    # album runs on api.global.alertlogic.com, which is already wired as
    # service_hosts["global"] in BaseModule.  No extra host entry required.

    def register_tools(self, server: FastMCP):
        # v1 — image retrieval
        self._add_tool(server, self.album_get_current_images, "album_get_current_images",
                       "Get current (latest enabled) AMI list, optionally filtered by product/platform type")
        self._add_tool(server, self.album_get_all_images, "album_get_all_images",
                       "Get all AMI records including historical entries with ami_name and description")
        self._add_tool(server, self.album_get_image, "album_get_image",
                       "Get a single AMI record by image_id")
        self._add_tool(server, self.album_get_image_product_type, "album_get_image_product_type",
                       "Get the product type for a specific image_id")
        # v1 — permission management
        self._add_tool(server, self.album_add_launch_permission, "album_add_launch_permission",
                       "Grant launch permission for current images to an AWS account (platform_id)")
        # v2 — versioned image sets
        self._add_tool(server, self.album_get_enabled_image_set, "album_get_enabled_image_set",
                       "Get all enabled image sets (one per product type) — the 'current' production images")
        self._add_tool(server, self.album_get_all_image_set, "album_get_all_image_set",
                       "Get all versioned image sets regardless of enabled state")
        self._add_tool(server, self.album_get_version_image_set, "album_get_version_image_set",
                       "Get a specific versioned image set by product_type, platform_type, and version string")
        self._add_tool(server, self.album_add_new_images, "album_add_new_images",
                       "Add a new AMI version set (POST ami_record body with ami_name, description, image_array)")
        self._add_tool(server, self.album_enable_version_image_set, "album_enable_version_image_set",
                       "Enable a specific version set — makes it the active set for that product/platform")

    # ------------------------------------------------------------------
    # v1 — Image retrieval
    # ------------------------------------------------------------------

    def album_get_current_images(
        self,
        product_type: Annotated[Optional[ProductType], Field(
            description="Filter by product type: 'ids', 'scan', or 'wsm'"
        )] = None,
        platform_type: Annotated[Optional[PlatformType], Field(
            description="Filter by platform type (currently only 'aws')"
        )] = None,
    ) -> dict:
        """GET /album/v1/images — returns the current active image list."""
        params = {}
        if product_type:
            params["product_type"] = product_type
        if platform_type:
            params["platform_type"] = platform_type
        return self._get_global("/album/v1/images", params=params or None)

    def album_get_all_images(self) -> dict:
        """GET /album/v1/all/images — all AMI records including ami_name and description."""
        return self._get_global("/album/v1/all/images")

    def album_get_image(
        self,
        image_id: Annotated[str, Field(description="AMI image ID (e.g., 'ami-11111111111111111')")],
    ) -> dict:
        """GET /album/v1/all/images/{image_id} — single AMI record."""
        return self._get_global(f"/album/v1/all/images/{image_id}")

    def album_get_image_product_type(
        self,
        image_id: Annotated[str, Field(description="AMI image ID to look up the product type for")],
    ) -> dict:
        """GET /album/v1/all/images/{image_id}/product_type — product type for an image."""
        return self._get_global(f"/album/v1/all/images/{image_id}/product_type")

    # ------------------------------------------------------------------
    # v1 — Permission management
    # ------------------------------------------------------------------

    def album_add_launch_permission(
        self,
        platform_type: Annotated[PlatformType, Field(
            description="Platform type — currently only 'aws'"
        )],
        platform_id: Annotated[str, Field(
            description="AWS account ID to grant launch permission to (e.g., '123456789012')"
        )],
    ) -> dict:
        """PUT /album/v1/shares/{platform_type}/{platform_id} — grant AMI launch permission.

        Adds launch permission for all current images to the specified AWS account.
        Returns 204 No Content on success.
        """
        return self._put_global(f"/album/v1/shares/{platform_type}/{platform_id}")

    # ------------------------------------------------------------------
    # v2 — Versioned image sets
    # ------------------------------------------------------------------

    def album_get_enabled_image_set(self) -> dict:
        """GET /album/v2/images/enabled — enabled (production) image sets per product type."""
        return self._get_global("/album/v2/images/enabled")

    def album_get_all_image_set(self) -> dict:
        """GET /album/v2/images/all — all versioned image sets regardless of enabled state."""
        return self._get_global("/album/v2/images/all")

    def album_get_version_image_set(
        self,
        product_type: Annotated[ProductType, Field(
            description="Product type: 'ids', 'scan', or 'wsm'"
        )],
        platform_type: Annotated[PlatformType, Field(
            description="Platform type — currently only 'aws'"
        )],
        version: Annotated[str, Field(
            description="Version string for the image set (e.g., '1.0.0' or a release tag)"
        )],
    ) -> dict:
        """GET /album/v2/images/{product_type}/{platform_type}/{version} — specific version set."""
        return self._get_global(f"/album/v2/images/{product_type}/{platform_type}/{version}")

    def album_add_new_images(
        self,
        product_type: Annotated[ProductType, Field(
            description="Product type: 'ids', 'scan', or 'wsm'"
        )],
        platform_type: Annotated[PlatformType, Field(
            description="Platform type — currently only 'aws'"
        )],
        version: Annotated[str, Field(
            description="Version string for the new image set (e.g., '2.1.0')"
        )],
        ami_name: Annotated[str, Field(
            description="Human-readable AMI name (min length 1, e.g., 'AL-IDS-2.1.0')"
        )],
        description: Annotated[str, Field(
            description="Description of this AMI / version set"
        )],
        image_array: Annotated[List[dict], Field(
            description=(
                "List of region→AMI mappings: "
                "[{\"image_id\": \"ami-111...\", \"region\": \"us-east-1\"}, ...]"
            )
        )],
    ) -> dict:
        """POST /album/v2/images/{product_type}/{platform_type}/{version} — add a new AMI version set.

        Creates a new versioned image record.  All AMIs in image_array are grouped
        under the single version key.  Returns 202 Accepted on success.

        Example image_array:
            [
              {"image_id": "ami-11111111111111111", "region": "us-east-1"},
              {"image_id": "ami-22222222222222222", "region": "us-west-2"}
            ]
        """
        body = {
            "ami_name": ami_name,
            "description": description,
            "image_array": image_array,
        }
        return self._post_global(
            f"/album/v2/images/{product_type}/{platform_type}/{version}",
            json_body=body,
        )

    def album_enable_version_image_set(
        self,
        product_type: Annotated[ProductType, Field(
            description="Product type: 'ids', 'scan', or 'wsm'"
        )],
        platform_type: Annotated[PlatformType, Field(
            description="Platform type — currently only 'aws'"
        )],
        version: Annotated[str, Field(
            description="Version string of the image set to enable"
        )],
    ) -> dict:
        """PUT /album/v2/images/{product_type}/{platform_type}/{version}/enable — activate a version set.

        Makes the specified version the enabled (production) set for its
        product_type/platform_type combination.  Returns 200 on success.
        """
        return self._put_global(
            f"/album/v2/images/{product_type}/{platform_type}/{version}/enable"
        )


def setup(server: FastMCP):
    mod = AlbumModule()
    mod.register_tools(server)
