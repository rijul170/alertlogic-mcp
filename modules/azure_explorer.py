"""
AlertLogic Azure Explorer.
Discover and enumerate Azure resources — subscriptions, resource groups,
virtual machines, network security groups, and virtual networks —
as seen by Alert Logic's cloud discovery service.

Official API: https://console.cloudinsight.alertlogic.com/api/azure_explorer/
"""
from typing import Annotated, Optional
from pydantic import Field
from mcp.server import FastMCP
from modules.base import BaseModule


class AzureExplorerModule(BaseModule):
    """Azure resource discovery and enumeration (azure_explorer v1)."""

    def register_tools(self, server: FastMCP):
        # ---- Subscriptions ----
        self._add_tool(server, self.azure_explorer_list_subscriptions,
                       "azure_explorer_list_subscriptions",
                       "List Azure subscriptions discovered for an account")
        self._add_tool(server, self.azure_explorer_get_subscription,
                       "azure_explorer_get_subscription",
                       "Get details of a specific Azure subscription")
        # ---- Resource Groups ----
        self._add_tool(server, self.azure_explorer_list_resource_groups,
                       "azure_explorer_list_resource_groups",
                       "List Azure resource groups within a subscription")
        self._add_tool(server, self.azure_explorer_get_resource_group,
                       "azure_explorer_get_resource_group",
                       "Get details of a specific Azure resource group")
        # ---- Virtual Networks ----
        self._add_tool(server, self.azure_explorer_list_virtual_networks,
                       "azure_explorer_list_virtual_networks",
                       "List Azure virtual networks (VNets) in a subscription or resource group")
        self._add_tool(server, self.azure_explorer_get_virtual_network,
                       "azure_explorer_get_virtual_network",
                       "Get details of a specific Azure virtual network")
        # ---- Subnets ----
        self._add_tool(server, self.azure_explorer_list_subnets,
                       "azure_explorer_list_subnets",
                       "List subnets within an Azure virtual network")
        # ---- Virtual Machines ----
        self._add_tool(server, self.azure_explorer_list_virtual_machines,
                       "azure_explorer_list_virtual_machines",
                       "List Azure virtual machines discovered in a subscription or resource group")
        self._add_tool(server, self.azure_explorer_get_virtual_machine,
                       "azure_explorer_get_virtual_machine",
                       "Get details of a specific Azure virtual machine")
        # ---- Network Security Groups ----
        self._add_tool(server, self.azure_explorer_list_security_groups,
                       "azure_explorer_list_security_groups",
                       "List Azure Network Security Groups (NSGs) in a subscription or resource group")
        self._add_tool(server, self.azure_explorer_get_security_group,
                       "azure_explorer_get_security_group",
                       "Get details and rules of a specific Azure NSG")
        # ---- Network Interfaces ----
        self._add_tool(server, self.azure_explorer_list_network_interfaces,
                       "azure_explorer_list_network_interfaces",
                       "List Azure network interfaces in a subscription or resource group")
        # ---- Public IP Addresses ----
        self._add_tool(server, self.azure_explorer_list_public_ips,
                       "azure_explorer_list_public_ips",
                       "List Azure public IP address resources in a subscription or resource group")

    # ---- Subscriptions ----

    def azure_explorer_list_subscriptions(
        self,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List subscriptions. GET /azure_explorer/v1/{account_id}/subscriptions"""
        return self._get(
            "/azure_explorer/v1/{account_id}/subscriptions",
            account_id=account_id,
        )

    def azure_explorer_get_subscription(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get subscription. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}"""
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}",
            account_id=account_id,
        )

    # ---- Resource Groups ----

    def azure_explorer_list_resource_groups(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List resource groups. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/resource_groups"""
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/resource_groups",
            account_id=account_id,
        )

    def azure_explorer_get_resource_group(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[str, Field(description="Resource group name")],
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get resource group. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/resource_groups/{resource_group_name}"""
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/resource_groups/{resource_group_name}",
            account_id=account_id,
        )

    # ---- Virtual Networks ----

    def azure_explorer_list_virtual_networks(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Filter by resource group name"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List VNets. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/virtual_networks"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/virtual_networks",
            account_id=account_id,
            params=params or None,
        )

    def azure_explorer_get_virtual_network(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        virtual_network_name: Annotated[str, Field(description="Virtual network name")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Resource group containing the VNet"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get VNet. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/virtual_networks/{virtual_network_name}"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/virtual_networks/{virtual_network_name}",
            account_id=account_id,
            params=params or None,
        )

    # ---- Subnets ----

    def azure_explorer_list_subnets(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        virtual_network_name: Annotated[str, Field(description="Virtual network name")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Resource group containing the VNet"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List subnets. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/virtual_networks/{virtual_network_name}/subnets"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/virtual_networks/{virtual_network_name}/subnets",
            account_id=account_id,
            params=params or None,
        )

    # ---- Virtual Machines ----

    def azure_explorer_list_virtual_machines(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Filter by resource group name"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List VMs. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/virtual_machines"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/virtual_machines",
            account_id=account_id,
            params=params or None,
        )

    def azure_explorer_get_virtual_machine(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        vm_name: Annotated[str, Field(description="Virtual machine name")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Resource group containing the VM"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get VM. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/virtual_machines/{vm_name}"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/virtual_machines/{vm_name}",
            account_id=account_id,
            params=params or None,
        )

    # ---- Network Security Groups ----

    def azure_explorer_list_security_groups(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Filter by resource group name"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List NSGs. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/security_groups"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/security_groups",
            account_id=account_id,
            params=params or None,
        )

    def azure_explorer_get_security_group(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        security_group_name: Annotated[str, Field(description="Network Security Group name")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Resource group containing the NSG"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """Get NSG. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/security_groups/{security_group_name}"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/security_groups/{security_group_name}",
            account_id=account_id,
            params=params or None,
        )

    # ---- Network Interfaces ----

    def azure_explorer_list_network_interfaces(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Filter by resource group name"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List NICs. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/network_interfaces"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/network_interfaces",
            account_id=account_id,
            params=params or None,
        )

    # ---- Public IP Addresses ----

    def azure_explorer_list_public_ips(
        self,
        subscription_id: Annotated[str, Field(description="Azure subscription UUID")],
        resource_group_name: Annotated[Optional[str], Field(
            description="Filter by resource group name"
        )] = None,
        account_id: Annotated[Optional[str], Field(description="Account ID")] = None,
    ) -> dict:
        """List public IPs. GET /azure_explorer/v1/{account_id}/subscriptions/{subscription_id}/public_ip_addresses"""
        params = {}
        if resource_group_name:
            params["resource_group"] = resource_group_name
        return self._get(
            f"/azure_explorer/v1/{{account_id}}/subscriptions/{subscription_id}/public_ip_addresses",
            account_id=account_id,
            params=params or None,
        )


def setup(server: FastMCP):
    mod = AzureExplorerModule()
    mod.register_tools(server)
