"""
AlertLogic MCP Server — Main Entrypoint.
Registers all modules and starts the MCP server.
"""
import os
import sys
from pathlib import Path

# Load environment variables from a .env file in the current working directory.
from dotenv import load_dotenv
load_dotenv()

from mcp.server import FastMCP

# ------------------------------------------------------------------ #
#  Server initialization                                              #
# ------------------------------------------------------------------ #

_transport = os.environ.get("MCP_TRANSPORT", "stdio")
_host = os.environ.get("MCP_HOST", "127.0.0.1")
_port = int(os.environ.get("MCP_PORT", "8000"))

server = FastMCP(
    name="AlertLogic MCP Server",
    host=_host,
    port=_port,
)

# ------------------------------------------------------------------ #
#  Module registration                                                #
# ------------------------------------------------------------------ #

from alertlogic_mcp.modules import auth
from alertlogic_mcp.modules import account_management
from alertlogic_mcp.modules import users
from alertlogic_mcp.modules import deployments
from alertlogic_mcp.modules import assets
from alertlogic_mcp.modules import policies
from alertlogic_mcp.modules import credentials
from alertlogic_mcp.modules import network_controls
from alertlogic_mcp.modules import incidents_mcp
from alertlogic_mcp.modules import soc
from alertlogic_mcp.modules import seceng
from alertlogic_mcp.modules import vulnerability
from alertlogic_mcp.modules import compliance
from alertlogic_mcp.modules import logging_integration
from alertlogic_mcp.modules import soar
from alertlogic_mcp.modules import billing
from alertlogic_mcp.modules import common
from alertlogic_mcp.modules import bulk_ops
from alertlogic_mcp.modules import tickets
from alertlogic_mcp.modules import otis
from alertlogic_mcp.modules import ingest_module
from alertlogic_mcp.modules import scan_scheduler
from alertlogic_mcp.modules import vulnerabilities_kb
from alertlogic_mcp.modules import suggestions
from alertlogic_mcp.modules import aecontent
from alertlogic_mcp.modules import themis
from alertlogic_mcp.modules import watchlist_module
from alertlogic_mcp.modules import usage_module
from alertlogic_mcp.modules import assets_manager
from alertlogic_mcp.modules import cloud_explorer
from alertlogic_mcp.modules import azure_explorer
from alertlogic_mcp.modules import aefr
from alertlogic_mcp.modules import aerta
from alertlogic_mcp.modules import aetag
from alertlogic_mcp.modules import aepublish
from alertlogic_mcp.modules import kalm
from alertlogic_mcp.modules import notify
from alertlogic_mcp.modules import search_stylist
from alertlogic_mcp.modules import aemanual
from alertlogic_mcp.modules import environments
from alertlogic_mcp.modules import scan_result
from alertlogic_mcp.modules import album
from alertlogic_mcp.modules import informant
from alertlogic_mcp.modules import strawboss
from alertlogic_mcp.modules import tacoma
from alertlogic_mcp.modules import soc_playbooks

MODULES = [
    auth, account_management, users, deployments, assets, policies, credentials,
    network_controls, incidents_mcp, soc, seceng, vulnerability,
    compliance, logging_integration, soar, billing, common, bulk_ops,
    tickets, otis, ingest_module, scan_scheduler, vulnerabilities_kb,
    suggestions, aecontent, themis, watchlist_module, usage_module,
    assets_manager, cloud_explorer, azure_explorer,
    aefr, aerta, aetag, aepublish, kalm, notify, search_stylist, aemanual,
    environments, scan_result, album, informant, strawboss, tacoma,
    soc_playbooks,
]
for mod in MODULES:
    mod.setup(server)

# ------------------------------------------------------------------ #
#  Start server                                                       #
# ------------------------------------------------------------------ #

def main():
    """Console-script entry point (alertlogic-mcp)."""
    print(f"AlertLogic MCP Server starting ({_transport})", file=sys.stderr)
    print(f"Registered {len(MODULES)} modules", file=sys.stderr)
    server.run(transport=_transport)


if __name__ == "__main__":
    main()