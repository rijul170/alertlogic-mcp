"""
AlertLogic MCP Server — Main Entrypoint.
Registers all modules and starts the MCP server.
"""
import os
import sys
from pathlib import Path

# Ensure the project directory is in sys.path for module imports
PROJECT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_DIR))

# Load environment variables from explicit .env path
# (Python 3.14 find_dotenv() has a frame assertion bug)
from dotenv import load_dotenv
load_dotenv(PROJECT_DIR / ".env")

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

from modules import auth
from modules import account_management
from modules import users
from modules import deployments
from modules import assets
from modules import policies
from modules import credentials
from modules import network_controls
from modules import incidents_mcp
from modules import soc
from modules import seceng
from modules import vulnerability
from modules import compliance
from modules import logging_integration
from modules import soar
from modules import billing
from modules import common
from modules import bulk_ops
from modules import tickets
from modules import otis
from modules import ingest_module
from modules import scan_scheduler
from modules import vulnerabilities_kb
from modules import suggestions
from modules import aecontent
from modules import themis
from modules import watchlist_module
from modules import usage_module
from modules import assets_manager
from modules import cloud_explorer
from modules import azure_explorer
from modules import aefr
from modules import aerta
from modules import aetag
from modules import aepublish
from modules import kalm
from modules import notify
from modules import search_stylist
from modules import aemanual
from modules import environments
from modules import scan_result
from modules import album
from modules import informant
from modules import strawboss
from modules import tacoma
from modules import soc_playbooks

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

if __name__ == "__main__":
    print(f"AlertLogic MCP Server starting ({_transport})", file=sys.stderr)
    print(f"Registered {len(MODULES)} modules", file=sys.stderr)
    server.run(transport=_transport)