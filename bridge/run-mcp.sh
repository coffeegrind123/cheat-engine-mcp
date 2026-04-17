#!/bin/bash
# Startup wrapper for the CE MCP bridge.
#
# Override the HTTP endpoint with CE_HTTP_URL if the plugin isn't reachable
# at the default host.docker.internal:6789.

: "${CE_HTTP_URL:=http://host.docker.internal:6789}"
export CE_HTTP_URL

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[CE MCP Bridge] Connecting to ${CE_HTTP_URL}" >&2
exec python3 "${SCRIPT_DIR}/bridge_mcp_cheatengine.py"
