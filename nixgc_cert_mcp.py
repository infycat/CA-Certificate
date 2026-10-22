#!/usr/bin/env python3
"""nixgc_cert_mcp.py - standalone CLI wrapper for the certificate MCP server.

The GUI hosts the same server in-process (see mcp_server.MCPHost), so most
people never need this file.  It exists for headless use: CI, a server with
no display, or a client that insists on launching its own stdio subprocess.

  python nixgc_cert_mcp.py                 # stdio
  python nixgc_cert_mcp.py --http 8765     # streamable HTTP
"""

from __future__ import annotations

import argparse
import sys

from mcp_server import build_server, store


def main() -> int:
    ap = argparse.ArgumentParser(description="nixgc certificate MCP server (standalone)")
    ap.add_argument(
        "--http",
        type=int,
        default=None,
        metavar="PORT",
        help="serve streamable HTTP on this port instead of stdio",
    )
    ap.add_argument("--host", default="127.0.0.1", help="HTTP bind address")
    ap.add_argument(
        "--json-response",
        action="store_true",
        help="HTTP transport: reply with plain JSON instead of SSE frames",
    )
    args = ap.parse_args()

    st = store()
    print(
        f"[nixgc-mcp] {len(st.certs)} certs, {len(st.keys)} keys, "
        f"{len(st.ca_keys)} CA keys",
        file=sys.stderr,
    )

    server = build_server()
    if args.http:
        print(
            f"[nixgc-mcp] HTTP on http://{args.host}:{args.http}/mcp", file=sys.stderr
        )
        server.run(
            transport="streamable-http",
            host=args.host,
            port=args.http,
            json_response=args.json_response,
        )
    else:
        print("[nixgc-mcp] stdio transport", file=sys.stderr)
        server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

