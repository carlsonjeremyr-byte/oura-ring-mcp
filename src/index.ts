#!/usr/bin/env node
/**
 * Oura MCP Server
 *
 * An MCP server that exposes Oura Ring data with smart analysis tools.
 * Designed to give LLMs human-readable summaries alongside raw data.
 *
 * CLI Commands:
 *   npx oura-ring-mcp          - Start the MCP server (stdio transport)
 *   npx oura-ring-mcp --http   - Start with HTTP transport (for remote deployment)
 *   npx oura-ring-mcp auth     - Authenticate with Oura via OAuth
 *   npx oura-ring-mcp logout   - Clear stored credentials
 *   npx oura-ring-mcp status   - Show authentication status
 */
import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { OuraClient } from "./client.js";
import { registerTools } from "./tools/index.js";
import { registerResources } from "./resources/index.js";
import { registerPrompts } from "./prompts/index.js";
import { OuraTokenManager } from "./auth/token-manager.js";

// Read version from package.json
const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(__dirname, "..", "package.json"), "utf-8"));
const VERSION: string = pkg.version;

// ─────────────────────────────────────────────────────────────
// CLI Command Handling
// ─────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0];
const useHttpTransport = args.includes("--http") || args.includes("-H");

// Handle CLI subcommands
if (["auth", "logout", "status"].includes(command)) {
  // Dynamic import to avoid loading auth modules unless needed
  const { runAuthFlow, runLogout, showAuthStatus } = await import("./auth/cli.js");

  switch (command) {
    case "auth":
      await runAuthFlow();
      break;
    case "logout":
      await runLogout();
      break;
    case "status":
      await showAuthStatus();
      break;
  }
  process.exit(0);
}

// ─────────────────────────────────────────────────────────────
// Token Resolution
// ─────────────────────────────────────────────────────────────

/**
 * Credential precedence:
 *   1. Stored OAuth credentials (auto-refreshed; persisted to OURA_CREDENTIALS_PATH)
 *   2. OURA_ACCESS_TOKEN env var (legacy Personal Access Token — deprecated by Oura)
 *
 * HTTP mode can start with neither: the owner authorizes via GET /oauth/start.
 */
const staticToken = process.env.OURA_ACCESS_TOKEN || process.env.OURA_PERSONAL_ACCESS_TOKEN;
const tokenManager = new OuraTokenManager({ staticToken });
await tokenManager.load();

if (!tokenManager.hasCredentials() && !useHttpTransport) {
  console.error(
    "Error: No Oura credentials found.\n\n" +
      "Authenticate via OAuth (Personal Access Tokens are no longer issued by Oura):\n" +
      "  Run: npx oura-ring-mcp auth\n" +
      "  (Requires OURA_CLIENT_ID and OURA_CLIENT_SECRET)"
  );
  process.exit(1);
}

if (!tokenManager.hasCredentials() && useHttpTransport) {
  console.error(
    "Warning: No Oura credentials found. Server will start; authorize it by opening /oauth/start."
  );
} else if (tokenManager.status().mode === "static") {
  console.error(
    "Warning: Using OURA_ACCESS_TOKEN (Personal Access Token). Oura has deprecated PATs — " +
      "set OURA_CLIENT_ID/OURA_CLIENT_SECRET and authorize via /oauth/start (HTTP) or `auth` (CLI)."
  );
}

// ─────────────────────────────────────────────────────────────
// Server Setup
// ─────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "oura-mcp",
  version: VERSION,
});

const ouraClient = new OuraClient({ tokenManager });

// Register all tools, resources, and prompts with the server
registerTools(server, ouraClient);
registerResources(server, ouraClient);
registerPrompts(server);

// ─────────────────────────────────────────────────────────────
// Start Server
// ─────────────────────────────────────────────────────────────

async function main() {
  if (useHttpTransport) {
    // HTTP transport for remote deployment
    const { startHttpServer } = await import("./transports/http.js");
    await startHttpServer(server, { ouraClient, tokenManager });
  } else {
    // Stdio transport for local use (Claude Desktop)
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Oura MCP server running on stdio");
  }
}

main().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
