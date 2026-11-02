#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

async function main() {
  const server = createServer();
  const transport = new StdioServerTransport();

  process.on('SIGINT', async () => {
    await server.close();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await server.close();
    process.exit(0);
  });

  await server.connect(transport);
  // Log strictly to stderr so stdio JSON-RPC transport is clean
  console.error('[security-kill-mcp] Server running on stdio');
}

main().catch((error) => {
  console.error('[security-kill-mcp] Fatal error:', error);
  process.exit(1);
});

