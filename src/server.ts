import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from './tools/index.js';
import { registerResources } from './resources/index.js';
import { registerPrompts } from './prompts/index.js';
import { initAuditLog, AuditLogConfig } from './utils/auditLog.js';

export interface ServerOptions {
  /** Audit logging configuration */
  auditLog?: Partial<AuditLogConfig>;
}

const DEFAULT_SERVER_OPTIONS: ServerOptions = {
  auditLog: {
    enabled: true,
    logFile: './mcp-audit.log',
    consoleOutput: false,
    level: 'standard',
    redactSensitive: true,
  },
};

export function createServer(options: ServerOptions = {}): McpServer {
  const opts = { ...DEFAULT_SERVER_OPTIONS, ...options };

  // Initialize audit logging
  initAuditLog(opts.auditLog);

  const server = new McpServer({
    name: 'vuln-scanner-mcp',
    version: '1.0.0',
  });

  // Register all capabilities
  registerTools(server);
  registerResources(server);
  registerPrompts(server);

  return server;
}
