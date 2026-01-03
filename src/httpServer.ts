import { randomUUID } from 'node:crypto';
import { createServer } from './server.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';

const HOST = process.env.MCP_HOST || '0.0.0.0';
const PORT = Number(process.env.MCP_PORT || 3000);
const allowedHosts = process.env.MCP_ALLOWED_HOSTS
  ? process.env.MCP_ALLOWED_HOSTS.split(',').map(host => host.trim()).filter(Boolean)
  : undefined;
const enableJsonResponse = process.env.MCP_JSON_RESPONSE === '1';

const app = createMcpExpressApp({ host: HOST, allowedHosts });

// Track active transports by session ID for Streamable HTTP.
const transports: Record<string, StreamableHTTPServerTransport> = Object.create(null);

app.get('/health', (_req, res) => {
  res.status(200).json({ ok: true });
});

app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  try {
    let transport: StreamableHTTPServerTransport | undefined;

    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse,
        onsessioninitialized: sid => {
          transports[sid] = transport as StreamableHTTPServerTransport;
        }
      });

      transport.onclose = () => {
        const sid = transport?.sessionId;
        if (sid && transports[sid]) {
          delete transports[sid];
        }
      };

      const server = createServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      return;
    } else {
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Bad Request: No valid session ID provided'
        },
        id: null
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error('Error handling MCP request:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error'
        },
        id: null
      });
    }
  }
});

app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  await transports[sessionId].handleRequest(req, res);
});

app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  try {
    await transports[sessionId].handleRequest(req, res);
  } catch (error) {
    console.error('Error handling MCP session termination:', error);
    if (!res.headersSent) {
      res.status(500).send('Error processing session termination');
    }
  }
});

app.listen(PORT, HOST, error => {
  if (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }

  const displayHost = HOST === '0.0.0.0' ? 'localhost' : HOST;
  console.log(`MCP Streamable HTTP Server listening at http://${displayHost}:${PORT}/mcp`);
});

process.on('SIGINT', async () => {
  for (const sessionId of Object.keys(transports)) {
    try {
      await transports[sessionId].close();
    } catch (error) {
      console.error(`Error closing transport for session ${sessionId}:`, error);
    } finally {
      delete transports[sessionId];
    }
  }

  process.exit(0);
});
