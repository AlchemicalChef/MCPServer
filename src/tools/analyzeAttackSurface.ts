import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

type SupportedLanguage = 'javascript' | 'typescript' | 'python' | 'go' | 'php' | 'ruby';

interface EntryPointPattern {
  category: string;
  name: string;
  patterns: RegExp[];
  variableExtractor: RegExp; // Regex to extract the variable being assigned
  risk: 'high' | 'medium' | 'low';
  description: string;
}

interface SinkPattern {
  category: string;
  name: string;
  patterns: RegExp[];
  argumentExtractor: RegExp; // Regex to extract arguments passed to sink
  vulnerabilityType: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface TaintedVariable {
  name: string;
  source: string;
  sourceLine: number;
  sourceCategory: string;
  risk: 'high' | 'medium' | 'low';
  propagations: Array<{ line: number; code: string; newName?: string }>;
}

interface EntryPoint {
  category: string;
  name: string;
  file: string;
  line: number;
  code: string;
  risk: 'high' | 'medium' | 'low';
  variable?: string;
}

interface Sink {
  category: string;
  name: string;
  file: string;
  line: number;
  code: string;
  vulnerabilityType: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  taintedArgs?: string[];
}

interface DataFlowPath {
  source: EntryPoint;
  sink: Sink;
  path: Array<{ line: number; code: string; description: string }>;
  taintedVariable: string;
  confidence: 'high' | 'medium' | 'low';
}

// ============================================================================
// ENTRY POINT PATTERNS BY LANGUAGE
// ============================================================================

const entryPointPatterns: Record<SupportedLanguage, EntryPointPattern[]> = {
  javascript: [
    {
      category: 'HTTP Request',
      name: 'Request Body',
      patterns: [/req\.body\s*[.\[]/g, /request\.body\s*[.\[]/g, /ctx\.request\.body/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.body/,
      risk: 'high',
      description: 'User-controlled HTTP request body',
    },
    {
      category: 'HTTP Request',
      name: 'Request Query',
      patterns: [/req\.query\s*[.\[]/g, /request\.query\s*[.\[]/g, /ctx\.query/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.query/,
      risk: 'high',
      description: 'User-controlled query parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Request Params',
      patterns: [/req\.params\s*[.\[]/g, /request\.params\s*[.\[]/g, /ctx\.params/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.params/,
      risk: 'high',
      description: 'User-controlled URL parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Request Headers',
      patterns: [/req\.headers\s*[.\[]/g, /request\.headers\s*[.\[]/g, /req\.get\s*\(/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:headers|get)/,
      risk: 'high',
      description: 'User-controlled HTTP headers',
    },
    {
      category: 'HTTP Request',
      name: 'Request Cookies',
      patterns: [/req\.cookies\s*[.\[]/g, /request\.cookies\s*[.\[]/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.cookies/,
      risk: 'high',
      description: 'User-controlled cookies',
    },
    {
      category: 'Environment',
      name: 'Environment Variables',
      patterns: [/process\.env\s*[.\[]/g, /process\.env\.(\w+)/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*process\.env/,
      risk: 'medium',
      description: 'Environment variable access',
    },
    {
      category: 'CLI Arguments',
      name: 'Command Line Args',
      patterns: [/process\.argv/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*process\.argv/,
      risk: 'medium',
      description: 'Command-line arguments',
    },
    {
      category: 'File Input',
      name: 'File Read',
      patterns: [/fs\.readFile(?:Sync)?\s*\(/g, /fs\.read(?:Sync)?\s*\(/g, /createReadStream\s*\(/g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?fs\.readFile/,
      risk: 'medium',
      description: 'File system input',
    },
    {
      category: 'User Files',
      name: 'File Uploads',
      patterns: [/req\.files?\s*[.\[]/g, /req\.file\s*\./g],
      variableExtractor: /(?:const|let|var)\s+(\w+)\s*=\s*req\.files?/,
      risk: 'high',
      description: 'User file uploads',
    },
    {
      category: 'Network',
      name: 'WebSocket Message',
      patterns: [/\.on\s*\(\s*['"]message['"]/g, /socket\.on\s*\(\s*['"]data['"]/g],
      variableExtractor: /\.on\s*\(\s*['"](?:message|data)['"]\s*,\s*(?:\(\s*)?(\w+)/,
      risk: 'high',
      description: 'WebSocket/Socket data',
    },
  ],
  typescript: [], // Will copy from JS
  python: [
    {
      category: 'HTTP Request',
      name: 'Flask Request',
      patterns: [/request\.(?:args|form|json|data|values|files)/g],
      variableExtractor: /(\w+)\s*=\s*request\.(?:args|form|json|data|values|files)/,
      risk: 'high',
      description: 'Flask request data',
    },
    {
      category: 'HTTP Request',
      name: 'Django Request',
      patterns: [/request\.(?:GET|POST|FILES)/g],
      variableExtractor: /(\w+)\s*=\s*request\.(?:GET|POST|FILES)/,
      risk: 'high',
      description: 'Django request data',
    },
    {
      category: 'Environment',
      name: 'Environment Variables',
      patterns: [/os\.environ\s*[.\[]/g, /os\.getenv\s*\(/g],
      variableExtractor: /(\w+)\s*=\s*os\.(?:environ|getenv)/,
      risk: 'medium',
      description: 'Environment variable access',
    },
    {
      category: 'CLI Arguments',
      name: 'Command Line Args',
      patterns: [/sys\.argv/g, /argparse/g],
      variableExtractor: /(\w+)\s*=\s*(?:sys\.argv|args\.)/,
      risk: 'medium',
      description: 'Command-line arguments',
    },
    {
      category: 'File Input',
      name: 'File Read',
      patterns: [/open\s*\([^)]+\)\.read/g, /\.read\s*\(\)/g, /\.readline/g],
      variableExtractor: /(\w+)\s*=\s*(?:open\s*\([^)]+\)\.read|.*\.read\s*\(\))/,
      risk: 'medium',
      description: 'File content',
    },
    {
      category: 'Network',
      name: 'Socket Data',
      patterns: [/\.recv\s*\(/g, /\.recvfrom\s*\(/g],
      variableExtractor: /(\w+)\s*=\s*.*\.recv(?:from)?\s*\(/,
      risk: 'high',
      description: 'Socket data',
    },
    {
      category: 'Database',
      name: 'Database Query Result',
      patterns: [/cursor\.fetchone/g, /cursor\.fetchall/g, /\.objects\.(?:get|filter|all)/g],
      variableExtractor: /(\w+)\s*=\s*(?:cursor\.fetch|.*\.objects\.)/,
      risk: 'low',
      description: 'Database query results',
    },
  ],
  go: [
    {
      category: 'HTTP Request',
      name: 'Form Values',
      patterns: [/r\.FormValue\s*\(/g, /r\.PostFormValue\s*\(/g],
      variableExtractor: /(\w+)\s*:?=\s*r\.(?:Form|PostForm)Value/,
      risk: 'high',
      description: 'HTTP form data',
    },
    {
      category: 'HTTP Request',
      name: 'URL Query',
      patterns: [/r\.URL\.Query\s*\(\)/g],
      variableExtractor: /(\w+)\s*:?=\s*r\.URL\.Query/,
      risk: 'high',
      description: 'URL query parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Request Body',
      patterns: [/r\.Body/g, /ioutil\.ReadAll\s*\(\s*r\.Body/g, /io\.ReadAll\s*\(\s*r\.Body/g],
      variableExtractor: /(\w+)\s*,?\s*\w*\s*:?=\s*(?:ioutil|io)\.ReadAll\s*\(\s*r\.Body/,
      risk: 'high',
      description: 'HTTP request body',
    },
    {
      category: 'HTTP Request',
      name: 'Mux Variables',
      patterns: [/mux\.Vars\s*\(/g, /chi\.URLParam\s*\(/g, /c\.Param\s*\(/g],
      variableExtractor: /(\w+)\s*:?=\s*(?:mux\.Vars|chi\.URLParam|c\.Param)/,
      risk: 'high',
      description: 'URL path parameters',
    },
    {
      category: 'Environment',
      name: 'Environment Variables',
      patterns: [/os\.Getenv\s*\(/g, /os\.LookupEnv\s*\(/g],
      variableExtractor: /(\w+)\s*,?\s*\w*\s*:?=\s*os\.(?:Getenv|LookupEnv)/,
      risk: 'medium',
      description: 'Environment variable',
    },
    {
      category: 'CLI Arguments',
      name: 'Command Line Args',
      patterns: [/os\.Args/g, /flag\.\w+\s*\(/g],
      variableExtractor: /(\w+)\s*:?=\s*(?:os\.Args|flag\.)/,
      risk: 'medium',
      description: 'Command-line arguments',
    },
    {
      category: 'File Input',
      name: 'File Read',
      patterns: [/(?:ioutil|os)\.ReadFile\s*\(/g, /os\.Open\s*\(/g],
      variableExtractor: /(\w+)\s*,?\s*\w*\s*:?=\s*(?:ioutil|os)\.(?:ReadFile|Open)/,
      risk: 'medium',
      description: 'File content',
    },
  ],
  php: [
    {
      category: 'HTTP Request',
      name: 'GET Parameters',
      patterns: [/\$_GET\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_GET/,
      risk: 'high',
      description: 'GET parameters',
    },
    {
      category: 'HTTP Request',
      name: 'POST Parameters',
      patterns: [/\$_POST\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_POST/,
      risk: 'high',
      description: 'POST parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Request Parameters',
      patterns: [/\$_REQUEST\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_REQUEST/,
      risk: 'high',
      description: 'Request parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Cookies',
      patterns: [/\$_COOKIE\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_COOKIE/,
      risk: 'high',
      description: 'Cookie values',
    },
    {
      category: 'HTTP Request',
      name: 'File Uploads',
      patterns: [/\$_FILES\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_FILES/,
      risk: 'high',
      description: 'File uploads',
    },
    {
      category: 'HTTP Request',
      name: 'Server Variables',
      patterns: [/\$_SERVER\s*\[\s*['"](?:REQUEST_URI|QUERY_STRING|HTTP_)/g],
      variableExtractor: /\$(\w+)\s*=\s*\$_SERVER/,
      risk: 'high',
      description: 'Server variables',
    },
    {
      category: 'Environment',
      name: 'Environment Variables',
      patterns: [/getenv\s*\(/g, /\$_ENV\s*\[/g],
      variableExtractor: /\$(\w+)\s*=\s*(?:getenv|\$_ENV)/,
      risk: 'medium',
      description: 'Environment variables',
    },
    {
      category: 'File Input',
      name: 'File Read',
      patterns: [/file_get_contents\s*\(/g, /fread\s*\(/g, /fgets\s*\(/g, /file\s*\(/g],
      variableExtractor: /\$(\w+)\s*=\s*(?:file_get_contents|fread|fgets|file)\s*\(/,
      risk: 'medium',
      description: 'File content',
    },
  ],
  ruby: [
    {
      category: 'HTTP Request',
      name: 'Rails Params',
      patterns: [/params\s*\[/g, /params\.(?:require|permit|fetch)/g],
      variableExtractor: /(\w+)\s*=\s*params/,
      risk: 'high',
      description: 'Request parameters',
    },
    {
      category: 'HTTP Request',
      name: 'Request Object',
      patterns: [/request\.(?:body|headers|cookies)/g],
      variableExtractor: /(\w+)\s*=\s*request\./,
      risk: 'high',
      description: 'Request data',
    },
    {
      category: 'Environment',
      name: 'Environment Variables',
      patterns: [/ENV\s*\[/g, /ENV\.fetch/g],
      variableExtractor: /(\w+)\s*=\s*ENV/,
      risk: 'medium',
      description: 'Environment variables',
    },
    {
      category: 'File Input',
      name: 'File Read',
      patterns: [/File\.read/g, /IO\.read/g, /File\.open.*\.read/g],
      variableExtractor: /(\w+)\s*=\s*(?:File|IO)\.(?:read|open)/,
      risk: 'medium',
      description: 'File content',
    },
  ],
};

entryPointPatterns.typescript = entryPointPatterns.javascript;

// ============================================================================
// SINK PATTERNS BY LANGUAGE
// ============================================================================

const sinkPatterns: Record<SupportedLanguage, SinkPattern[]> = {
  javascript: [
    {
      category: 'SQL',
      name: 'SQL Query',
      patterns: [/\.query\s*\(/g, /\.execute\s*\(/g, /\.raw\s*\(/g],
      argumentExtractor: /\.(?:query|execute|raw)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
    },
    {
      category: 'Command',
      name: 'Command Execution',
      patterns: [/exec\s*\(/g, /execSync\s*\(/g, /spawn\s*\(/g, /execFile\s*\(/g],
      argumentExtractor: /(?:exec|execSync|spawn|execFile)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'Command Injection',
      cwe: 'CWE-78',
      severity: 'critical',
    },
    {
      category: 'Eval',
      name: 'Code Evaluation',
      patterns: [/\beval\s*\(/g, /Function\s*\(/g, /vm\.runIn/g],
      argumentExtractor: /(?:eval|Function|vm\.runIn\w*)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Code Injection',
      cwe: 'CWE-94',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Write',
      patterns: [/fs\.writeFile/g, /fs\.appendFile/g, /createWriteStream\s*\(/g],
      argumentExtractor: /(?:writeFile|appendFile|createWriteStream)\s*\(\s*([^,]+)/,
      vulnerabilityType: 'Arbitrary File Write',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'File',
      name: 'File Path',
      patterns: [/fs\.(?:readFile|unlink|rmdir|stat|access)\s*\(/g],
      argumentExtractor: /fs\.\w+\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'Path Traversal',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'Network',
      name: 'HTTP Request',
      patterns: [/fetch\s*\(/g, /axios\s*[.(]/g, /got\s*\(/g, /request\s*\(/g, /http\.get\s*\(/g],
      argumentExtractor: /(?:fetch|axios|got|request|http\.get)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'SSRF',
      cwe: 'CWE-918',
      severity: 'high',
    },
    {
      category: 'Template',
      name: 'Template Render',
      patterns: [/\.render\s*\(/g, /ejs\.render/g, /pug\.render/g],
      argumentExtractor: /\.render\s*\(\s*[^,]+,\s*(\{[^}]+\}|\w+)/,
      vulnerabilityType: 'SSTI',
      cwe: 'CWE-1336',
      severity: 'high',
    },
    {
      category: 'DOM',
      name: 'DOM Manipulation',
      patterns: [/\.innerHTML\s*=/g, /\.outerHTML\s*=/g, /document\.write\s*\(/g],
      argumentExtractor: /(?:innerHTML|outerHTML)\s*=\s*([^;]+)|document\.write\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'XSS',
      cwe: 'CWE-79',
      severity: 'high',
    },
    {
      category: 'Deserialize',
      name: 'Deserialization',
      patterns: [/JSON\.parse\s*\(/g, /deserialize\s*\(/g],
      argumentExtractor: /(?:JSON\.parse|deserialize)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Insecure Deserialization',
      cwe: 'CWE-502',
      severity: 'medium',
    },
    {
      category: 'Redirect',
      name: 'Open Redirect',
      patterns: [/res\.redirect\s*\(/g, /response\.redirect\s*\(/g, /location\.href\s*=/g],
      argumentExtractor: /(?:redirect\s*\(|location\.href\s*=)\s*([^);]+)/,
      vulnerabilityType: 'Open Redirect',
      cwe: 'CWE-601',
      severity: 'medium',
    },
  ],
  typescript: [],
  python: [
    {
      category: 'SQL',
      name: 'SQL Query',
      patterns: [/cursor\.execute\s*\(/g, /\.execute\s*\(\s*f?['"]/g, /\.raw\s*\(/g],
      argumentExtractor: /\.execute\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
    },
    {
      category: 'Command',
      name: 'Command Execution',
      patterns: [/os\.system\s*\(/g, /os\.popen\s*\(/g, /subprocess\.(?:call|run|Popen)\s*\(/g],
      argumentExtractor: /(?:os\.(?:system|popen)|subprocess\.\w+)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Command Injection',
      cwe: 'CWE-78',
      severity: 'critical',
    },
    {
      category: 'Eval',
      name: 'Code Evaluation',
      patterns: [/\beval\s*\(/g, /\bexec\s*\(/g, /compile\s*\(/g],
      argumentExtractor: /(?:eval|exec|compile)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Code Injection',
      cwe: 'CWE-94',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Operations',
      patterns: [/open\s*\([^)]+,\s*['"][wa]/g, /shutil\.(?:copy|move)/g],
      argumentExtractor: /(?:open|shutil\.\w+)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'Arbitrary File Write',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'Network',
      name: 'HTTP Request',
      patterns: [/requests\.(?:get|post|put|delete)\s*\(/g, /urllib\.request\.urlopen\s*\(/g],
      argumentExtractor: /(?:requests\.\w+|urllib\.request\.urlopen)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'SSRF',
      cwe: 'CWE-918',
      severity: 'high',
    },
    {
      category: 'Template',
      name: 'Template Render',
      patterns: [/render_template_string\s*\(/g, /Template\s*\([^)]*\)\.render/g],
      argumentExtractor: /(?:render_template_string|Template)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'SSTI',
      cwe: 'CWE-1336',
      severity: 'high',
    },
    {
      category: 'Deserialize',
      name: 'Deserialization',
      patterns: [/pickle\.loads?\s*\(/g, /yaml\.(?:load|unsafe_load)\s*\(/g, /marshal\.loads?\s*\(/g],
      argumentExtractor: /(?:pickle|yaml|marshal)\.loads?\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Insecure Deserialization',
      cwe: 'CWE-502',
      severity: 'critical',
    },
    {
      category: 'Redirect',
      name: 'Open Redirect',
      patterns: [/redirect\s*\(/g, /HttpResponseRedirect\s*\(/g],
      argumentExtractor: /(?:redirect|HttpResponseRedirect)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Open Redirect',
      cwe: 'CWE-601',
      severity: 'medium',
    },
  ],
  go: [
    {
      category: 'SQL',
      name: 'SQL Query',
      patterns: [/\.(?:Query|Exec|QueryRow)\s*\(/g],
      argumentExtractor: /\.(?:Query|Exec|QueryRow)\s*\(\s*(?:ctx\s*,\s*)?([^)]+)\)/,
      vulnerabilityType: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
    },
    {
      category: 'Command',
      name: 'Command Execution',
      patterns: [/exec\.Command\s*\(/g],
      argumentExtractor: /exec\.Command\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Command Injection',
      cwe: 'CWE-78',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Operations',
      patterns: [/(?:os|ioutil)\.(?:WriteFile|Create|OpenFile)\s*\(/g],
      argumentExtractor: /(?:os|ioutil)\.\w+\s*\(\s*([^,]+)/,
      vulnerabilityType: 'Path Traversal',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'Network',
      name: 'HTTP Request',
      patterns: [/http\.(?:Get|Post|Do)\s*\(/g],
      argumentExtractor: /http\.(?:Get|Post|Do)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'SSRF',
      cwe: 'CWE-918',
      severity: 'high',
    },
    {
      category: 'Template',
      name: 'Template Execution',
      patterns: [/\.Execute\s*\(/g, /template\.(?:HTML|JS|URL)\s*\(/g],
      argumentExtractor: /\.Execute\s*\(\s*\w+\s*,\s*([^)]+)\)/,
      vulnerabilityType: 'SSTI',
      cwe: 'CWE-1336',
      severity: 'high',
    },
    {
      category: 'Redirect',
      name: 'Open Redirect',
      patterns: [/http\.Redirect\s*\(/g],
      argumentExtractor: /http\.Redirect\s*\([^,]+,[^,]+,\s*([^,]+)/,
      vulnerabilityType: 'Open Redirect',
      cwe: 'CWE-601',
      severity: 'medium',
    },
  ],
  php: [
    {
      category: 'SQL',
      name: 'SQL Query',
      patterns: [/mysqli?_query\s*\(/g, /\->query\s*\(/g, /\->execute\s*\(/g],
      argumentExtractor: /(?:mysqli?_query|->query|->execute)\s*\(\s*(?:\$\w+\s*,\s*)?([^)]+)\)/,
      vulnerabilityType: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
    },
    {
      category: 'Command',
      name: 'Command Execution',
      patterns: [/\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(/g],
      argumentExtractor: /(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Command Injection',
      cwe: 'CWE-78',
      severity: 'critical',
    },
    {
      category: 'Eval',
      name: 'Code Evaluation',
      patterns: [/\beval\s*\(/g, /\bassert\s*\(/g, /create_function\s*\(/g, /preg_replace\s*\([^)]*\/e/g],
      argumentExtractor: /(?:eval|assert|create_function)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Code Injection',
      cwe: 'CWE-94',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Inclusion',
      patterns: [/\b(?:include|require|include_once|require_once)\s*\(?/g],
      argumentExtractor: /(?:include|require|include_once|require_once)\s*\(?\s*([^;)]+)/,
      vulnerabilityType: 'LFI/RFI',
      cwe: 'CWE-98',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Operations',
      patterns: [/file_put_contents\s*\(/g, /fwrite\s*\(/g, /move_uploaded_file\s*\(/g],
      argumentExtractor: /(?:file_put_contents|fwrite|move_uploaded_file)\s*\(\s*([^,]+)/,
      vulnerabilityType: 'Arbitrary File Write',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'Network',
      name: 'HTTP Request',
      patterns: [/file_get_contents\s*\(\s*['"]?https?/g, /curl_exec\s*\(/g, /fopen\s*\(\s*['"]?https?/g],
      argumentExtractor: /(?:file_get_contents|fopen)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'SSRF',
      cwe: 'CWE-918',
      severity: 'high',
    },
    {
      category: 'Deserialize',
      name: 'Deserialization',
      patterns: [/unserialize\s*\(/g],
      argumentExtractor: /unserialize\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Insecure Deserialization',
      cwe: 'CWE-502',
      severity: 'critical',
    },
    {
      category: 'Redirect',
      name: 'Open Redirect',
      patterns: [/header\s*\(\s*['"]Location:/g],
      argumentExtractor: /header\s*\(\s*['"]Location:\s*([^'"]+)/,
      vulnerabilityType: 'Open Redirect',
      cwe: 'CWE-601',
      severity: 'medium',
    },
  ],
  ruby: [
    {
      category: 'SQL',
      name: 'SQL Query',
      patterns: [/\.(?:execute|find_by_sql|where)\s*\(\s*['"]/g, /\.where\s*\([^)]*#\{/g],
      argumentExtractor: /\.(?:execute|find_by_sql|where)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
    },
    {
      category: 'Command',
      name: 'Command Execution',
      patterns: [/\bsystem\s*\(/g, /\bexec\s*\(/g, /`[^`]+`/g, /%x\{/g, /Open3\./g, /IO\.popen/g],
      argumentExtractor: /(?:system|exec|IO\.popen)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Command Injection',
      cwe: 'CWE-78',
      severity: 'critical',
    },
    {
      category: 'Eval',
      name: 'Code Evaluation',
      patterns: [/\beval\s*\(/g, /instance_eval/g, /class_eval/g, /module_eval/g, /send\s*\(/g],
      argumentExtractor: /(?:eval|instance_eval|class_eval|send)\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Code Injection',
      cwe: 'CWE-94',
      severity: 'critical',
    },
    {
      category: 'File',
      name: 'File Operations',
      patterns: [/File\.(?:write|open)/g, /IO\.write/g],
      argumentExtractor: /(?:File|IO)\.(?:write|open)\s*\(\s*([^,]+)/,
      vulnerabilityType: 'Arbitrary File Write',
      cwe: 'CWE-22',
      severity: 'high',
    },
    {
      category: 'Network',
      name: 'HTTP Request',
      patterns: [/Net::HTTP\.(?:get|post)/g, /open-uri/g, /RestClient/g],
      argumentExtractor: /(?:Net::HTTP\.\w+|open|RestClient\.\w+)\s*\(\s*([^,)]+)/,
      vulnerabilityType: 'SSRF',
      cwe: 'CWE-918',
      severity: 'high',
    },
    {
      category: 'Template',
      name: 'Template Render',
      patterns: [/ERB\.new\s*\(/g, /render\s+inline:/g],
      argumentExtractor: /(?:ERB\.new|render\s+inline:)\s*\(?([^)]+)\)?/,
      vulnerabilityType: 'SSTI',
      cwe: 'CWE-1336',
      severity: 'high',
    },
    {
      category: 'Deserialize',
      name: 'Deserialization',
      patterns: [/Marshal\.load/g, /YAML\.load\s*\(/g],
      argumentExtractor: /(?:Marshal|YAML)\.load\s*\(\s*([^)]+)\)/,
      vulnerabilityType: 'Insecure Deserialization',
      cwe: 'CWE-502',
      severity: 'critical',
    },
    {
      category: 'Redirect',
      name: 'Open Redirect',
      patterns: [/redirect_to\s+/g],
      argumentExtractor: /redirect_to\s+([^\s,]+)/,
      vulnerabilityType: 'Open Redirect',
      cwe: 'CWE-601',
      severity: 'medium',
    },
  ],
};

sinkPatterns.typescript = sinkPatterns.javascript;

// ============================================================================
// TAINT TRACKING ENGINE
// ============================================================================

class TaintTracker {
  private taintedVars: Map<string, TaintedVariable> = new Map();
  private lines: string[];
  private language: SupportedLanguage;

  constructor(content: string, language: SupportedLanguage) {
    this.lines = content.split('\n');
    this.language = language;
  }

  // Extract variable name from an assignment
  private extractAssignedVariable(line: string): string | null {
    const patterns: Record<SupportedLanguage, RegExp[]> = {
      javascript: [
        /(?:const|let|var)\s+(\w+)\s*=/,
        /(?:const|let|var)\s+\{\s*([^}]+)\s*\}\s*=/,  // destructuring
      ],
      typescript: [
        /(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=/,
        /(?:const|let|var)\s+\{\s*([^}]+)\s*\}\s*(?::\s*\w+)?\s*=/,
      ],
      python: [/^(\w+)\s*=/],
      go: [/(\w+)\s*:?=/],
      php: [/\$(\w+)\s*=/],
      ruby: [/(\w+)\s*=/],
    };

    for (const pattern of patterns[this.language]) {
      const match = line.match(pattern);
      if (match) {
        // Handle destructuring
        if (match[1].includes(',')) {
          return match[1].split(',')[0].trim();
        }
        return match[1];
      }
    }
    return null;
  }

  // Check if a variable is used in a line
  private variableUsedInLine(varName: string, line: string): boolean {
    // Create a pattern that matches the variable as a whole word
    const pattern = new RegExp(`\\b${varName}\\b`);
    return pattern.test(line);
  }

  // Track propagation of a tainted variable through assignments
  private trackPropagation(varName: string, startLine: number): Array<{ line: number; code: string; newName?: string }> {
    const propagations: Array<{ line: number; code: string; newName?: string }> = [];

    for (let i = startLine + 1; i < this.lines.length; i++) {
      const line = this.lines[i];
      if (this.variableUsedInLine(varName, line)) {
        const newVar = this.extractAssignedVariable(line);
        propagations.push({
          line: i + 1,
          code: line.trim(),
          newName: newVar || undefined,
        });

        // If assigned to a new variable, track that too
        if (newVar && newVar !== varName) {
          const subPropagations = this.trackPropagation(newVar, i);
          propagations.push(...subPropagations);
        }
      }
    }

    return propagations;
  }

  // Identify entry points and track their taint
  identifyEntryPoints(filePath: string): EntryPoint[] {
    const entryPoints: EntryPoint[] = [];
    const patterns = entryPointPatterns[this.language] || [];

    for (let lineNum = 0; lineNum < this.lines.length; lineNum++) {
      const line = this.lines[lineNum];

      for (const pattern of patterns) {
        for (const regex of pattern.patterns) {
          regex.lastIndex = 0;
          if (regex.test(line)) {
            // Extract the variable being assigned
            const varMatch = line.match(pattern.variableExtractor);
            const varName = varMatch ? varMatch[1] : null;

            const entryPoint: EntryPoint = {
              category: pattern.category,
              name: pattern.name,
              file: filePath,
              line: lineNum + 1,
              code: line.trim(),
              risk: pattern.risk,
              variable: varName || undefined,
            };

            entryPoints.push(entryPoint);

            // Track taint if we identified a variable
            if (varName) {
              const propagations = this.trackPropagation(varName, lineNum);
              this.taintedVars.set(varName, {
                name: varName,
                source: pattern.name,
                sourceLine: lineNum + 1,
                sourceCategory: pattern.category,
                risk: pattern.risk,
                propagations,
              });

              // Also track propagated variables as tainted
              for (const prop of propagations) {
                if (prop.newName) {
                  this.taintedVars.set(prop.newName, {
                    name: prop.newName,
                    source: `${pattern.name} via ${varName}`,
                    sourceLine: prop.line,
                    sourceCategory: pattern.category,
                    risk: pattern.risk,
                    propagations: this.trackPropagation(prop.newName, prop.line - 1),
                  });
                }
              }
            }
            break;
          }
        }
      }
    }

    return entryPoints;
  }

  // Identify sinks and check for tainted arguments
  identifySinks(filePath: string): Sink[] {
    const sinks: Sink[] = [];
    const patterns = sinkPatterns[this.language] || [];

    for (let lineNum = 0; lineNum < this.lines.length; lineNum++) {
      const line = this.lines[lineNum];

      for (const pattern of patterns) {
        for (const regex of pattern.patterns) {
          regex.lastIndex = 0;
          if (regex.test(line)) {
            // Extract arguments passed to the sink
            const argMatch = line.match(pattern.argumentExtractor);
            const argString = argMatch ? (argMatch[1] || argMatch[2] || '') : '';

            // Check if any tainted variables are in the arguments
            const taintedArgs: string[] = [];
            for (const [varName] of this.taintedVars) {
              if (this.variableUsedInLine(varName, argString) || this.variableUsedInLine(varName, line)) {
                taintedArgs.push(varName);
              }
            }

            sinks.push({
              category: pattern.category,
              name: pattern.name,
              file: filePath,
              line: lineNum + 1,
              code: line.trim(),
              vulnerabilityType: pattern.vulnerabilityType,
              cwe: pattern.cwe,
              severity: pattern.severity,
              taintedArgs: taintedArgs.length > 0 ? taintedArgs : undefined,
            });
            break;
          }
        }
      }
    }

    return sinks;
  }

  // Build data flow paths from sources to sinks
  buildDataFlowPaths(entryPoints: EntryPoint[], sinks: Sink[]): DataFlowPath[] {
    const paths: DataFlowPath[] = [];

    for (const sink of sinks) {
      if (!sink.taintedArgs || sink.taintedArgs.length === 0) continue;

      for (const taintedVarName of sink.taintedArgs) {
        const taintInfo = this.taintedVars.get(taintedVarName);
        if (!taintInfo) continue;

        // Find the original entry point
        const source = entryPoints.find(ep =>
          ep.variable === taintedVarName ||
          (taintInfo.source.includes(ep.name) && ep.line <= taintInfo.sourceLine)
        );

        if (!source) continue;

        // Build the path
        const pathSteps: Array<{ line: number; code: string; description: string }> = [];

        // Add source
        pathSteps.push({
          line: source.line,
          code: source.code,
          description: `Source: ${source.name}`,
        });

        // Add propagations
        for (const prop of taintInfo.propagations) {
          if (prop.line < sink.line) {
            pathSteps.push({
              line: prop.line,
              code: prop.code,
              description: prop.newName ? `Assigned to ${prop.newName}` : 'Used',
            });
          }
        }

        // Add sink
        pathSteps.push({
          line: sink.line,
          code: sink.code,
          description: `Sink: ${sink.name}`,
        });

        // Calculate confidence based on path evidence
        let confidence: 'high' | 'medium' | 'low' = 'high';
        if (pathSteps.length === 2 && sink.line - source.line > 50) {
          confidence = 'medium';
        }
        if (taintInfo.source.includes('via')) {
          confidence = 'medium'; // Indirect taint
        }

        paths.push({
          source,
          sink,
          path: pathSteps,
          taintedVariable: taintedVarName,
          confidence,
        });
      }
    }

    return paths;
  }

  getTaintedVariables(): Map<string, TaintedVariable> {
    return this.taintedVars;
  }
}

// ============================================================================
// FILE SCANNING
// ============================================================================

const skipDirs = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor', '.next', 'coverage'];
const testPatterns = [/\.test\./i, /\.spec\./i, /_test\./i, /test_/i, /tests?\//i, /__tests__/i];

function detectLanguage(filePath: string): SupportedLanguage | null {
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

function isTestFile(filePath: string): boolean {
  return testPatterns.some(pattern => pattern.test(filePath));
}

interface ScanResult {
  entryPoints: EntryPoint[];
  sinks: Sink[];
  paths: DataFlowPath[];
  taintedVars: number;
}

async function scanFile(
  filePath: string,
  language: SupportedLanguage
): Promise<ScanResult> {
  const content = await fs.readFile(filePath, 'utf-8');
  const tracker = new TaintTracker(content, language);

  const entryPoints = tracker.identifyEntryPoints(filePath);
  const sinks = tracker.identifySinks(filePath);
  const paths = tracker.buildDataFlowPaths(entryPoints, sinks);

  return {
    entryPoints,
    sinks,
    paths,
    taintedVars: tracker.getTaintedVariables().size,
  };
}

async function scanDirectory(
  dirPath: string,
  language: SupportedLanguage | undefined,
  recursive: boolean,
  includeTests: boolean
): Promise<ScanResult> {
  const result: ScanResult = { entryPoints: [], sinks: [], paths: [], taintedVars: 0 };

  const entries = await fs.readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (skipDirs.includes(entry.name)) continue;
      if (recursive) {
        const subResult = await scanDirectory(fullPath, language, recursive, includeTests);
        result.entryPoints.push(...subResult.entryPoints);
        result.sinks.push(...subResult.sinks);
        result.paths.push(...subResult.paths);
        result.taintedVars += subResult.taintedVars;
      }
    } else if (entry.isFile()) {
      const detectedLang = language || detectLanguage(fullPath);
      if (!detectedLang) continue;
      if (!includeTests && isTestFile(fullPath)) continue;

      try {
        const fileResult = await scanFile(fullPath, detectedLang);
        result.entryPoints.push(...fileResult.entryPoints);
        result.sinks.push(...fileResult.sinks);
        result.paths.push(...fileResult.paths);
        result.taintedVars += fileResult.taintedVars;
      } catch {
        // Skip files that can't be read
      }
    }
  }

  return result;
}

// ============================================================================
// RISK ASSESSMENT
// ============================================================================

function calculateRiskScore(
  entryPoints: EntryPoint[],
  sinks: Sink[],
  paths: DataFlowPath[]
): { score: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; reasons: string[] } {
  const reasons: string[] = [];

  const criticalSinks = sinks.filter(s => s.severity === 'critical');
  const sinksTainted = sinks.filter(s => s.taintedArgs && s.taintedArgs.length > 0);
  const highConfPaths = paths.filter(p => p.confidence === 'high');
  const criticalPaths = paths.filter(p => p.sink.severity === 'critical' && p.confidence === 'high');

  if (criticalPaths.length > 0) {
    reasons.push(`${criticalPaths.length} confirmed critical vulnerability path(s) (user input → critical sink)`);
    return { score: 'CRITICAL', reasons };
  }

  if (sinksTainted.length > 0 && criticalSinks.length > 0) {
    const overlap = sinksTainted.filter(s => s.severity === 'critical');
    if (overlap.length > 0) {
      reasons.push(`${overlap.length} critical sink(s) receiving tainted data`);
      return { score: 'CRITICAL', reasons };
    }
  }

  if (highConfPaths.length > 0) {
    reasons.push(`${highConfPaths.length} high-confidence data flow path(s) to dangerous sinks`);
    return { score: 'HIGH', reasons };
  }

  if (paths.length > 0) {
    reasons.push(`${paths.length} potential data flow path(s) identified`);
    return { score: 'MEDIUM', reasons };
  }

  if (criticalSinks.length > 0 && entryPoints.filter(e => e.risk === 'high').length > 0) {
    reasons.push(`${criticalSinks.length} critical sink(s) and ${entryPoints.filter(e => e.risk === 'high').length} high-risk entry point(s) present`);
    return { score: 'MEDIUM', reasons };
  }

  reasons.push('No confirmed taint flows to dangerous sinks');
  return { score: 'LOW', reasons };
}

// ============================================================================
// TOOL REGISTRATION
// ============================================================================

export function registerAnalyzeAttackSurfaceTool(server: McpServer): void {
  server.tool(
    'analyze-attack-surface',
    'Map attack surface with taint tracking: identify entry points, trace data flow to dangerous sinks',
    {
      target: z.string().describe('File or directory to analyze'),
      language: z
        .enum(['javascript', 'typescript', 'python', 'go', 'php', 'ruby'])
        .optional()
        .describe('Target language (auto-detected if not specified)'),
      recursive: z.boolean().default(true).describe('Recursively scan directories'),
      includeTests: z.boolean().default(false).describe('Include test files in analysis'),
    },
    async ({ target, language, recursive, includeTests }) => {
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      logToolInvocation('analyze-attack-surface', { target, language, recursive, includeTests }, validation.warnings);

      try {
        const stats = await fs.stat(sanitizedTarget);
        let result: ScanResult;

        if (stats.isDirectory()) {
          result = await scanDirectory(sanitizedTarget, language, recursive, includeTests);
        } else {
          const detectedLang = language || detectLanguage(sanitizedTarget);
          if (!detectedLang) {
            logOutput('analyze-attack-surface', { success: false, error: 'Could not detect language' });
            return {
              isError: true,
              content: [{ type: 'text' as const, text: 'Could not detect language. Please specify the language parameter.' }],
            };
          }
          result = await scanFile(sanitizedTarget, detectedLang);
        }

        const { entryPoints, sinks, paths, taintedVars } = result;
        const riskAssessment = calculateRiskScore(entryPoints, sinks, paths);

        // Group entry points by category
        const entryByCategory = entryPoints.reduce((acc, e) => {
          if (!acc[e.category]) acc[e.category] = [];
          acc[e.category].push(e);
          return acc;
        }, {} as Record<string, EntryPoint[]>);

        // Group sinks by severity then category
        const criticalSinks = sinks.filter(s => s.severity === 'critical');
        const highSinks = sinks.filter(s => s.severity === 'high');
        const otherSinks = sinks.filter(s => s.severity !== 'critical' && s.severity !== 'high');

        // Format entry points
        const formatEntry = (e: EntryPoint) =>
          `- \`${path.basename(e.file)}:${e.line}\` ${e.variable ? `**${e.variable}** ←` : ''} \`${e.code.slice(0, 70)}${e.code.length > 70 ? '...' : ''}\``;

        const entrySection = Object.entries(entryByCategory)
          .map(([category, entries]) => {
            const items = entries.slice(0, 8).map(formatEntry).join('\n');
            return `### ${category} (${entries.length})\n${items}${entries.length > 8 ? `\n- *...and ${entries.length - 8} more*` : ''}`;
          })
          .join('\n\n');

        // Format sinks
        const formatSink = (s: Sink) => {
          const taint = s.taintedArgs ? ` ⚠️ **TAINTED: ${s.taintedArgs.join(', ')}**` : '';
          return `- \`${path.basename(s.file)}:${s.line}\` [${s.cwe}] ${s.vulnerabilityType}${taint}\n  \`${s.code.slice(0, 70)}${s.code.length > 70 ? '...' : ''}\``;
        };

        let sinkSection = '';
        if (criticalSinks.length > 0) {
          sinkSection += `### 🔴 Critical (${criticalSinks.length})\n${criticalSinks.slice(0, 10).map(formatSink).join('\n')}\n\n`;
        }
        if (highSinks.length > 0) {
          sinkSection += `### 🟠 High (${highSinks.length})\n${highSinks.slice(0, 10).map(formatSink).join('\n')}\n\n`;
        }
        if (otherSinks.length > 0) {
          sinkSection += `### 🟡 Medium/Low (${otherSinks.length})\n${otherSinks.slice(0, 5).map(formatSink).join('\n')}`;
        }

        // Format data flow paths
        const pathSection = paths
          .sort((a, b) => {
            const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            const confOrder = { high: 0, medium: 1, low: 2 };
            return (sevOrder[a.sink.severity] - sevOrder[b.sink.severity]) ||
                   (confOrder[a.confidence] - confOrder[b.confidence]);
          })
          .slice(0, 15)
          .map((p, idx) => {
            const pathSteps = p.path.map(step => `    ${step.line}: ${step.description}`).join('\n');
            return `#### ${idx + 1}. ${p.source.category} → ${p.sink.vulnerabilityType} [${p.confidence.toUpperCase()}]
**Tainted Variable:** \`${p.taintedVariable}\`
**Source:** \`${path.basename(p.source.file)}:${p.source.line}\`
**Sink:** \`${path.basename(p.sink.file)}:${p.sink.line}\` (${p.sink.cwe})

**Flow:**
${pathSteps}`;
          })
          .join('\n\n---\n\n');

        const report = `# Attack Surface Analysis

## Summary
| Metric | Value |
|--------|-------|
| **Target** | ${target} |
| **Entry Points** | ${entryPoints.length} |
| **Dangerous Sinks** | ${sinks.length} |
| **Tainted Variables Tracked** | ${taintedVars} |
| **Data Flow Paths** | ${paths.length} |
| **Risk Score** | **${riskAssessment.score}** |

### Risk Assessment
${riskAssessment.reasons.map(r => `- ${r}`).join('\n')}

---

## Entry Points (Sources of Untrusted Data)

${entrySection || '*No entry points detected*'}

---

## Dangerous Sinks

${sinkSection || '*No dangerous sinks detected*'}

---

## Confirmed Data Flow Paths (Taint Analysis)

${pathSection || '*No taint flows detected from sources to sinks*'}

${paths.length > 15 ? `\n*Showing top 15 of ${paths.length} paths, sorted by severity and confidence*` : ''}

---

## Methodology

This analysis uses **taint tracking** to trace data flow:
1. **Entry Points**: Identifies where untrusted data enters (HTTP params, env vars, file input)
2. **Variable Tracking**: Follows assignments and propagations of tainted variables
3. **Sink Detection**: Finds dangerous operations (SQL, exec, eval, file ops)
4. **Flow Analysis**: Confirms which sinks receive tainted data

**Confidence Levels:**
- **HIGH**: Direct flow from source to sink with variable tracking
- **MEDIUM**: Indirect flow through reassignments or distant code
- **LOW**: Heuristic match without confirmed variable tracking
`;

        logOutput('analyze-attack-surface', {
          success: true,
          summary: `Found ${paths.length} data flows, ${sinks.filter(s => s.taintedArgs).length} tainted sinks. Risk: ${riskAssessment.score}`,
          metrics: {
            entryPoints: entryPoints.length,
            sinks: sinks.length,
            taintedSinks: sinks.filter(s => s.taintedArgs && s.taintedArgs.length > 0).length,
            paths: paths.length,
            highConfidencePaths: paths.filter(p => p.confidence === 'high').length,
            taintedVars,
            riskScore: riskAssessment.score,
          },
        });

        return { content: [{ type: 'text' as const, text: report }] };
      } catch (error) {
        logOutput('analyze-attack-surface', {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return {
          isError: true,
          content: [{ type: 'text' as const, text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        };
      }
    }
  );
}
