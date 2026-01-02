import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

interface TaintSource {
  name: string;
  patterns: RegExp[];
  description: string;
  risk: 'high' | 'medium' | 'low';
}

interface TaintSink {
  name: string;
  patterns: RegExp[];
  vulnerabilityType: string;
  cwe: string;
  description: string;
}

interface DataFlowFinding {
  source: {
    type: string;
    line: number;
    code: string;
    variable?: string;
  };
  sink: {
    type: string;
    line: number;
    code: string;
    vulnerabilityType: string;
    cwe: string;
  };
  path: Array<{
    line: number;
    code: string;
    description: string;
  }>;
  file: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'high' | 'medium' | 'low';
}

// Taint sources - where untrusted data enters
const taintSources: TaintSource[] = [
  // JavaScript/TypeScript
  {
    name: 'HTTP Request Parameters',
    patterns: [
      /req\.(?:params|query|body|headers)\[?['"]?(\w+)['"]?\]?/g,
      /request\.(?:params|query|body|headers|cookies)/g,
      /ctx\.(?:params|query|request\.body)/g,
    ],
    description: 'User-controlled HTTP request data',
    risk: 'high',
  },
  {
    name: 'URL Parameters',
    patterns: [
      /new\s+URLSearchParams/g,
      /location\.(?:search|hash|href)/g,
      /window\.location/g,
      /document\.URL/g,
    ],
    description: 'URL-derived user input',
    risk: 'high',
  },
  {
    name: 'DOM Input',
    patterns: [
      /document\.getElementById\s*\([^)]+\)\.(?:value|innerHTML|textContent)/g,
      /document\.querySelector\s*\([^)]+\)\.(?:value|innerHTML)/g,
      /\$\([^)]+\)\.(?:val|html|text)\(\)/g,
      /\.value\b/g,
    ],
    description: 'User input from DOM elements',
    risk: 'high',
  },
  {
    name: 'File Input',
    patterns: [
      /fs\.readFile(?:Sync)?\s*\(/g,
      /readFileSync\s*\(/g,
      /createReadStream\s*\(/g,
      /open\s*\([^)]+,\s*['"]r/g,
    ],
    description: 'File content that may be user-controlled',
    risk: 'medium',
  },
  {
    name: 'Environment Variables',
    patterns: [
      /process\.env\[?['"]?(\w+)['"]?\]?/g,
      /os\.environ(?:\.get)?\s*\(/g,
      /getenv\s*\(/g,
    ],
    description: 'Environment variables that may be controlled',
    risk: 'medium',
  },
  {
    name: 'Database Results',
    patterns: [
      /\.query\s*\([^)]+\)\s*\.then/g,
      /await\s+\w+\.(?:find|select|query)\s*\(/g,
      /cursor\.fetchone|fetchall/g,
    ],
    description: 'Database query results',
    risk: 'medium',
  },
  // Python
  {
    name: 'Flask/Django Request',
    patterns: [
      /request\.(?:args|form|json|data|files|cookies|headers)/g,
      /request\.GET|request\.POST/g,
    ],
    description: 'Web framework request data',
    risk: 'high',
  },
  {
    name: 'User Input (Python)',
    patterns: [
      /input\s*\(/g,
      /raw_input\s*\(/g,
      /sys\.argv/g,
    ],
    description: 'Direct user input in Python',
    risk: 'high',
  },
];

// Taint sinks - where dangerous operations occur
const taintSinks: TaintSink[] = [
  // SQL Injection
  {
    name: 'SQL Query Execution',
    patterns: [
      /\.query\s*\(\s*[`'"].*\$\{/g,
      /\.query\s*\(\s*[`'"]\s*[^`'"]*\s*\+/g,
      /execute\s*\(\s*f?['"]/g,
      /cursor\.execute\s*\(\s*['"]/g,
      /\.raw\s*\(\s*[`'"]/g,
      /sequelize\.query\s*\(/g,
    ],
    vulnerabilityType: 'SQL Injection',
    cwe: 'CWE-89',
    description: 'SQL query with potential string concatenation',
  },
  // Command Injection
  {
    name: 'Command Execution',
    patterns: [
      /exec\s*\(\s*[`'"]/g,
      /execSync\s*\(\s*[`'"]/g,
      /spawn\s*\(\s*[`'"]/g,
      /child_process/g,
      /os\.system\s*\(/g,
      /subprocess\.(?:call|run|Popen)\s*\(/g,
      /eval\s*\(/g,
    ],
    vulnerabilityType: 'Command Injection',
    cwe: 'CWE-78',
    description: 'OS command execution with potential user input',
  },
  // XSS
  {
    name: 'DOM Manipulation',
    patterns: [
      /\.innerHTML\s*=/g,
      /\.outerHTML\s*=/g,
      /document\.write\s*\(/g,
      /document\.writeln\s*\(/g,
      /\$\([^)]+\)\.html\s*\(/g,
      /dangerouslySetInnerHTML/g,
      /v-html\s*=/g,
    ],
    vulnerabilityType: 'Cross-Site Scripting (XSS)',
    cwe: 'CWE-79',
    description: 'Direct HTML injection into DOM',
  },
  // Path Traversal
  {
    name: 'File Path Operations',
    patterns: [
      /fs\.(?:readFile|writeFile|unlink|rmdir|mkdir)(?:Sync)?\s*\(/g,
      /path\.(?:join|resolve)\s*\([^)]*\+/g,
      /open\s*\(\s*[`'"]/g,
      /require\s*\(\s*[^'"]/g,
    ],
    vulnerabilityType: 'Path Traversal',
    cwe: 'CWE-22',
    description: 'File system operation with potential path manipulation',
  },
  // Deserialization
  {
    name: 'Unsafe Deserialization',
    patterns: [
      /JSON\.parse\s*\(/g,
      /yaml\.(?:load|unsafe_load)\s*\(/g,
      /pickle\.loads?\s*\(/g,
      /unserialize\s*\(/g,
      /ObjectInputStream/g,
    ],
    vulnerabilityType: 'Insecure Deserialization',
    cwe: 'CWE-502',
    description: 'Deserialization of untrusted data',
  },
  // SSRF
  {
    name: 'HTTP Requests',
    patterns: [
      /fetch\s*\(\s*[`'"]/g,
      /axios\.(?:get|post|put|delete)\s*\(/g,
      /http\.request\s*\(/g,
      /requests\.(?:get|post|put|delete)\s*\(/g,
      /urllib\.request/g,
    ],
    vulnerabilityType: 'Server-Side Request Forgery (SSRF)',
    cwe: 'CWE-918',
    description: 'HTTP request with potentially user-controlled URL',
  },
  // Template Injection
  {
    name: 'Template Rendering',
    patterns: [
      /render_template_string\s*\(/g,
      /Template\s*\(\s*[`'"]/g,
      /\.render\s*\(\s*\{/g,
      /eval\s*\(\s*[`'"]/g,
      /new\s+Function\s*\(/g,
    ],
    vulnerabilityType: 'Template Injection',
    cwe: 'CWE-94',
    description: 'Template with potential code injection',
  },
  // LDAP Injection
  {
    name: 'LDAP Query',
    patterns: [
      /ldap\.search\s*\(/g,
      /ldap_search\s*\(/g,
      /LdapConnection/g,
    ],
    vulnerabilityType: 'LDAP Injection',
    cwe: 'CWE-90',
    description: 'LDAP query with potential injection',
  },
  // XML Injection
  {
    name: 'XML Processing',
    patterns: [
      /parseString\s*\(/g,
      /XMLParser\s*\(/g,
      /etree\.(?:parse|fromstring)\s*\(/g,
      /DOMParser/g,
    ],
    vulnerabilityType: 'XML External Entity (XXE)',
    cwe: 'CWE-611',
    description: 'XML parsing with potential XXE',
  },
  // Log Injection
  {
    name: 'Logging',
    patterns: [
      /console\.log\s*\(\s*[`'"]/g,
      /logger\.(?:info|debug|warn|error)\s*\(/g,
      /logging\.(?:info|debug|warning|error)\s*\(/g,
    ],
    vulnerabilityType: 'Log Injection',
    cwe: 'CWE-117',
    description: 'Logging with potential log injection',
  },
];

interface VariableTrace {
  name: string;
  sourceLine: number;
  sourceType: string;
  assignments: Array<{ line: number; code: string }>;
}

function extractVariableName(code: string): string | undefined {
  // Extract variable from assignment: const foo = ..., let bar = ..., var baz = ...
  const match = code.match(/(?:const|let|var)\s+(\w+)\s*=/);
  if (match) return match[1];

  // Extract from destructuring: const { foo } = ...
  const destructMatch = code.match(/(?:const|let|var)\s+\{\s*([^}]+)\s*\}\s*=/);
  if (destructMatch) {
    return destructMatch[1].split(',')[0].trim();
  }

  return undefined;
}

function traceVariable(lines: string[], varName: string, startLine: number): number[] {
  const usageLines: number[] = [];
  const varPattern = new RegExp(`\\b${varName}\\b`);

  for (let i = startLine; i < lines.length; i++) {
    if (varPattern.test(lines[i])) {
      usageLines.push(i);
    }
  }

  return usageLines;
}

async function analyzeFile(
  content: string,
  filePath: string,
  trackVariables: boolean
): Promise<DataFlowFinding[]> {
  const findings: DataFlowFinding[] = [];
  const lines = content.split('\n');
  const trackedVariables: Map<string, VariableTrace> = new Map();

  // First pass: identify taint sources and track variables
  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];

    for (const source of taintSources) {
      for (const pattern of source.patterns) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          const varName = extractVariableName(line);

          if (varName && trackVariables) {
            trackedVariables.set(varName, {
              name: varName,
              sourceLine: lineNum,
              sourceType: source.name,
              assignments: [{ line: lineNum, code: line.trim() }],
            });
          }

          // Look for immediate sink usage on same line or nearby
          for (const sink of taintSinks) {
            for (const sinkPattern of sink.patterns) {
              sinkPattern.lastIndex = 0;
              if (sinkPattern.test(line)) {
                findings.push({
                  source: {
                    type: source.name,
                    line: lineNum + 1,
                    code: line.trim(),
                    variable: varName,
                  },
                  sink: {
                    type: sink.name,
                    line: lineNum + 1,
                    code: line.trim(),
                    vulnerabilityType: sink.vulnerabilityType,
                    cwe: sink.cwe,
                  },
                  path: [],
                  file: filePath,
                  severity: 'critical',
                  confidence: 'high',
                });
              }
            }
          }
        }
      }
    }
  }

  // Second pass: trace variable usage to sinks
  if (trackVariables) {
    for (const [varName, trace] of trackedVariables) {
      const usageLines = traceVariable(lines, varName, trace.sourceLine);

      for (const usageLine of usageLines) {
        const line = lines[usageLine];

        for (const sink of taintSinks) {
          for (const sinkPattern of sink.patterns) {
            sinkPattern.lastIndex = 0;
            if (sinkPattern.test(line) && usageLine !== trace.sourceLine) {
              // Build path from source to sink
              const flowPath: Array<{ line: number; code: string; description: string }> = [];

              // Find intermediate assignments
              for (let i = trace.sourceLine + 1; i < usageLine; i++) {
                const intermediateLine = lines[i];
                if (new RegExp(`\\b${varName}\\b`).test(intermediateLine)) {
                  flowPath.push({
                    line: i + 1,
                    code: intermediateLine.trim(),
                    description: `Variable "${varName}" used`,
                  });
                }
              }

              findings.push({
                source: {
                  type: trace.sourceType,
                  line: trace.sourceLine + 1,
                  code: lines[trace.sourceLine].trim(),
                  variable: varName,
                },
                sink: {
                  type: sink.name,
                  line: usageLine + 1,
                  code: line.trim(),
                  vulnerabilityType: sink.vulnerabilityType,
                  cwe: sink.cwe,
                },
                path: flowPath,
                file: filePath,
                severity: flowPath.length > 3 ? 'high' : 'critical',
                confidence: flowPath.length > 5 ? 'medium' : 'high',
              });
            }
          }
        }
      }
    }
  }

  // Third pass: look for direct sink usage without obvious source (potential issues)
  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];

    for (const sink of taintSinks) {
      for (const pattern of sink.patterns) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          // Check if this sink already has a finding
          const alreadyFound = findings.some(
            f => f.sink.line === lineNum + 1 && f.file === filePath
          );

          if (!alreadyFound) {
            // Check for string concatenation or template literals
            if (/\+\s*\w+|\$\{|\%s|\%d|f['"]/.test(line)) {
              findings.push({
                source: {
                  type: 'Potential User Input',
                  line: lineNum + 1,
                  code: line.trim(),
                },
                sink: {
                  type: sink.name,
                  line: lineNum + 1,
                  code: line.trim(),
                  vulnerabilityType: sink.vulnerabilityType,
                  cwe: sink.cwe,
                },
                path: [],
                file: filePath,
                severity: 'medium',
                confidence: 'low',
              });
            }
          }
        }
      }
    }
  }

  return findings;
}

export function registerAnalyzeDataflowTool(server: McpServer): void {
  server.tool(
    'analyze-dataflow',
    'Analyze data flow to detect tainted data from user input reaching dangerous sinks (SQL queries, command execution, etc.)',
    {
      target: z.string().describe('File or directory to analyze'),
      recursive: z.boolean().default(true).describe('Recursively analyze directories'),
      trackVariables: z.boolean().default(true).describe('Track variable assignments to trace data flow'),
      minConfidence: z.enum(['high', 'medium', 'low']).default('low').describe('Minimum confidence level for findings'),
    },
    async ({ target, recursive, trackVariables, minConfidence }) => {
      const findings: DataFlowFinding[] = [];
      const scannedFiles: string[] = [];

      const analyzeExtensions = new Set([
        '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
        '.py', '.go', '.java', '.php', '.rb',
      ]);

      async function processPath(targetPath: string): Promise<void> {
        try {
          const stats = await fs.stat(targetPath);

          if (stats.isFile()) {
            const ext = path.extname(targetPath).toLowerCase();
            if (analyzeExtensions.has(ext)) {
              const content = await fs.readFile(targetPath, 'utf-8');
              const fileFindings = await analyzeFile(content, targetPath, trackVariables);
              findings.push(...fileFindings);
              scannedFiles.push(targetPath);
            }
          } else if (stats.isDirectory() && recursive) {
            const entries = await fs.readdir(targetPath, { withFileTypes: true });
            for (const entry of entries) {
              if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'].includes(entry.name)) {
                continue;
              }
              await processPath(path.join(targetPath, entry.name));
            }
          }
        } catch (error) {
          // Skip files we can't read
        }
      }

      await processPath(target);

      // Filter by confidence
      const confidenceLevels = ['high', 'medium', 'low'];
      const minIndex = confidenceLevels.indexOf(minConfidence);
      const filteredFindings = findings.filter(
        f => confidenceLevels.indexOf(f.confidence) <= minIndex
      );

      if (filteredFindings.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `# Data Flow Analysis Results

**Target:** ${target}
**Files Analyzed:** ${scannedFiles.length}
**Findings:** 0

No data flow vulnerabilities detected at the "${minConfidence}" confidence level or above.

**Note:** This analysis uses static pattern matching. For comprehensive taint analysis, consider using:
- CodeQL
- Semgrep with dataflow rules
- Snyk Code`,
          }],
        };
      }

      // Sort by severity
      const severityOrder = ['critical', 'high', 'medium', 'low'];
      filteredFindings.sort((a, b) =>
        severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
      );

      // Group by vulnerability type
      const byType = filteredFindings.reduce((acc, f) => {
        const type = f.sink.vulnerabilityType;
        if (!acc[type]) acc[type] = [];
        acc[type].push(f);
        return acc;
      }, {} as Record<string, DataFlowFinding[]>);

      const summaryByType = Object.entries(byType)
        .map(([type, items]) => `- **${type}**: ${items.length}`)
        .join('\n');

      const detailedReport = filteredFindings.map((f, idx) => {
        const pathStr = f.path.length > 0
          ? `\n**Data Flow Path:**\n${f.path.map(p => `  - Line ${p.line}: \`${p.code.substring(0, 60)}${p.code.length > 60 ? '...' : ''}\``).join('\n')}`
          : '';

        return `### Finding ${idx + 1}: ${f.sink.vulnerabilityType}

**Severity:** ${f.severity.toUpperCase()} | **Confidence:** ${f.confidence}
**File:** ${f.file}
**CWE:** ${f.sink.cwe}

**Source (Line ${f.source.line}):**
\`\`\`
${f.source.code}
\`\`\`
${f.source.variable ? `**Tainted Variable:** \`${f.source.variable}\`` : ''}
${pathStr}

**Sink (Line ${f.sink.line}):**
\`\`\`
${f.sink.code}
\`\`\``;
      }).join('\n\n---\n\n');

      return {
        content: [{
          type: 'text' as const,
          text: `# Data Flow Analysis Results

## Summary
- **Target:** ${target}
- **Files Analyzed:** ${scannedFiles.length}
- **Total Findings:** ${filteredFindings.length}
- **Critical:** ${filteredFindings.filter(f => f.severity === 'critical').length}
- **High:** ${filteredFindings.filter(f => f.severity === 'high').length}
- **Medium:** ${filteredFindings.filter(f => f.severity === 'medium').length}

## Findings by Vulnerability Type
${summaryByType}

---

## Detailed Findings

${detailedReport}

---

## Remediation Guidance

1. **SQL Injection**: Use parameterized queries or prepared statements
2. **Command Injection**: Avoid shell execution; use safe APIs with argument arrays
3. **XSS**: Sanitize output; use framework auto-escaping; avoid innerHTML
4. **Path Traversal**: Validate and canonicalize paths; use allowlists
5. **SSRF**: Validate URLs against allowlist; block internal IPs
6. **Deserialization**: Avoid deserializing untrusted data; use safe alternatives`,
        }],
      };
    }
  );
}
