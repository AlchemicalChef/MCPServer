import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

interface VulnerabilityPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cwe: string;
  pattern: RegExp;
  description: string;
  languages: string[];
}

const vulnerabilityPatterns: VulnerabilityPattern[] = [
  // SQL Injection
  {
    id: 'SQLI-001',
    name: 'SQL Injection (String Concatenation)',
    severity: 'critical',
    cwe: 'CWE-89',
    pattern: /(?:execute|query|raw|exec)\s*\(\s*[`"']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\+|(?:SELECT|INSERT|UPDATE|DELETE).*?\$\{/gi,
    description: 'Potential SQL injection via string concatenation or template literals',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  },
  {
    id: 'SQLI-002',
    name: 'SQL Injection (f-string/format)',
    severity: 'critical',
    cwe: 'CWE-89',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*f['"]/gi,
    description: 'Potential SQL injection via Python f-string',
    languages: ['python'],
  },
  // Command Injection
  {
    id: 'CMDI-001',
    name: 'Command Injection',
    severity: 'critical',
    cwe: 'CWE-78',
    pattern: /(?:exec|spawn|execSync|spawnSync|execFile|child_process|system|popen|subprocess\.call|subprocess\.run|os\.system|os\.popen)\s*\([^)]*\+|(?:exec|spawn)\s*\([^)]*\$\{/gi,
    description: 'Potential command injection via user input in shell commands',
    languages: ['javascript', 'typescript', 'python', 'go'],
  },
  {
    id: 'CMDI-002',
    name: 'Shell Command with Variable',
    severity: 'high',
    cwe: 'CWE-78',
    pattern: /(?:shell=True|shell:\s*true)/gi,
    description: 'Shell execution enabled which may allow command injection',
    languages: ['python', 'javascript', 'typescript'],
  },
  // XSS
  {
    id: 'XSS-001',
    name: 'Cross-Site Scripting (innerHTML)',
    severity: 'high',
    cwe: 'CWE-79',
    pattern: /\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(/gi,
    description: 'Direct HTML manipulation may lead to XSS',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'XSS-002',
    name: 'Cross-Site Scripting (dangerouslySetInnerHTML)',
    severity: 'high',
    cwe: 'CWE-79',
    pattern: /dangerouslySetInnerHTML/gi,
    description: 'React dangerouslySetInnerHTML usage may lead to XSS',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'XSS-003',
    name: 'Document Write',
    severity: 'medium',
    cwe: 'CWE-79',
    pattern: /document\.write\s*\(|document\.writeln\s*\(/gi,
    description: 'document.write usage may lead to XSS',
    languages: ['javascript', 'typescript'],
  },
  // Path Traversal
  {
    id: 'PATH-001',
    name: 'Path Traversal',
    severity: 'high',
    cwe: 'CWE-22',
    pattern: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|open)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    description: 'File operation with user input may allow path traversal',
    languages: ['javascript', 'typescript'],
  },
  // Insecure Deserialization
  {
    id: 'DESER-001',
    name: 'Insecure Deserialization (eval)',
    severity: 'critical',
    cwe: 'CWE-502',
    pattern: /\beval\s*\(/gi,
    description: 'Use of eval() can lead to code injection',
    languages: ['javascript', 'typescript', 'python'],
  },
  {
    id: 'DESER-002',
    name: 'Insecure Deserialization (pickle)',
    severity: 'critical',
    cwe: 'CWE-502',
    pattern: /pickle\.loads?\s*\(|cPickle\.loads?\s*\(/gi,
    description: 'Pickle deserialization of untrusted data can lead to RCE',
    languages: ['python'],
  },
  {
    id: 'DESER-003',
    name: 'Insecure Deserialization (yaml)',
    severity: 'high',
    cwe: 'CWE-502',
    pattern: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/gi,
    description: 'Unsafe YAML loading can lead to code execution',
    languages: ['python'],
  },
  // Hardcoded Credentials (also covered by secret scanner but included here)
  {
    id: 'CRED-001',
    name: 'Hardcoded Password',
    severity: 'high',
    cwe: 'CWE-798',
    pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['""][^'""]{4,}['""]|(?:password|passwd|pwd)\s*=\s*['""][^'""]{4,}['""]/gi,
    description: 'Potential hardcoded password detected',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  },
  // Weak Cryptography
  {
    id: 'CRYPTO-001',
    name: 'Weak Hash Algorithm (MD5)',
    severity: 'medium',
    cwe: 'CWE-328',
    pattern: /(?:createHash|hashlib\.md5|MD5|Md5)\s*\(\s*['""]?md5['""]?\s*\)|\.md5\s*\(/gi,
    description: 'MD5 is cryptographically weak and should not be used for security',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  },
  {
    id: 'CRYPTO-002',
    name: 'Weak Hash Algorithm (SHA1)',
    severity: 'medium',
    cwe: 'CWE-328',
    pattern: /(?:createHash|hashlib\.sha1)\s*\(\s*['""]?sha1['""]?\s*\)/gi,
    description: 'SHA1 is cryptographically weak for security purposes',
    languages: ['javascript', 'typescript', 'python', 'java'],
  },
  // Insecure Randomness
  {
    id: 'RAND-001',
    name: 'Insecure Randomness',
    severity: 'medium',
    cwe: 'CWE-330',
    pattern: /Math\.random\s*\(\)|random\.random\s*\(\)|rand\s*\(\)/gi,
    description: 'Non-cryptographic random number generator used (use crypto.randomBytes or secrets module)',
    languages: ['javascript', 'typescript', 'python'],
  },
  // SSRF
  {
    id: 'SSRF-001',
    name: 'Server-Side Request Forgery',
    severity: 'high',
    cwe: 'CWE-918',
    pattern: /(?:fetch|axios|request|http\.get|https\.get|urllib|requests\.get)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/gi,
    description: 'HTTP request with user-controlled URL may lead to SSRF',
    languages: ['javascript', 'typescript', 'python'],
  },
  // XXE
  {
    id: 'XXE-001',
    name: 'XML External Entity',
    severity: 'high',
    cwe: 'CWE-611',
    pattern: /(?:XMLParser|etree\.parse|xml\.parse|parseString|DOMParser)\s*\(/gi,
    description: 'XML parsing may be vulnerable to XXE attacks',
    languages: ['javascript', 'typescript', 'python', 'java'],
  },
  // Open Redirect
  {
    id: 'REDIR-001',
    name: 'Open Redirect',
    severity: 'medium',
    cwe: 'CWE-601',
    pattern: /(?:redirect|location\.href|window\.location)\s*[=:]\s*(?:req\.|request\.|params\.|query\.)/gi,
    description: 'Redirect with user-controlled URL may lead to open redirect',
    languages: ['javascript', 'typescript', 'python'],
  },
  // Prototype Pollution
  {
    id: 'PROTO-001',
    name: 'Prototype Pollution',
    severity: 'high',
    cwe: 'CWE-1321',
    pattern: /\[(?:req\.|request\.|params\.|query\.|body\.)[^\]]*\]\s*=/gi,
    description: 'Dynamic property assignment may lead to prototype pollution',
    languages: ['javascript', 'typescript'],
  },
  // NoSQL Injection
  {
    id: 'NOSQL-001',
    name: 'NoSQL Injection',
    severity: 'high',
    cwe: 'CWE-943',
    pattern: /(?:find|findOne|findMany|updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    description: 'MongoDB query with user input may be vulnerable to NoSQL injection',
    languages: ['javascript', 'typescript'],
  },
  // Unsafe Regex
  {
    id: 'REGEX-001',
    name: 'ReDoS (Regular Expression Denial of Service)',
    severity: 'medium',
    cwe: 'CWE-1333',
    pattern: /new\s+RegExp\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    description: 'Dynamic regex from user input may cause ReDoS',
    languages: ['javascript', 'typescript'],
  },
  // JWT Issues
  {
    id: 'JWT-001',
    name: 'JWT None Algorithm',
    severity: 'critical',
    cwe: 'CWE-347',
    pattern: /algorithms?\s*[=:]\s*\[?\s*['""]none['""]/gi,
    description: 'JWT with "none" algorithm allows signature bypass',
    languages: ['javascript', 'typescript', 'python'],
  },
  // CORS
  {
    id: 'CORS-001',
    name: 'CORS Wildcard',
    severity: 'medium',
    cwe: 'CWE-942',
    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['""]?\*['""]?/gi,
    description: 'CORS wildcard allows requests from any origin',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  },
];

interface Finding {
  id: string;
  name: string;
  severity: string;
  cwe: string;
  description: string;
  file: string;
  line: number;
  column: number;
  match: string;
  context: string;
}

async function scanFileContent(
  content: string,
  filePath: string,
  language: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const pattern of vulnerabilityPatterns) {
    if (!pattern.languages.includes(language) && !pattern.languages.includes('all')) {
      continue;
    }

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      let match: RegExpExecArray | null;

      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      while ((match = pattern.pattern.exec(line)) !== null) {
        // Get context (2 lines before and after)
        const contextStart = Math.max(0, lineNum - 2);
        const contextEnd = Math.min(lines.length - 1, lineNum + 2);
        const context = lines.slice(contextStart, contextEnd + 1).join('\n');

        findings.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          cwe: pattern.cwe,
          description: pattern.description,
          file: filePath,
          line: lineNum + 1,
          column: match.index + 1,
          match: match[0],
          context,
        });
      }
    }
  }

  return findings;
}

function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const languageMap: Record<string, string> = {
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.go': 'go',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
  };
  return languageMap[ext] || 'unknown';
}

export function registerScanCodeTool(server: McpServer): void {
  server.tool(
    'scan-code',
    'Scan source code for security vulnerabilities (OWASP Top 10, CWE patterns)',
    {
      target: z.string().describe('File path or directory to scan'),
      recursive: z.boolean().default(true).describe('Recursively scan directories'),
      severity: z.enum(['all', 'critical', 'high', 'medium', 'low']).default('all')
        .describe('Minimum severity level to report'),
    },
    async ({ target, recursive, severity }) => {
      const findings: Finding[] = [];
      const severityOrder = ['critical', 'high', 'medium', 'low'];
      const minSeverityIndex = severity === 'all' ? 3 : severityOrder.indexOf(severity);

      async function scanPath(targetPath: string): Promise<void> {
        try {
          const stats = await fs.stat(targetPath);

          if (stats.isFile()) {
            const language = detectLanguage(targetPath);
            if (language !== 'unknown') {
              const content = await fs.readFile(targetPath, 'utf-8');
              const fileFindings = await scanFileContent(content, targetPath, language);
              findings.push(...fileFindings);
            }
          } else if (stats.isDirectory() && recursive) {
            const entries = await fs.readdir(targetPath, { withFileTypes: true });
            for (const entry of entries) {
              // Skip common non-source directories
              if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'].includes(entry.name)) {
                continue;
              }
              await scanPath(path.join(targetPath, entry.name));
            }
          }
        } catch (error) {
          // Skip files we can't read
        }
      }

      await scanPath(target);

      // Filter by severity
      const filteredFindings = findings.filter(f => {
        const idx = severityOrder.indexOf(f.severity);
        return idx <= minSeverityIndex;
      });

      // Sort by severity
      filteredFindings.sort((a, b) => {
        return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
      });

      if (filteredFindings.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `No vulnerabilities found in ${target}`,
          }],
        };
      }

      const report = filteredFindings.map(f =>
        `[${f.severity.toUpperCase()}] ${f.name} (${f.cwe})
  File: ${f.file}:${f.line}:${f.column}
  Match: ${f.match}
  Description: ${f.description}
  Context:
${f.context.split('\n').map(l => '    ' + l).join('\n')}`
      ).join('\n\n---\n\n');

      const summary = {
        total: filteredFindings.length,
        critical: filteredFindings.filter(f => f.severity === 'critical').length,
        high: filteredFindings.filter(f => f.severity === 'high').length,
        medium: filteredFindings.filter(f => f.severity === 'medium').length,
        low: filteredFindings.filter(f => f.severity === 'low').length,
      };

      return {
        content: [{
          type: 'text' as const,
          text: `# Security Scan Results

## Summary
- Total findings: ${summary.total}
- Critical: ${summary.critical}
- High: ${summary.high}
- Medium: ${summary.medium}
- Low: ${summary.low}

## Findings

${report}`,
        }],
      };
    }
  );
}
