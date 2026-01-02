import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  description: string;
}

const secretPatterns: SecretPattern[] = [
  // AWS
  {
    id: 'AWS-KEY',
    name: 'AWS Access Key ID',
    pattern: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    description: 'AWS Access Key ID',
  },
  {
    id: 'AWS-SECRET',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
    description: 'AWS Secret Access Key',
  },
  // GitHub
  {
    id: 'GITHUB-PAT',
    name: 'GitHub Personal Access Token',
    pattern: /\bghp_[A-Za-z0-9]{36}\b/g,
    description: 'GitHub Personal Access Token (classic)',
  },
  {
    id: 'GITHUB-OAUTH',
    name: 'GitHub OAuth Access Token',
    pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
    description: 'GitHub OAuth Access Token',
  },
  {
    id: 'GITHUB-APP',
    name: 'GitHub App Token',
    pattern: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/g,
    description: 'GitHub App Token',
  },
  {
    id: 'GITHUB-REFRESH',
    name: 'GitHub Refresh Token',
    pattern: /\bghr_[A-Za-z0-9]{36}\b/g,
    description: 'GitHub Refresh Token',
  },
  // GitLab
  {
    id: 'GITLAB-PAT',
    name: 'GitLab Personal Access Token',
    pattern: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g,
    description: 'GitLab Personal Access Token',
  },
  // Slack
  {
    id: 'SLACK-TOKEN',
    name: 'Slack Token',
    pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b/g,
    description: 'Slack API Token',
  },
  {
    id: 'SLACK-WEBHOOK',
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g,
    description: 'Slack Webhook URL',
  },
  // Google
  {
    id: 'GOOGLE-API',
    name: 'Google API Key',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    description: 'Google API Key',
  },
  {
    id: 'GOOGLE-OAUTH',
    name: 'Google OAuth Client ID',
    pattern: /\b[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b/g,
    description: 'Google OAuth Client ID',
  },
  // Stripe
  {
    id: 'STRIPE-KEY',
    name: 'Stripe API Key',
    pattern: /\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}\b/g,
    description: 'Stripe API Key (secret or publishable)',
  },
  // Twilio
  {
    id: 'TWILIO-KEY',
    name: 'Twilio API Key',
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    description: 'Twilio API Key',
  },
  // SendGrid
  {
    id: 'SENDGRID-KEY',
    name: 'SendGrid API Key',
    pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    description: 'SendGrid API Key',
  },
  // Mailchimp
  {
    id: 'MAILCHIMP-KEY',
    name: 'Mailchimp API Key',
    pattern: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    description: 'Mailchimp API Key',
  },
  // Discord
  {
    id: 'DISCORD-TOKEN',
    name: 'Discord Bot Token',
    pattern: /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b/g,
    description: 'Discord Bot Token',
  },
  {
    id: 'DISCORD-WEBHOOK',
    name: 'Discord Webhook URL',
    pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g,
    description: 'Discord Webhook URL',
  },
  // npm
  {
    id: 'NPM-TOKEN',
    name: 'npm Access Token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    description: 'npm Access Token',
  },
  // PyPI
  {
    id: 'PYPI-TOKEN',
    name: 'PyPI API Token',
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b/g,
    description: 'PyPI API Token',
  },
  // Private Keys
  {
    id: 'PRIVATE-KEY',
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    description: 'Private Key Header',
  },
  // Generic secrets
  {
    id: 'GENERIC-SECRET',
    name: 'Generic Secret Assignment',
    pattern: /(?:api_key|apikey|api_secret|apisecret|auth_token|authtoken|access_token|accesstoken|secret_key|secretkey|private_key|privatekey)\s*[=:]\s*['"][A-Za-z0-9\-_+/=]{16,}['"]/gi,
    description: 'Generic secret or API key assignment',
  },
  {
    id: 'GENERIC-PASSWORD',
    name: 'Generic Password Assignment',
    pattern: /(?:password|passwd|pwd|pass)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    description: 'Hardcoded password',
  },
  // Base64 encoded secrets (likely)
  {
    id: 'BASE64-SECRET',
    name: 'Base64 Encoded Secret',
    pattern: /(?:secret|key|token|password|credential)\s*[=:]\s*['"][A-Za-z0-9+/=]{40,}['"]/gi,
    description: 'Potentially base64 encoded secret',
  },
  // JWT
  {
    id: 'JWT-TOKEN',
    name: 'JWT Token',
    pattern: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g,
    description: 'JSON Web Token',
  },
  // Heroku
  {
    id: 'HEROKU-KEY',
    name: 'Heroku API Key',
    pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    description: 'Heroku API Key (UUID format)',
  },
  // Azure
  {
    id: 'AZURE-KEY',
    name: 'Azure Storage Key',
    pattern: /(?:AccountKey|azure_storage_key)\s*[=:]\s*['"][A-Za-z0-9+/=]{88}['"]/gi,
    description: 'Azure Storage Account Key',
  },
  // Anthropic
  {
    id: 'ANTHROPIC-KEY',
    name: 'Anthropic API Key',
    pattern: /\bsk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{80,}\b/g,
    description: 'Anthropic API Key',
  },
  // OpenAI
  {
    id: 'OPENAI-KEY',
    name: 'OpenAI API Key',
    pattern: /\bsk-[A-Za-z0-9]{48}\b/g,
    description: 'OpenAI API Key',
  },
];

interface SecretFinding {
  id: string;
  name: string;
  description: string;
  file: string;
  line: number;
  match: string;
  masked: string;
  entropy?: number;
}

// Shannon entropy calculation for detecting high-entropy secrets
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// Find high-entropy strings that might be secrets
function findHighEntropyStrings(content: string, filePath: string, lineNum: number): SecretFinding[] {
  const findings: SecretFinding[] = [];

  // Look for string assignments with high entropy
  const stringPatterns = [
    // Variable assignments: key = "value" or key: "value"
    /(?:const|let|var|export)?\s*(\w+)\s*[=:]\s*['"]([A-Za-z0-9\-_+/=]{20,})['"]/g,
    // Object properties: "key": "value"
    /['"]([\w_]+)['"]\s*:\s*['"]([A-Za-z0-9\-_+/=]{20,})['"]/g,
    // Environment-style: KEY=value
    /^([A-Z][A-Z0-9_]*)\s*=\s*([A-Za-z0-9\-_+/=]{20,})$/gm,
  ];

  // Keywords that suggest the string might be a secret
  const sensitiveKeywords = [
    'key', 'secret', 'token', 'password', 'passwd', 'pwd', 'auth',
    'credential', 'api', 'private', 'access', 'refresh', 'bearer',
  ];

  for (const pattern of stringPatterns) {
    pattern.lastIndex = 0;
    let match;

    while ((match = pattern.exec(content)) !== null) {
      const varName = match[1].toLowerCase();
      const value = match[2];

      // Skip if too short or looks like a hash/checksum (might be intentional)
      if (value.length < 20 || value.length > 200) continue;

      // Calculate entropy
      const entropy = calculateEntropy(value);

      // High entropy threshold (typical secrets have entropy > 4.5)
      // Also check if variable name suggests it's sensitive
      const isSensitiveName = sensitiveKeywords.some(kw => varName.includes(kw));
      const entropyThreshold = isSensitiveName ? 3.5 : 4.5;

      if (entropy >= entropyThreshold) {
        const masked = value.length > 10
          ? value.slice(0, 5) + '*'.repeat(value.length - 10) + value.slice(-5)
          : '*'.repeat(value.length);

        findings.push({
          id: 'ENTROPY-HIGH',
          name: 'High Entropy String',
          description: `High entropy string in "${match[1]}" (entropy: ${entropy.toFixed(2)}) - possible secret`,
          file: filePath,
          line: lineNum,
          match: value,
          masked,
          entropy,
        });
      }
    }
  }

  return findings;
}

async function scanFileForSecrets(
  content: string,
  filePath: string,
  useEntropy: boolean = false
): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];
  const lines = content.split('\n');

  // Pattern-based scanning
  for (const pattern of secretPatterns) {
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      let match: RegExpExecArray | null;

      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      while ((match = pattern.pattern.exec(line)) !== null) {
        const matchStr = match[0];
        // Mask the middle portion of the secret
        const masked = matchStr.length > 10
          ? matchStr.slice(0, 5) + '*'.repeat(matchStr.length - 10) + matchStr.slice(-5)
          : '*'.repeat(matchStr.length);

        findings.push({
          id: pattern.id,
          name: pattern.name,
          description: pattern.description,
          file: filePath,
          line: lineNum + 1,
          match: matchStr,
          masked,
        });
      }
    }
  }

  // Entropy-based scanning (optional)
  if (useEntropy) {
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const entropyFindings = findHighEntropyStrings(lines[lineNum], filePath, lineNum + 1);

      // Filter out duplicates (already found by pattern matching)
      for (const ef of entropyFindings) {
        const isDuplicate = findings.some(
          f => f.file === ef.file && f.line === ef.line && f.match === ef.match
        );
        if (!isDuplicate) {
          findings.push(ef);
        }
      }
    }
  }

  return findings;
}

export function registerScanSecretsTool(server: McpServer): void {
  server.tool(
    'scan-secrets',
    'Scan files for hardcoded secrets, API keys, and credentials (supports entropy-based detection)',
    {
      target: z.string().describe('File path or directory to scan'),
      recursive: z.boolean().default(true).describe('Recursively scan directories'),
      showValues: z.boolean().default(false).describe('Show actual secret values (use with caution)'),
      useEntropy: z.boolean().default(false).describe('Enable entropy-based detection for unknown secret formats'),
    },
    async ({ target, recursive, showValues, useEntropy }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-secrets', { target, recursive, showValues, useEntropy }, validation.warnings);

      const findings: SecretFinding[] = [];
      const scannedFiles: string[] = [];

      // File extensions to scan
      const scanExtensions = new Set([
        '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
        '.py', '.go', '.java', '.rb', '.php',
        '.json', '.yaml', '.yml', '.toml', '.xml',
        '.env', '.cfg', '.conf', '.config', '.ini',
        '.sh', '.bash', '.zsh',
        '.sql', '.properties',
      ]);

      // Files to always scan regardless of extension
      const scanFiles = new Set([
        '.env', '.env.local', '.env.development', '.env.production',
        'credentials', 'secrets', '.npmrc', '.pypirc',
        'docker-compose.yml', 'docker-compose.yaml',
        'config', 'settings',
      ]);

      async function scanPath(targetPath: string): Promise<void> {
        try {
          const stats = await fs.stat(targetPath);

          if (stats.isFile()) {
            const ext = path.extname(targetPath).toLowerCase();
            const basename = path.basename(targetPath).toLowerCase();

            if (scanExtensions.has(ext) || scanFiles.has(basename)) {
              const content = await fs.readFile(targetPath, 'utf-8');
              const fileFindings = await scanFileForSecrets(content, targetPath, useEntropy);
              findings.push(...fileFindings);
              scannedFiles.push(targetPath);
            }
          } else if (stats.isDirectory() && recursive) {
            const entries = await fs.readdir(targetPath, { withFileTypes: true });
            for (const entry of entries) {
              // Skip common non-source directories
              if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor', '.next'].includes(entry.name)) {
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

      if (findings.length === 0) {
        logOutput('scan-secrets', {
          success: true,
          summary: `No secrets found in ${target}`,
          metrics: { filesScanned: scannedFiles.length },
        });
        return {
          content: [{
            type: 'text' as const,
            text: `No secrets found in ${target}\n\nScanned ${scannedFiles.length} files.`,
          }],
        };
      }

      // Group findings by type
      const grouped = findings.reduce((acc, f) => {
        if (!acc[f.name]) acc[f.name] = [];
        acc[f.name].push(f);
        return acc;
      }, {} as Record<string, SecretFinding[]>);

      const report = Object.entries(grouped).map(([name, items]) =>
        `## ${name} (${items.length} found)\n\n` +
        items.map(f =>
          `- **File:** ${f.file}:${f.line}\n  **Value:** \`${showValues ? f.match : f.masked}\``
        ).join('\n\n')
      ).join('\n\n---\n\n');

      logOutput('scan-secrets', {
        success: true,
        summary: `Found ${findings.length} secrets`,
        metrics: { secretsFound: findings.length, filesScanned: scannedFiles.length, secretTypes: Object.keys(grouped).length },
      });
      return {
        content: [{
          type: 'text' as const,
          text: `# Secret Scan Results

## Summary
- Total secrets found: ${findings.length}
- Files scanned: ${scannedFiles.length}
- Secret types: ${Object.keys(grouped).length}

${report}

---

**Warning:** These secrets should be rotated immediately and removed from version control.`,
        }],
      };
    }
  );
}
