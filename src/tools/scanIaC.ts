import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

interface IaCFinding {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  description: string;
  remediation: string;
  cis?: string;
}

interface DockerfileCheck {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  pattern: RegExp;
  description: string;
  remediation: string;
  cis?: string;
  invertMatch?: boolean;
  requiresContext?: boolean;
  contextCheck?: (lines: string[], lineIndex: number) => boolean;
}

const dockerfileChecks: DockerfileCheck[] = [
  // CIS Docker Benchmark checks
  {
    id: 'DOCKER-001',
    name: 'Running as root user',
    severity: 'high',
    pattern: /^(?!.*USER\s+\S+)/,
    description: 'No USER instruction found. Container will run as root by default.',
    remediation: 'Add USER instruction to run container as non-root user: USER appuser',
    cis: 'CIS 4.1',
    invertMatch: true,
    requiresContext: true,
    contextCheck: (lines: string[]) => {
      // Check if any USER instruction exists that's not root
      return !lines.some(line => {
        const match = line.match(/^\s*USER\s+(\S+)/i);
        return match && match[1] !== 'root' && match[1] !== '0';
      });
    },
  },
  {
    id: 'DOCKER-002',
    name: 'USER root explicitly set',
    severity: 'high',
    pattern: /^\s*USER\s+(root|0)\s*$/i,
    description: 'Container explicitly configured to run as root user.',
    remediation: 'Change USER to a non-root user: USER appuser',
    cis: 'CIS 4.1',
  },
  {
    id: 'DOCKER-003',
    name: 'Using latest tag',
    severity: 'medium',
    pattern: /^\s*FROM\s+\S+:latest\s*$/i,
    description: 'Using "latest" tag can lead to unpredictable builds and security issues.',
    remediation: 'Specify a specific version tag: FROM image:1.0.0',
    cis: 'CIS 4.7',
  },
  {
    id: 'DOCKER-004',
    name: 'FROM without tag',
    severity: 'medium',
    pattern: /^\s*FROM\s+([^\s:]+)\s*$/i,
    description: 'No tag specified for base image. Defaults to "latest" which is unpredictable.',
    remediation: 'Specify a version tag: FROM image:1.0.0',
    cis: 'CIS 4.7',
  },
  {
    id: 'DOCKER-005',
    name: 'ADD instead of COPY',
    severity: 'low',
    pattern: /^\s*ADD\s+(?!https?:\/\/)/i,
    description: 'ADD has implicit behaviors (tar extraction, remote URLs). COPY is more explicit.',
    remediation: 'Use COPY for local files: COPY src/ /app/',
    cis: 'CIS 4.9',
  },
  {
    id: 'DOCKER-006',
    name: 'Exposed secrets in ENV',
    severity: 'critical',
    pattern: /^\s*ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY|APIKEY|AUTH)\S*\s*[=\s]/i,
    description: 'Potential secret exposed in environment variable. Secrets should not be hardcoded.',
    remediation: 'Use Docker secrets or pass secrets at runtime via --env-file',
  },
  {
    id: 'DOCKER-007',
    name: 'Hardcoded secret in ARG',
    severity: 'critical',
    pattern: /^\s*ARG\s+\S*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY|APIKEY|AUTH)\S*=/i,
    description: 'Secrets in ARG are visible in image history and should be avoided.',
    remediation: 'Use Docker secrets or multi-stage builds to avoid secrets in final image',
  },
  {
    id: 'DOCKER-008',
    name: 'EXPOSE all interfaces',
    severity: 'medium',
    pattern: /^\s*EXPOSE\s+0\.0\.0\.0/i,
    description: 'Exposing on all interfaces may expose service to unintended networks.',
    remediation: 'Limit exposure to specific interfaces if possible',
  },
  {
    id: 'DOCKER-009',
    name: 'Privileged port exposure',
    severity: 'low',
    pattern: /^\s*EXPOSE\s+([1-9]|[1-9][0-9]|[1-9][0-9][0-9]|10[0-1][0-9]|102[0-3])\s*$/,
    description: 'Exposing privileged ports (< 1024) typically requires root privileges.',
    remediation: 'Use non-privileged ports (>= 1024) when possible',
  },
  {
    id: 'DOCKER-010',
    name: 'apt-get without no-install-recommends',
    severity: 'low',
    pattern: /^\s*RUN\s+.*apt-get\s+install(?!.*--no-install-recommends)/i,
    description: 'Installing packages without --no-install-recommends increases image size and attack surface.',
    remediation: 'Add --no-install-recommends: apt-get install --no-install-recommends package',
  },
  {
    id: 'DOCKER-011',
    name: 'apt-get without cleanup',
    severity: 'low',
    pattern: /^\s*RUN\s+.*apt-get\s+install(?!.*&&\s*rm\s+-rf\s+\/var\/lib\/apt\/lists)/i,
    description: 'Package cache not cleaned after installation, increasing image size.',
    remediation: 'Clean apt cache: && rm -rf /var/lib/apt/lists/*',
  },
  {
    id: 'DOCKER-012',
    name: 'curl/wget piped to shell',
    severity: 'critical',
    pattern: /^\s*RUN\s+.*(curl|wget)\s+.*\|\s*(sh|bash|zsh)/i,
    description: 'Piping remote scripts to shell is dangerous. Script could be compromised.',
    remediation: 'Download script first, verify checksum, then execute',
  },
  {
    id: 'DOCKER-013',
    name: 'sudo in RUN',
    severity: 'medium',
    pattern: /^\s*RUN\s+.*\bsudo\b/i,
    description: 'Using sudo in Dockerfile. Build already runs as root, sudo is unnecessary and may indicate issues.',
    remediation: 'Remove sudo from RUN commands. If non-root user needed, use USER instruction',
  },
  {
    id: 'DOCKER-014',
    name: 'HEALTHCHECK missing',
    severity: 'low',
    pattern: /^(?!.*HEALTHCHECK)/,
    description: 'No HEALTHCHECK instruction. Container health cannot be monitored.',
    remediation: 'Add HEALTHCHECK: HEALTHCHECK CMD curl -f http://localhost/ || exit 1',
    invertMatch: true,
    requiresContext: true,
    contextCheck: (lines: string[]) => {
      return !lines.some(line => /^\s*HEALTHCHECK\s+/i.test(line));
    },
  },
  {
    id: 'DOCKER-015',
    name: 'chmod 777 permissions',
    severity: 'high',
    pattern: /^\s*RUN\s+.*chmod\s+777/i,
    description: 'World-writable permissions (777) are overly permissive and insecure.',
    remediation: 'Use minimal permissions: chmod 755 for directories, chmod 644 for files',
  },
  {
    id: 'DOCKER-016',
    name: 'SSH private key copy',
    severity: 'critical',
    pattern: /^\s*(COPY|ADD)\s+.*id_rsa|\.ssh/i,
    description: 'SSH private key may be copied into image. Keys will be visible in image layers.',
    remediation: 'Use SSH agent forwarding or Docker build secrets instead',
  },
  {
    id: 'DOCKER-017',
    name: 'Sensitive file copy',
    severity: 'high',
    pattern: /^\s*(COPY|ADD)\s+.*\.(pem|key|p12|pfx|env|credentials|htpasswd)/i,
    description: 'Sensitive file being copied into image. Will be visible in image layers.',
    remediation: 'Use Docker secrets or mount at runtime',
  },
  {
    id: 'DOCKER-018',
    name: 'Package manager cache not cleaned (yum/dnf)',
    severity: 'low',
    pattern: /^\s*RUN\s+.*(yum|dnf)\s+install(?!.*&&\s*(yum|dnf)\s+clean\s+all)/i,
    description: 'Package cache not cleaned after installation.',
    remediation: 'Clean cache: && yum clean all or && dnf clean all',
  },
  {
    id: 'DOCKER-019',
    name: 'Package manager cache not cleaned (apk)',
    severity: 'low',
    pattern: /^\s*RUN\s+.*apk\s+add(?!.*--no-cache)/i,
    description: 'Alpine package cache not disabled.',
    remediation: 'Use --no-cache flag: apk add --no-cache package',
  },
  {
    id: 'DOCKER-020',
    name: 'Using root in final stage',
    severity: 'high',
    pattern: /^\s*FROM\s+.*\s+AS\s+\S+[\s\S]*?(?=FROM|$)/gi,
    description: 'Multi-stage build final stage may run as root.',
    remediation: 'Ensure USER instruction in final stage sets non-root user',
    requiresContext: true,
    contextCheck: (lines: string[]) => {
      // Find the last FROM and check if there's a non-root USER after it
      let lastFromIndex = -1;
      for (let i = lines.length - 1; i >= 0; i--) {
        if (/^\s*FROM\s+/i.test(lines[i])) {
          lastFromIndex = i;
          break;
        }
      }
      if (lastFromIndex === -1) return false;

      // Check for USER instruction after last FROM
      for (let i = lastFromIndex + 1; i < lines.length; i++) {
        const match = lines[i].match(/^\s*USER\s+(\S+)/i);
        if (match && match[1] !== 'root' && match[1] !== '0') {
          return false; // Found non-root user, no issue
        }
      }
      return true; // No non-root USER found after last FROM
    },
  },
];

async function scanDockerfile(filePath: string): Promise<IaCFinding[]> {
  const findings: IaCFinding[] = [];
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n');

  // Context checks (checks that need to look at whole file)
  for (const check of dockerfileChecks) {
    if (check.requiresContext && check.contextCheck) {
      if (check.contextCheck(lines, 0)) {
        findings.push({
          id: check.id,
          name: check.name,
          severity: check.severity,
          file: filePath,
          line: 1,
          description: check.description,
          remediation: check.remediation,
          cis: check.cis,
        });
      }
    }
  }

  // Line-by-line checks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip empty lines and comments
    if (!line.trim() || line.trim().startsWith('#')) {
      continue;
    }

    for (const check of dockerfileChecks) {
      if (check.requiresContext) continue; // Already handled above

      if (check.invertMatch) {
        // These are handled by context checks
        continue;
      }

      check.pattern.lastIndex = 0;
      if (check.pattern.test(line)) {
        findings.push({
          id: check.id,
          name: check.name,
          severity: check.severity,
          file: filePath,
          line: i + 1,
          description: check.description,
          remediation: check.remediation,
          cis: check.cis,
        });
      }
    }
  }

  return findings;
}

export function registerScanIaCTool(server: McpServer): void {
  server.tool(
    'scan-iac',
    'Scan Infrastructure-as-Code files (Dockerfile) for security misconfigurations',
    {
      target: z.string().describe('File path or directory to scan'),
      recursive: z.boolean().default(true).describe('Recursively scan directories'),
      severity: z.enum(['all', 'critical', 'high', 'medium', 'low']).default('all')
        .describe('Minimum severity level to report'),
    },
    async ({ target, recursive, severity }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-iac', { target, recursive, severity }, validation.warnings);

      const findings: IaCFinding[] = [];
      const severityOrder = ['critical', 'high', 'medium', 'low'];
      const minSeverityIndex = severity === 'all' ? 3 : severityOrder.indexOf(severity);
      const scannedFiles: string[] = [];

      async function scanPath(targetPath: string): Promise<void> {
        try {
          const stats = await fs.stat(targetPath);

          if (stats.isFile()) {
            const filename = path.basename(targetPath).toLowerCase();
            if (filename === 'dockerfile' || filename.startsWith('dockerfile.')) {
              const fileFindings = await scanDockerfile(targetPath);
              findings.push(...fileFindings);
              scannedFiles.push(targetPath);
            }
          } else if (stats.isDirectory() && recursive) {
            const entries = await fs.readdir(targetPath, { withFileTypes: true });
            for (const entry of entries) {
              if (['node_modules', '.git', 'vendor', '.venv'].includes(entry.name)) {
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

      // Sort by severity then by file/line
      filteredFindings.sort((a, b) => {
        const sevDiff = severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
        if (sevDiff !== 0) return sevDiff;
        const fileDiff = a.file.localeCompare(b.file);
        if (fileDiff !== 0) return fileDiff;
        return a.line - b.line;
      });

      if (filteredFindings.length === 0) {
        logOutput('scan-iac', {
          success: true,
          summary: 'No security issues found',
          metrics: { filesScanned: scannedFiles.length },
        });
        return {
          content: [{
            type: 'text' as const,
            text: `# IaC Security Scan Results

**Target:** ${target}
**Files scanned:** ${scannedFiles.length}
**Issues found:** 0

No security issues found in scanned Dockerfiles.`,
          }],
        };
      }

      const summary = {
        critical: filteredFindings.filter(f => f.severity === 'critical').length,
        high: filteredFindings.filter(f => f.severity === 'high').length,
        medium: filteredFindings.filter(f => f.severity === 'medium').length,
        low: filteredFindings.filter(f => f.severity === 'low').length,
      };

      const report = filteredFindings.map(f =>
        `### [${f.severity.toUpperCase()}] ${f.name} (${f.id})
**File:** ${f.file}:${f.line}
${f.cis ? `**CIS Benchmark:** ${f.cis}` : ''}
**Description:** ${f.description}
**Remediation:** ${f.remediation}`
      ).join('\n\n---\n\n');

      logOutput('scan-iac', {
        success: true,
        summary: `Found ${filteredFindings.length} issues`,
        metrics: { critical: summary.critical, high: summary.high, medium: summary.medium, low: summary.low, total: filteredFindings.length },
      });
      return {
        content: [{
          type: 'text' as const,
          text: `# IaC Security Scan Results

## Summary
- **Target:** ${target}
- **Files scanned:** ${scannedFiles.length}
- **Total issues:** ${filteredFindings.length}
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
