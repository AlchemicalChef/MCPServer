import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation } from '../utils/auditLog.js';

interface DependencyInfo {
  name: string;
  version: string;
  type: 'production' | 'development';
}

interface VulnerabilityInfo {
  package: string;
  currentVersion: string;
  vulnerableVersions: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
  title: string;
  cve?: string;
  recommendation: string;
}

async function parsePackageJson(filePath: string): Promise<DependencyInfo[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const pkg = JSON.parse(content);
  const deps: DependencyInfo[] = [];

  if (pkg.dependencies) {
    for (const [name, version] of Object.entries(pkg.dependencies)) {
      deps.push({
        name,
        version: String(version).replace(/^[\^~]/, ''),
        type: 'production',
      });
    }
  }

  if (pkg.devDependencies) {
    for (const [name, version] of Object.entries(pkg.devDependencies)) {
      deps.push({
        name,
        version: String(version).replace(/^[\^~]/, ''),
        type: 'development',
      });
    }
  }

  return deps;
}

async function parseRequirementsTxt(filePath: string): Promise<DependencyInfo[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const deps: DependencyInfo[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }

    // Handle various formats: package==1.0.0, package>=1.0.0, package~=1.0.0
    const match = trimmed.match(/^([a-zA-Z0-9\-_]+)(?:[=<>~!]+(.+))?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || 'latest',
        type: 'production',
      });
    }
  }

  return deps;
}

async function parseGoMod(filePath: string): Promise<DependencyInfo[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const deps: DependencyInfo[] = [];

  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  if (requireBlock) {
    for (const line of requireBlock[1].split('\n')) {
      const match = line.trim().match(/^(\S+)\s+v?(\S+)/);
      if (match && !match[1].startsWith('//')) {
        deps.push({
          name: match[1],
          version: match[2],
          type: 'production',
        });
      }
    }
  }

  // Also check single-line requires
  const singleRequires = content.matchAll(/require\s+(\S+)\s+v?(\S+)/g);
  for (const match of singleRequires) {
    deps.push({
      name: match[1],
      version: match[2],
      type: 'production',
    });
  }

  return deps;
}

async function parseCargoToml(filePath: string): Promise<DependencyInfo[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const deps: DependencyInfo[] = [];

  // Simple TOML parsing for dependencies
  const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
  if (depSection) {
    for (const line of depSection[1].split('\n')) {
      const match = line.trim().match(/^([a-zA-Z0-9\-_]+)\s*=\s*["']?([^"'\s]+)["']?/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          type: 'production',
        });
      }
    }
  }

  return deps;
}

// Known vulnerable packages database (simplified - in production, use a real CVE database)
const knownVulnerabilities: Record<string, VulnerabilityInfo[]> = {
  'lodash': [
    {
      package: 'lodash',
      currentVersion: '',
      vulnerableVersions: '<4.17.21',
      severity: 'high',
      title: 'Prototype Pollution',
      cve: 'CVE-2021-23337',
      recommendation: 'Upgrade to 4.17.21 or later',
    },
  ],
  'minimist': [
    {
      package: 'minimist',
      currentVersion: '',
      vulnerableVersions: '<1.2.6',
      severity: 'critical',
      title: 'Prototype Pollution',
      cve: 'CVE-2021-44906',
      recommendation: 'Upgrade to 1.2.6 or later',
    },
  ],
  'node-fetch': [
    {
      package: 'node-fetch',
      currentVersion: '',
      vulnerableVersions: '<2.6.7',
      severity: 'high',
      title: 'Exposure of Sensitive Information',
      cve: 'CVE-2022-0235',
      recommendation: 'Upgrade to 2.6.7 or later',
    },
  ],
  'axios': [
    {
      package: 'axios',
      currentVersion: '',
      vulnerableVersions: '<1.6.0',
      severity: 'high',
      title: 'CSRF and SSRF vulnerabilities',
      cve: 'CVE-2023-45857',
      recommendation: 'Upgrade to 1.6.0 or later',
    },
  ],
  'express': [
    {
      package: 'express',
      currentVersion: '',
      vulnerableVersions: '<4.19.2',
      severity: 'moderate',
      title: 'Open Redirect vulnerability',
      cve: 'CVE-2024-29041',
      recommendation: 'Upgrade to 4.19.2 or later',
    },
  ],
  'jsonwebtoken': [
    {
      package: 'jsonwebtoken',
      currentVersion: '',
      vulnerableVersions: '<9.0.0',
      severity: 'high',
      title: 'Algorithm confusion attack',
      cve: 'CVE-2022-23529',
      recommendation: 'Upgrade to 9.0.0 or later',
    },
  ],
  'moment': [
    {
      package: 'moment',
      currentVersion: '',
      vulnerableVersions: '<2.29.4',
      severity: 'high',
      title: 'Path Traversal vulnerability',
      cve: 'CVE-2022-31129',
      recommendation: 'Upgrade to 2.29.4 or later, or consider day.js/date-fns',
    },
  ],
  'tar': [
    {
      package: 'tar',
      currentVersion: '',
      vulnerableVersions: '<6.1.11',
      severity: 'high',
      title: 'Arbitrary File Creation/Overwrite',
      cve: 'CVE-2021-37701',
      recommendation: 'Upgrade to 6.1.11 or later',
    },
  ],
  'glob-parent': [
    {
      package: 'glob-parent',
      currentVersion: '',
      vulnerableVersions: '<5.1.2',
      severity: 'high',
      title: 'Regular Expression Denial of Service',
      cve: 'CVE-2020-28469',
      recommendation: 'Upgrade to 5.1.2 or later',
    },
  ],
  'path-parse': [
    {
      package: 'path-parse',
      currentVersion: '',
      vulnerableVersions: '<1.0.7',
      severity: 'moderate',
      title: 'Regular Expression Denial of Service',
      cve: 'CVE-2021-23343',
      recommendation: 'Upgrade to 1.0.7 or later',
    },
  ],
  'requests': [
    {
      package: 'requests',
      currentVersion: '',
      vulnerableVersions: '<2.31.0',
      severity: 'moderate',
      title: 'Information disclosure via proxy',
      cve: 'CVE-2023-32681',
      recommendation: 'Upgrade to 2.31.0 or later',
    },
  ],
  'pyyaml': [
    {
      package: 'pyyaml',
      currentVersion: '',
      vulnerableVersions: '<5.4',
      severity: 'critical',
      title: 'Arbitrary Code Execution',
      cve: 'CVE-2020-14343',
      recommendation: 'Upgrade to 5.4 or later',
    },
  ],
  'django': [
    {
      package: 'django',
      currentVersion: '',
      vulnerableVersions: '<4.2.8',
      severity: 'high',
      title: 'Denial of Service vulnerability',
      cve: 'CVE-2023-46695',
      recommendation: 'Upgrade to 4.2.8 or later',
    },
  ],
  'flask': [
    {
      package: 'flask',
      currentVersion: '',
      vulnerableVersions: '<2.3.2',
      severity: 'high',
      title: 'Security bypass vulnerability',
      cve: 'CVE-2023-30861',
      recommendation: 'Upgrade to 2.3.2 or later',
    },
  ],
  'pillow': [
    {
      package: 'pillow',
      currentVersion: '',
      vulnerableVersions: '<10.0.1',
      severity: 'high',
      title: 'Buffer overflow vulnerability',
      cve: 'CVE-2023-4863',
      recommendation: 'Upgrade to 10.0.1 or later',
    },
  ],
};

function compareVersions(current: string, vulnerable: string): boolean {
  // Simple version comparison - in production, use semver library
  const parseVersion = (v: string) => {
    const match = v.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
    if (!match) return [0, 0, 0];
    return [
      parseInt(match[1]) || 0,
      parseInt(match[2]) || 0,
      parseInt(match[3]) || 0,
    ];
  };

  const currentParts = parseVersion(current);
  const vulnMatch = vulnerable.match(/<(.+)/);
  if (!vulnMatch) return false;

  const vulnParts = parseVersion(vulnMatch[1]);

  for (let i = 0; i < 3; i++) {
    if (currentParts[i] < vulnParts[i]) return true;
    if (currentParts[i] > vulnParts[i]) return false;
  }
  return false;
}

export function registerScanDependenciesTool(server: McpServer): void {
  server.tool(
    'scan-dependencies',
    'Scan project dependencies for known security vulnerabilities (CVEs)',
    {
      target: z.string().describe('Project directory or dependency file path'),
    },
    async ({ target }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-dependencies', { target }, validation.warnings);

      const vulnerabilities: VulnerabilityInfo[] = [];
      let dependencies: DependencyInfo[] = [];
      let dependencyFile = '';

      try {
        const stats = await fs.stat(target);

        if (stats.isDirectory()) {
          // Look for dependency files
          const files = await fs.readdir(target);

          if (files.includes('package.json')) {
            dependencyFile = path.join(target, 'package.json');
            dependencies = await parsePackageJson(dependencyFile);
          } else if (files.includes('requirements.txt')) {
            dependencyFile = path.join(target, 'requirements.txt');
            dependencies = await parseRequirementsTxt(dependencyFile);
          } else if (files.includes('go.mod')) {
            dependencyFile = path.join(target, 'go.mod');
            dependencies = await parseGoMod(dependencyFile);
          } else if (files.includes('Cargo.toml')) {
            dependencyFile = path.join(target, 'Cargo.toml');
            dependencies = await parseCargoToml(dependencyFile);
          } else {
            return {
              content: [{
                type: 'text' as const,
                text: 'No supported dependency file found (package.json, requirements.txt, go.mod, Cargo.toml)',
              }],
            };
          }
        } else {
          // Direct file path
          dependencyFile = target;
          const filename = path.basename(target);

          if (filename === 'package.json') {
            dependencies = await parsePackageJson(target);
          } else if (filename === 'requirements.txt') {
            dependencies = await parseRequirementsTxt(target);
          } else if (filename === 'go.mod') {
            dependencies = await parseGoMod(target);
          } else if (filename === 'Cargo.toml') {
            dependencies = await parseCargoToml(target);
          }
        }

        // Check each dependency against known vulnerabilities
        for (const dep of dependencies) {
          const vulns = knownVulnerabilities[dep.name.toLowerCase()];
          if (vulns) {
            for (const vuln of vulns) {
              if (compareVersions(dep.version, vuln.vulnerableVersions)) {
                vulnerabilities.push({
                  ...vuln,
                  currentVersion: dep.version,
                });
              }
            }
          }
        }

        if (vulnerabilities.length === 0) {
          return {
            content: [{
              type: 'text' as const,
              text: `# Dependency Scan Results

**File:** ${dependencyFile}
**Dependencies scanned:** ${dependencies.length}
**Vulnerabilities found:** 0

No known vulnerabilities found in the scanned dependencies.

**Note:** This scan uses a limited vulnerability database. For comprehensive scanning, consider using:
- \`npm audit\` for Node.js projects
- \`pip-audit\` or \`safety\` for Python projects
- \`govulncheck\` for Go projects
- \`cargo audit\` for Rust projects`,
            }],
          };
        }

        // Sort by severity
        const severityOrder = ['critical', 'high', 'moderate', 'low'];
        vulnerabilities.sort((a, b) =>
          severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
        );

        const report = vulnerabilities.map(v =>
          `### ${v.package}@${v.currentVersion}

- **Severity:** ${v.severity.toUpperCase()}
- **CVE:** ${v.cve || 'N/A'}
- **Title:** ${v.title}
- **Vulnerable versions:** ${v.vulnerableVersions}
- **Recommendation:** ${v.recommendation}`
        ).join('\n\n---\n\n');

        const summary = {
          critical: vulnerabilities.filter(v => v.severity === 'critical').length,
          high: vulnerabilities.filter(v => v.severity === 'high').length,
          moderate: vulnerabilities.filter(v => v.severity === 'moderate').length,
          low: vulnerabilities.filter(v => v.severity === 'low').length,
        };

        return {
          content: [{
            type: 'text' as const,
            text: `# Dependency Scan Results

**File:** ${dependencyFile}
**Dependencies scanned:** ${dependencies.length}

## Summary
- **Critical:** ${summary.critical}
- **High:** ${summary.high}
- **Moderate:** ${summary.moderate}
- **Low:** ${summary.low}
- **Total:** ${vulnerabilities.length}

## Vulnerabilities

${report}`,
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error scanning dependencies: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );
}
