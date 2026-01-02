import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

interface LicenseInfo {
  name: string;
  spdxId: string;
  category: 'permissive' | 'copyleft' | 'weak-copyleft' | 'proprietary' | 'public-domain' | 'unknown';
  osiApproved: boolean;
  commercial: boolean;
  notes?: string;
}

const licenseDatabase: Record<string, LicenseInfo> = {
  // Permissive licenses
  'MIT': { name: 'MIT License', spdxId: 'MIT', category: 'permissive', osiApproved: true, commercial: true },
  'Apache-2.0': { name: 'Apache License 2.0', spdxId: 'Apache-2.0', category: 'permissive', osiApproved: true, commercial: true },
  'BSD-2-Clause': { name: 'BSD 2-Clause', spdxId: 'BSD-2-Clause', category: 'permissive', osiApproved: true, commercial: true },
  'BSD-3-Clause': { name: 'BSD 3-Clause', spdxId: 'BSD-3-Clause', category: 'permissive', osiApproved: true, commercial: true },
  'ISC': { name: 'ISC License', spdxId: 'ISC', category: 'permissive', osiApproved: true, commercial: true },
  'Unlicense': { name: 'Unlicense', spdxId: 'Unlicense', category: 'public-domain', osiApproved: true, commercial: true },
  'CC0-1.0': { name: 'CC0 1.0', spdxId: 'CC0-1.0', category: 'public-domain', osiApproved: false, commercial: true },
  'WTFPL': { name: 'WTFPL', spdxId: 'WTFPL', category: 'permissive', osiApproved: false, commercial: true },
  '0BSD': { name: 'Zero-Clause BSD', spdxId: '0BSD', category: 'permissive', osiApproved: true, commercial: true },
  'Zlib': { name: 'zlib License', spdxId: 'Zlib', category: 'permissive', osiApproved: true, commercial: true },

  // Copyleft licenses
  'GPL-2.0': { name: 'GNU GPL v2', spdxId: 'GPL-2.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft - derivative works must be GPL' },
  'GPL-2.0-only': { name: 'GNU GPL v2', spdxId: 'GPL-2.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft - derivative works must be GPL' },
  'GPL-2.0-or-later': { name: 'GNU GPL v2+', spdxId: 'GPL-2.0-or-later', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft' },
  'GPL-3.0': { name: 'GNU GPL v3', spdxId: 'GPL-3.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft - derivative works must be GPL' },
  'GPL-3.0-only': { name: 'GNU GPL v3', spdxId: 'GPL-3.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft - derivative works must be GPL' },
  'GPL-3.0-or-later': { name: 'GNU GPL v3+', spdxId: 'GPL-3.0-or-later', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Strong copyleft' },
  'AGPL-3.0': { name: 'GNU AGPL v3', spdxId: 'AGPL-3.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Network copyleft - even SaaS must share source' },
  'AGPL-3.0-only': { name: 'GNU AGPL v3', spdxId: 'AGPL-3.0-only', category: 'copyleft', osiApproved: true, commercial: false, notes: 'Network copyleft - even SaaS must share source' },

  // Weak copyleft
  'LGPL-2.1': { name: 'GNU LGPL v2.1', spdxId: 'LGPL-2.1-only', category: 'weak-copyleft', osiApproved: true, commercial: true, notes: 'Library linking allowed, modifications must be shared' },
  'LGPL-2.1-only': { name: 'GNU LGPL v2.1', spdxId: 'LGPL-2.1-only', category: 'weak-copyleft', osiApproved: true, commercial: true, notes: 'Library linking allowed, modifications must be shared' },
  'LGPL-3.0': { name: 'GNU LGPL v3', spdxId: 'LGPL-3.0-only', category: 'weak-copyleft', osiApproved: true, commercial: true, notes: 'Library linking allowed, modifications must be shared' },
  'LGPL-3.0-only': { name: 'GNU LGPL v3', spdxId: 'LGPL-3.0-only', category: 'weak-copyleft', osiApproved: true, commercial: true, notes: 'Library linking allowed' },
  'MPL-2.0': { name: 'Mozilla Public License 2.0', spdxId: 'MPL-2.0', category: 'weak-copyleft', osiApproved: true, commercial: true, notes: 'File-level copyleft' },
  'EPL-1.0': { name: 'Eclipse Public License 1.0', spdxId: 'EPL-1.0', category: 'weak-copyleft', osiApproved: true, commercial: true },
  'EPL-2.0': { name: 'Eclipse Public License 2.0', spdxId: 'EPL-2.0', category: 'weak-copyleft', osiApproved: true, commercial: true },
  'CDDL-1.0': { name: 'CDDL 1.0', spdxId: 'CDDL-1.0', category: 'weak-copyleft', osiApproved: true, commercial: true },

  // Other
  'CC-BY-4.0': { name: 'Creative Commons BY 4.0', spdxId: 'CC-BY-4.0', category: 'permissive', osiApproved: false, commercial: true, notes: 'Requires attribution' },
  'CC-BY-SA-4.0': { name: 'Creative Commons BY-SA 4.0', spdxId: 'CC-BY-SA-4.0', category: 'copyleft', osiApproved: false, commercial: true, notes: 'Share-alike requirement' },
  'CC-BY-NC-4.0': { name: 'Creative Commons BY-NC 4.0', spdxId: 'CC-BY-NC-4.0', category: 'proprietary', osiApproved: false, commercial: false, notes: 'Non-commercial only' },
  'BSL-1.0': { name: 'Boost Software License', spdxId: 'BSL-1.0', category: 'permissive', osiApproved: true, commercial: true },
  'Artistic-2.0': { name: 'Artistic License 2.0', spdxId: 'Artistic-2.0', category: 'permissive', osiApproved: true, commercial: true },
};

interface DependencyLicense {
  name: string;
  version: string;
  license: string;
  licenseInfo: LicenseInfo | null;
  risk: 'none' | 'low' | 'medium' | 'high';
}

function normalizeLicense(license: string): string {
  // Handle SPDX expressions
  let normalized = license.trim();

  // Common variations
  const variations: Record<string, string> = {
    'Apache 2.0': 'Apache-2.0',
    'Apache License 2.0': 'Apache-2.0',
    'Apache-2': 'Apache-2.0',
    'BSD': 'BSD-3-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD-3': 'BSD-3-Clause',
    'GPL': 'GPL-3.0',
    'GPLv2': 'GPL-2.0',
    'GPLv3': 'GPL-3.0',
    'LGPL': 'LGPL-3.0',
    'LGPLv2': 'LGPL-2.1',
    'LGPLv3': 'LGPL-3.0',
    'Public Domain': 'Unlicense',
  };

  return variations[normalized] || normalized;
}

function assessRisk(license: string, licenseInfo: LicenseInfo | null): 'none' | 'low' | 'medium' | 'high' {
  if (!licenseInfo) {
    return 'medium'; // Unknown license
  }

  if (licenseInfo.category === 'copyleft') {
    if (licenseInfo.spdxId.includes('AGPL')) {
      return 'high'; // AGPL is highest risk for commercial
    }
    return 'high'; // GPL family
  }

  if (licenseInfo.category === 'weak-copyleft') {
    return 'medium';
  }

  if (!licenseInfo.commercial) {
    return 'high'; // Non-commercial license
  }

  return 'none';
}

async function parsePackageJson(filePath: string): Promise<DependencyLicense[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const pkg = JSON.parse(content);
  const deps: DependencyLicense[] = [];

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  // For a real implementation, we'd read each package's package.json
  // For now, we'll flag that we need to scan node_modules
  for (const [name, version] of Object.entries(allDeps)) {
    deps.push({
      name,
      version: String(version),
      license: 'NEEDS_SCAN',
      licenseInfo: null,
      risk: 'medium',
    });
  }

  // Try to read license info from node_modules
  const nodeModulesPath = path.join(path.dirname(filePath), 'node_modules');
  try {
    await fs.access(nodeModulesPath);
    for (const dep of deps) {
      try {
        const depPkgPath = path.join(nodeModulesPath, dep.name, 'package.json');
        const depContent = await fs.readFile(depPkgPath, 'utf-8');
        const depPkg = JSON.parse(depContent);
        const license = depPkg.license || 'UNKNOWN';
        const normalizedLicense = normalizeLicense(license);
        const licenseInfo = licenseDatabase[normalizedLicense] || null;

        dep.license = license;
        dep.licenseInfo = licenseInfo;
        dep.risk = assessRisk(license, licenseInfo);
      } catch {
        // Package not installed or no package.json
      }
    }
  } catch {
    // node_modules doesn't exist
  }

  return deps;
}

async function parseRequirementsTxt(filePath: string): Promise<DependencyLicense[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const deps: DependencyLicense[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }

    const match = trimmed.match(/^([a-zA-Z0-9\-_]+)(?:[=<>~!]+(.+))?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || 'latest',
        license: 'UNKNOWN', // Would need pip show or API to get license
        licenseInfo: null,
        risk: 'medium',
      });
    }
  }

  return deps;
}

export function registerScanLicensesTool(server: McpServer): void {
  server.tool(
    'scan-licenses',
    'Scan project dependencies for license compliance and potential conflicts',
    {
      target: z.string().describe('Project directory or dependency file path'),
      policy: z.enum(['permissive', 'weak-copyleft', 'any-oss', 'all']).default('permissive')
        .describe('License policy: permissive (MIT, Apache, BSD), weak-copyleft (+ LGPL, MPL), any-oss (any OSI), all (show all)'),
    },
    async ({ target, policy }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-licenses', { target, policy }, validation.warnings);

      let deps: DependencyLicense[] = [];
      let dependencyFile = '';

      try {
        const stats = await fs.stat(target);

        if (stats.isDirectory()) {
          const files = await fs.readdir(target);

          if (files.includes('package.json')) {
            dependencyFile = path.join(target, 'package.json');
            deps = await parsePackageJson(dependencyFile);
          } else if (files.includes('requirements.txt')) {
            dependencyFile = path.join(target, 'requirements.txt');
            deps = await parseRequirementsTxt(dependencyFile);
          } else {
            logOutput('scan-licenses', {
              success: false,
              error: 'No supported dependency file found',
            });
            return {
              content: [{
                type: 'text' as const,
                text: 'No supported dependency file found (package.json, requirements.txt)',
              }],
              isError: true,
            };
          }
        } else {
          dependencyFile = target;
          const filename = path.basename(target);

          if (filename === 'package.json') {
            deps = await parsePackageJson(target);
          } else if (filename === 'requirements.txt') {
            deps = await parseRequirementsTxt(target);
          }
        }

        // Filter by policy
        const violations: DependencyLicense[] = [];
        const allowed: DependencyLicense[] = [];
        const unknown: DependencyLicense[] = [];

        for (const dep of deps) {
          if (!dep.licenseInfo || dep.license === 'UNKNOWN' || dep.license === 'NEEDS_SCAN') {
            unknown.push(dep);
            continue;
          }

          let isViolation = false;

          switch (policy) {
            case 'permissive':
              isViolation = dep.licenseInfo.category !== 'permissive' && dep.licenseInfo.category !== 'public-domain';
              break;
            case 'weak-copyleft':
              isViolation = dep.licenseInfo.category === 'copyleft' || dep.licenseInfo.category === 'proprietary';
              break;
            case 'any-oss':
              isViolation = !dep.licenseInfo.osiApproved;
              break;
            case 'all':
              isViolation = false;
              break;
          }

          if (isViolation) {
            violations.push(dep);
          } else {
            allowed.push(dep);
          }
        }

        // Generate license inventory
        const licenseInventory: Record<string, string[]> = {};
        for (const dep of deps) {
          const license = dep.license || 'UNKNOWN';
          if (!licenseInventory[license]) {
            licenseInventory[license] = [];
          }
          licenseInventory[license].push(`${dep.name}@${dep.version}`);
        }

        const inventoryText = Object.entries(licenseInventory)
          .map(([license, packages]) => `### ${license}\n${packages.map(p => `- ${p}`).join('\n')}`)
          .join('\n\n');

        const violationsText = violations.length > 0
          ? violations.map(v =>
              `- **${v.name}@${v.version}**: ${v.license} (${v.licenseInfo?.category || 'unknown'})\n  ${v.licenseInfo?.notes || ''}`
            ).join('\n')
          : 'None';

        const unknownText = unknown.length > 0
          ? unknown.map(u => `- ${u.name}@${u.version}: ${u.license}`).join('\n')
          : 'None';

        const highRisk = deps.filter(d => d.risk === 'high');
        const mediumRisk = deps.filter(d => d.risk === 'medium');

        logOutput('scan-licenses', {
          success: true,
          summary: `Scanned ${deps.length} dependencies, ${violations.length} violations`,
          metrics: { total: deps.length, violations: violations.length, unknown: unknown.length, highRisk: highRisk.length },
        });
        return {
          content: [{
            type: 'text' as const,
            text: `# License Compliance Report

## Summary
- **File:** ${dependencyFile}
- **Policy:** ${policy}
- **Total dependencies:** ${deps.length}
- **Policy violations:** ${violations.length}
- **Unknown licenses:** ${unknown.length}

## Risk Assessment
- **High risk (copyleft/non-commercial):** ${highRisk.length}
- **Medium risk (weak-copyleft/unknown):** ${mediumRisk.length}
- **Low/No risk:** ${deps.length - highRisk.length - mediumRisk.length}

---

## Policy Violations (${violations.length})

${violationsText}

---

## Unknown Licenses (${unknown.length})

${unknownText}

---

## License Inventory

${inventoryText}

---

## Notes

${policy === 'permissive' ? '**Permissive policy**: Only MIT, Apache-2.0, BSD, ISC, and similar licenses allowed.' : ''}
${policy === 'weak-copyleft' ? '**Weak copyleft policy**: Permissive + LGPL, MPL allowed. GPL/AGPL prohibited.' : ''}
${policy === 'any-oss' ? '**Any OSS policy**: All OSI-approved licenses allowed.' : ''}

**Important:** For accurate Python license detection, run: \`pip-licenses --format=json\`
`,
          }],
        };
      } catch (error) {
        logOutput('scan-licenses', {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error scanning licenses: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );
}
