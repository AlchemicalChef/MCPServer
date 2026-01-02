import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

interface Component {
  type: 'library' | 'framework' | 'application';
  name: string;
  version: string;
  purl?: string;
  description?: string;
  licenses?: Array<{ id?: string; name?: string }>;
  hashes?: Array<{ alg: string; content: string }>;
  externalReferences?: Array<{ type: string; url: string }>;
  scope?: 'required' | 'optional' | 'excluded';
}

interface CycloneDXBom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{ vendor: string; name: string; version: string }>;
    component?: {
      type: string;
      name: string;
      version?: string;
    };
  };
  components: Component[];
  dependencies?: Array<{
    ref: string;
    dependsOn: string[];
  }>;
}

function generateUuid(): string {
  return 'urn:uuid:' + crypto.randomUUID();
}

function createPurl(ecosystem: string, name: string, version: string): string {
  // Package URL format: pkg:type/namespace/name@version
  const encodedName = encodeURIComponent(name);
  return `pkg:${ecosystem}/${encodedName}@${version}`;
}

async function parsePackageJsonForSbom(filePath: string): Promise<{
  metadata: { name: string; version?: string; description?: string };
  components: Component[];
  lockFile?: string;
}> {
  const content = await fs.readFile(filePath, 'utf-8');
  const pkg = JSON.parse(content);
  const components: Component[] = [];

  const addDependencies = (deps: Record<string, string>, scope: 'required' | 'optional') => {
    for (const [name, version] of Object.entries(deps)) {
      const cleanVersion = String(version).replace(/^[\^~>=<]/, '').replace(/\s.+$/, '');
      components.push({
        type: 'library',
        name,
        version: cleanVersion,
        purl: createPurl('npm', name, cleanVersion),
        scope,
        externalReferences: [
          { type: 'website', url: `https://www.npmjs.com/package/${name}` },
        ],
      });
    }
  };

  if (pkg.dependencies) {
    addDependencies(pkg.dependencies, 'required');
  }

  if (pkg.devDependencies) {
    addDependencies(pkg.devDependencies, 'optional');
  }

  // Check for lock file
  const dir = path.dirname(filePath);
  let lockFile: string | undefined;
  try {
    await fs.access(path.join(dir, 'package-lock.json'));
    lockFile = 'package-lock.json';
  } catch {
    try {
      await fs.access(path.join(dir, 'yarn.lock'));
      lockFile = 'yarn.lock';
    } catch {
      try {
        await fs.access(path.join(dir, 'pnpm-lock.yaml'));
        lockFile = 'pnpm-lock.yaml';
      } catch {
        // No lock file found
      }
    }
  }

  return {
    metadata: {
      name: pkg.name || 'unknown',
      version: pkg.version,
      description: pkg.description,
    },
    components,
    lockFile,
  };
}

async function parseRequirementsTxtForSbom(filePath: string): Promise<{
  metadata: { name: string };
  components: Component[];
}> {
  const content = await fs.readFile(filePath, 'utf-8');
  const components: Component[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }

    // Handle: package==1.0.0, package>=1.0.0, package~=1.0.0, package[extra]==1.0.0
    const match = trimmed.match(/^([a-zA-Z0-9\-_]+)(?:\[.+\])?(?:[=<>~!]+(.+))?/);
    if (match) {
      const name = match[1];
      const version = match[2] || 'latest';
      components.push({
        type: 'library',
        name,
        version,
        purl: createPurl('pypi', name, version),
        externalReferences: [
          { type: 'website', url: `https://pypi.org/project/${name}/` },
        ],
      });
    }
  }

  return {
    metadata: { name: path.basename(path.dirname(filePath)) },
    components,
  };
}

async function parseGoModForSbom(filePath: string): Promise<{
  metadata: { name: string };
  components: Component[];
}> {
  const content = await fs.readFile(filePath, 'utf-8');
  const components: Component[] = [];

  // Get module name
  const moduleMatch = content.match(/^module\s+(\S+)/m);
  const moduleName = moduleMatch ? moduleMatch[1] : 'unknown';

  // Parse require block
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  if (requireBlock) {
    for (const line of requireBlock[1].split('\n')) {
      const match = line.trim().match(/^(\S+)\s+v?(\S+)/);
      if (match && !match[1].startsWith('//')) {
        components.push({
          type: 'library',
          name: match[1],
          version: match[2],
          purl: createPurl('golang', match[1], match[2]),
          externalReferences: [
            { type: 'website', url: `https://pkg.go.dev/${match[1]}` },
          ],
        });
      }
    }
  }

  // Single-line requires
  const singleRequires = content.matchAll(/require\s+(\S+)\s+v?(\S+)/g);
  for (const match of singleRequires) {
    components.push({
      type: 'library',
      name: match[1],
      version: match[2],
      purl: createPurl('golang', match[1], match[2]),
      externalReferences: [
        { type: 'website', url: `https://pkg.go.dev/${match[1]}` },
      ],
    });
  }

  return {
    metadata: { name: moduleName },
    components,
  };
}

async function parseCargoTomlForSbom(filePath: string): Promise<{
  metadata: { name: string; version?: string };
  components: Component[];
}> {
  const content = await fs.readFile(filePath, 'utf-8');
  const components: Component[] = [];

  // Get package name and version
  const nameMatch = content.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
  const versionMatch = content.match(/^\s*version\s*=\s*["']([^"']+)["']/m);

  // Parse dependencies
  const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
  if (depSection) {
    for (const line of depSection[1].split('\n')) {
      // Simple format: name = "version"
      let match = line.trim().match(/^([a-zA-Z0-9\-_]+)\s*=\s*["']([^"']+)["']/);
      if (match) {
        components.push({
          type: 'library',
          name: match[1],
          version: match[2],
          purl: createPurl('cargo', match[1], match[2]),
          externalReferences: [
            { type: 'website', url: `https://crates.io/crates/${match[1]}` },
          ],
        });
        continue;
      }

      // Complex format: name = { version = "x.y.z", ... }
      match = line.trim().match(/^([a-zA-Z0-9\-_]+)\s*=\s*\{.*version\s*=\s*["']([^"']+)["']/);
      if (match) {
        components.push({
          type: 'library',
          name: match[1],
          version: match[2],
          purl: createPurl('cargo', match[1], match[2]),
          externalReferences: [
            { type: 'website', url: `https://crates.io/crates/${match[1]}` },
          ],
        });
      }
    }
  }

  return {
    metadata: {
      name: nameMatch ? nameMatch[1] : 'unknown',
      version: versionMatch ? versionMatch[1] : undefined,
    },
    components,
  };
}

async function parsePomXmlForSbom(filePath: string): Promise<{
  metadata: { name: string; version?: string };
  components: Component[];
}> {
  const content = await fs.readFile(filePath, 'utf-8');
  const components: Component[] = [];

  // Simple XML parsing for dependencies
  const artifactId = content.match(/<artifactId>([^<]+)<\/artifactId>/);
  const version = content.match(/<version>([^<]+)<\/version>/);

  // Parse dependencies
  const depsSection = content.match(/<dependencies>([\s\S]*?)<\/dependencies>/);
  if (depsSection) {
    const depMatches = depsSection[1].matchAll(/<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g);

    for (const match of depMatches) {
      const groupId = match[1];
      const artifactId = match[2];
      const depVersion = match[3] || 'unknown';

      components.push({
        type: 'library',
        name: `${groupId}:${artifactId}`,
        version: depVersion,
        purl: `pkg:maven/${groupId}/${artifactId}@${depVersion}`,
        externalReferences: [
          { type: 'website', url: `https://mvnrepository.com/artifact/${groupId}/${artifactId}` },
        ],
      });
    }
  }

  return {
    metadata: {
      name: artifactId ? artifactId[1] : 'unknown',
      version: version ? version[1] : undefined,
    },
    components,
  };
}

export function registerGenerateSbomTool(server: McpServer): void {
  server.tool(
    'generate-sbom',
    'Generate a Software Bill of Materials (SBOM) in CycloneDX format for dependency tracking and security analysis',
    {
      target: z.string().describe('Project directory or dependency file path'),
      format: z.enum(['json', 'xml']).default('json').describe('Output format (json or xml)'),
      includeDevDeps: z.boolean().default(true).describe('Include development dependencies'),
    },
    async ({ target, format, includeDevDeps }) => {
      try {
        const stats = await fs.stat(target);
        let dependencyFile = '';
        let parseResult: {
          metadata: { name: string; version?: string; description?: string };
          components: Component[];
          lockFile?: string;
        };

        if (stats.isDirectory()) {
          const files = await fs.readdir(target);

          if (files.includes('package.json')) {
            dependencyFile = path.join(target, 'package.json');
            parseResult = await parsePackageJsonForSbom(dependencyFile);
          } else if (files.includes('requirements.txt')) {
            dependencyFile = path.join(target, 'requirements.txt');
            parseResult = await parseRequirementsTxtForSbom(dependencyFile);
          } else if (files.includes('go.mod')) {
            dependencyFile = path.join(target, 'go.mod');
            parseResult = await parseGoModForSbom(dependencyFile);
          } else if (files.includes('Cargo.toml')) {
            dependencyFile = path.join(target, 'Cargo.toml');
            parseResult = await parseCargoTomlForSbom(dependencyFile);
          } else if (files.includes('pom.xml')) {
            dependencyFile = path.join(target, 'pom.xml');
            parseResult = await parsePomXmlForSbom(dependencyFile);
          } else {
            return {
              isError: true,
              content: [{
                type: 'text' as const,
                text: 'No supported dependency file found (package.json, requirements.txt, go.mod, Cargo.toml, pom.xml)',
              }],
            };
          }
        } else {
          dependencyFile = target;
          const filename = path.basename(target);

          if (filename === 'package.json') {
            parseResult = await parsePackageJsonForSbom(target);
          } else if (filename === 'requirements.txt') {
            parseResult = await parseRequirementsTxtForSbom(target);
          } else if (filename === 'go.mod') {
            parseResult = await parseGoModForSbom(target);
          } else if (filename === 'Cargo.toml') {
            parseResult = await parseCargoTomlForSbom(target);
          } else if (filename === 'pom.xml') {
            parseResult = await parsePomXmlForSbom(target);
          } else {
            return {
              isError: true,
              content: [{
                type: 'text' as const,
                text: 'Unsupported dependency file format',
              }],
            };
          }
        }

        // Filter out dev dependencies if requested
        let components = parseResult.components;
        if (!includeDevDeps) {
          components = components.filter(c => c.scope !== 'optional');
        }

        // Create CycloneDX BOM
        const bom: CycloneDXBom = {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          serialNumber: generateUuid(),
          version: 1,
          metadata: {
            timestamp: new Date().toISOString(),
            tools: [
              {
                vendor: 'VulnScanner',
                name: 'vuln-scanner-mcp',
                version: '1.0.0',
              },
            ],
            component: {
              type: 'application',
              name: parseResult.metadata.name,
              version: parseResult.metadata.version,
            },
          },
          components,
        };

        let output: string;
        if (format === 'json') {
          output = JSON.stringify(bom, null, 2);
        } else {
          // Generate XML format
          output = generateCycloneDXXml(bom);
        }

        const summary = `# Software Bill of Materials (SBOM)

## Project Information
- **Name:** ${parseResult.metadata.name}
- **Version:** ${parseResult.metadata.version || 'N/A'}
- **Source File:** ${dependencyFile}
${parseResult.lockFile ? `- **Lock File:** ${parseResult.lockFile}` : ''}

## Statistics
- **Total Components:** ${components.length}
- **Production Dependencies:** ${components.filter(c => c.scope === 'required').length}
- **Development Dependencies:** ${components.filter(c => c.scope === 'optional').length}
- **Format:** CycloneDX ${bom.specVersion} (${format.toUpperCase()})
- **Serial Number:** ${bom.serialNumber}

## Components Summary
${components.slice(0, 20).map(c => `- ${c.name}@${c.version}`).join('\n')}
${components.length > 20 ? `\n... and ${components.length - 20} more components` : ''}

---

## Full SBOM (${format.toUpperCase()})

\`\`\`${format}
${output}
\`\`\``;

        return {
          content: [{
            type: 'text' as const,
            text: summary,
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error generating SBOM: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );
}

function generateCycloneDXXml(bom: CycloneDXBom): string {
  const escapeXml = (str: string): string => {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  };

  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="${bom.serialNumber}" version="${bom.version}">
  <metadata>
    <timestamp>${bom.metadata.timestamp}</timestamp>
    <tools>
      <tool>
        <vendor>VulnScanner</vendor>
        <name>vuln-scanner-mcp</name>
        <version>1.0.0</version>
      </tool>
    </tools>
    <component type="${bom.metadata.component?.type || 'application'}">
      <name>${escapeXml(bom.metadata.component?.name || 'unknown')}</name>
${bom.metadata.component?.version ? `      <version>${escapeXml(bom.metadata.component.version)}</version>` : ''}
    </component>
  </metadata>
  <components>`;

  for (const component of bom.components) {
    xml += `
    <component type="${component.type}">
      <name>${escapeXml(component.name)}</name>
      <version>${escapeXml(component.version)}</version>
${component.purl ? `      <purl>${escapeXml(component.purl)}</purl>` : ''}
${component.scope ? `      <scope>${component.scope}</scope>` : ''}
${component.externalReferences ? `      <externalReferences>
${component.externalReferences.map(ref => `        <reference type="${ref.type}">
          <url>${escapeXml(ref.url)}</url>
        </reference>`).join('\n')}
      </externalReferences>` : ''}
    </component>`;
  }

  xml += `
  </components>
</bom>`;

  return xml;
}
