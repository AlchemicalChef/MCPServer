import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' | 'none' };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
  };
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

function severityToLevel(severity: string): 'error' | 'warning' | 'note' | 'none' {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

function severityToScore(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '4.0';
    case 'low':
      return '2.0';
    default:
      return '0.0';
  }
}

interface ParsedFinding {
  id: string;
  name: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  cwe?: string;
  remediation?: string;
}

function parseFindings(rawFindings: string): ParsedFinding[] {
  const findings: ParsedFinding[] = [];

  // Parse various finding formats
  // Format 1: [SEVERITY] Name (ID)
  const pattern1 = /\[(\w+)\]\s+(.+?)\s+\(([A-Z]+-\d+)\)[\s\S]*?File:\s*([^:\n]+):(\d+)(?::(\d+))?[\s\S]*?(?:CWE[:\s]+)?([A-Z]+-\d+)?[\s\S]*?Description:\s*([^\n]+)[\s\S]*?(?:Remediation:\s*([^\n]+))?/gi;

  // Format 2: ## file:line sections
  const pattern2 = /##\s+([^:\n]+):(\d+)[\s\S]*?(?:Match|Context):\s*([^\n]+)/gi;

  // Try pattern 1 first
  let match;
  while ((match = pattern1.exec(rawFindings)) !== null) {
    findings.push({
      severity: match[1],
      name: match[2],
      id: match[3],
      file: match[4],
      line: parseInt(match[5], 10),
      column: match[6] ? parseInt(match[6], 10) : undefined,
      cwe: match[7],
      description: match[8],
      remediation: match[9],
    });
  }

  // If no findings from pattern 1, try simpler parsing
  if (findings.length === 0) {
    // Look for any structured data
    const lines = rawFindings.split('\n');
    let currentFinding: Partial<ParsedFinding> = {};

    for (const line of lines) {
      // Check for severity indicators
      const sevMatch = line.match(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i);
      if (sevMatch) {
        if (currentFinding.id) {
          findings.push(currentFinding as ParsedFinding);
        }
        currentFinding = { severity: sevMatch[1] };
      }

      // Check for ID
      const idMatch = line.match(/([A-Z]+-\d+)/);
      if (idMatch && !currentFinding.id) {
        currentFinding.id = idMatch[1];
      }

      // Check for file:line
      const fileMatch = line.match(/(?:File|Location):\s*([^:\s]+):(\d+)/i);
      if (fileMatch) {
        currentFinding.file = fileMatch[1];
        currentFinding.line = parseInt(fileMatch[2], 10);
      }

      // Check for description
      const descMatch = line.match(/(?:Description|Message):\s*(.+)/i);
      if (descMatch) {
        currentFinding.description = descMatch[1];
      }

      // Check for CWE
      const cweMatch = line.match(/(CWE-\d+)/i);
      if (cweMatch) {
        currentFinding.cwe = cweMatch[1];
      }
    }

    // Push last finding
    if (currentFinding.id && currentFinding.file && currentFinding.line) {
      findings.push(currentFinding as ParsedFinding);
    }
  }

  return findings;
}

export function registerExportSarifTool(server: McpServer): void {
  server.tool(
    'export-sarif',
    'Convert vulnerability findings to SARIF v2.1.0 format for CI/CD integration',
    {
      findings: z.string().describe('Raw vulnerability findings text to convert'),
      toolName: z.string().default('vuln-scanner-mcp').describe('Name of the scanning tool'),
      toolVersion: z.string().default('1.0.0').describe('Version of the scanning tool'),
    },
    async ({ findings, toolName, toolVersion }) => {
      const parsedFindings = parseFindings(findings);

      if (parsedFindings.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `No findings could be parsed from the input. Please ensure findings follow a structured format with severity, ID, file, and line information.`,
          }],
          isError: true,
        };
      }

      // Build rules from unique finding types
      const rulesMap = new Map<string, SarifRule>();
      for (const finding of parsedFindings) {
        if (!rulesMap.has(finding.id)) {
          const tags = ['security'];
          if (finding.cwe) {
            tags.push(`external/cwe/${finding.cwe.toLowerCase()}`);
          }

          rulesMap.set(finding.id, {
            id: finding.id,
            name: finding.name || finding.id,
            shortDescription: { text: finding.name || finding.id },
            fullDescription: finding.description ? { text: finding.description } : undefined,
            help: finding.remediation
              ? { text: finding.remediation, markdown: `**Remediation:** ${finding.remediation}` }
              : undefined,
            defaultConfiguration: { level: severityToLevel(finding.severity) },
            properties: {
              tags,
              precision: 'high',
              'security-severity': severityToScore(finding.severity),
            },
          });
        }
      }

      // Build results
      const results: SarifResult[] = parsedFindings.map(finding => ({
        ruleId: finding.id,
        level: severityToLevel(finding.severity),
        message: { text: finding.description || finding.name || 'Security issue detected' },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.file },
            region: {
              startLine: finding.line,
              startColumn: finding.column,
            },
          },
        }],
      }));

      const sarifReport: SarifReport = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: toolName,
              version: toolVersion,
              informationUri: 'https://github.com/modelcontextprotocol',
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
        }],
      };

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify(sarifReport, null, 2),
        }],
      };
    }
  );
}
