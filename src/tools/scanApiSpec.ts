import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

interface ApiSecurityFinding {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  path?: string;
  method?: string;
  description: string;
  remediation: string;
  owasp?: string;
}

interface OpenApiSpec {
  openapi?: string;
  swagger?: string;
  info?: {
    title?: string;
    version?: string;
  };
  servers?: Array<{ url: string }>;
  paths?: Record<string, Record<string, {
    security?: Array<Record<string, string[]>>;
    parameters?: Array<{
      name: string;
      in: string;
      schema?: { type?: string };
    }>;
    requestBody?: {
      content?: Record<string, unknown>;
    };
    responses?: Record<string, unknown>;
  }>>;
  components?: {
    securitySchemes?: Record<string, {
      type: string;
      scheme?: string;
      bearerFormat?: string;
      flows?: Record<string, unknown>;
    }>;
  };
  security?: Array<Record<string, string[]>>;
}

function analyzeOpenApiSpec(spec: OpenApiSpec): ApiSecurityFinding[] {
  const findings: ApiSecurityFinding[] = [];

  // Check for version
  const version = spec.openapi || spec.swagger;
  if (spec.swagger) {
    findings.push({
      id: 'API-001',
      name: 'Outdated OpenAPI Version',
      severity: 'low',
      description: `Using Swagger ${spec.swagger}. OpenAPI 3.x is recommended.`,
      remediation: 'Migrate to OpenAPI 3.0 or 3.1 specification.',
    });
  }

  // Check for global security
  if (!spec.security || spec.security.length === 0) {
    findings.push({
      id: 'API-002',
      name: 'No Global Security Defined',
      severity: 'high',
      description: 'No global security requirements defined. Endpoints may be unprotected.',
      remediation: 'Add global security requirement: security: [{ bearerAuth: [] }]',
      owasp: 'API2:2023 - Broken Authentication',
    });
  }

  // Check security schemes
  const securitySchemes = spec.components?.securitySchemes || {};
  const schemeNames = Object.keys(securitySchemes);

  if (schemeNames.length === 0 && !spec.security) {
    findings.push({
      id: 'API-003',
      name: 'No Security Schemes Defined',
      severity: 'critical',
      description: 'No authentication mechanisms defined in the API specification.',
      remediation: 'Define security schemes in components.securitySchemes (OAuth2, Bearer, API Key, etc.)',
      owasp: 'API2:2023 - Broken Authentication',
    });
  }

  // Check for basic auth (weak)
  for (const [name, scheme] of Object.entries(securitySchemes)) {
    if (scheme.type === 'http' && scheme.scheme === 'basic') {
      findings.push({
        id: 'API-004',
        name: 'Basic Authentication Used',
        severity: 'medium',
        description: `Security scheme "${name}" uses Basic authentication which transmits credentials with every request.`,
        remediation: 'Use OAuth2, JWT Bearer tokens, or API keys instead of Basic auth.',
        owasp: 'API2:2023 - Broken Authentication',
      });
    }
  }

  // Check servers for HTTP (non-HTTPS)
  const servers = spec.servers || [];
  for (const server of servers) {
    if (server.url && server.url.startsWith('http://') && !server.url.includes('localhost')) {
      findings.push({
        id: 'API-005',
        name: 'Non-HTTPS Server URL',
        severity: 'high',
        description: `Server "${server.url}" uses HTTP instead of HTTPS.`,
        remediation: 'Use HTTPS for all server URLs to ensure transport security.',
        owasp: 'API7:2023 - Security Misconfiguration',
      });
    }
  }

  // Analyze paths and operations
  const paths = spec.paths || {};
  const globalSecurity = spec.security || [];

  for (const [pathUrl, pathItem] of Object.entries(paths)) {
    const methods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

    for (const method of methods) {
      const operation = pathItem[method as keyof typeof pathItem];
      if (!operation || typeof operation !== 'object') continue;

      const op = operation as {
        security?: Array<Record<string, string[]>>;
        parameters?: Array<{ name: string; in: string; schema?: { type?: string } }>;
        requestBody?: { content?: Record<string, unknown> };
      };

      // Check for operation-level security override
      const operationSecurity = op.security;
      const hasSecurityDisabled = operationSecurity && operationSecurity.length === 1 &&
        Object.keys(operationSecurity[0]).length === 0;

      if (hasSecurityDisabled && globalSecurity.length > 0) {
        // Security explicitly disabled for this endpoint
        if (!pathUrl.includes('health') && !pathUrl.includes('public') && !pathUrl.includes('docs')) {
          findings.push({
            id: 'API-006',
            name: 'Security Disabled for Endpoint',
            severity: 'high',
            path: pathUrl,
            method: method.toUpperCase(),
            description: 'Security explicitly disabled for this endpoint (empty security array).',
            remediation: 'Review if this endpoint should be public. Add security if authentication is needed.',
            owasp: 'API1:2023 - Broken Object Level Authorization',
          });
        }
      }

      // Check for sensitive data in query parameters
      const parameters = op.parameters || [];
      for (const param of parameters) {
        if (param.in === 'query') {
          const sensitiveNames = ['password', 'secret', 'token', 'key', 'apikey', 'api_key', 'auth', 'credential'];
          if (sensitiveNames.some(s => param.name.toLowerCase().includes(s))) {
            findings.push({
              id: 'API-007',
              name: 'Sensitive Data in Query Parameter',
              severity: 'high',
              path: pathUrl,
              method: method.toUpperCase(),
              description: `Parameter "${param.name}" may contain sensitive data but is sent in query string (visible in logs/URLs).`,
              remediation: 'Move sensitive parameters to request body or headers.',
              owasp: 'API3:2023 - Broken Object Property Level Authorization',
            });
          }
        }
      }

      // Check for potential mass assignment (POST/PUT/PATCH without specific schema)
      if (['post', 'put', 'patch'].includes(method)) {
        const requestBody = op.requestBody;
        if (requestBody?.content) {
          const jsonContent = requestBody.content['application/json'] as { schema?: { type?: string; additionalProperties?: boolean } } | undefined;
          if (jsonContent?.schema?.additionalProperties === true) {
            findings.push({
              id: 'API-008',
              name: 'Potential Mass Assignment',
              severity: 'medium',
              path: pathUrl,
              method: method.toUpperCase(),
              description: 'Schema allows additional properties which may enable mass assignment attacks.',
              remediation: 'Set additionalProperties: false or explicitly define all allowed properties.',
              owasp: 'API3:2023 - Broken Object Property Level Authorization',
            });
          }
        }
      }

      // Check for ID in path (potential BOLA/IDOR)
      if (pathUrl.match(/\{.*id.*\}/i)) {
        const effectiveSecurity = operationSecurity || globalSecurity;
        if (effectiveSecurity.length === 0) {
          findings.push({
            id: 'API-009',
            name: 'Object ID Access Without Authentication',
            severity: 'critical',
            path: pathUrl,
            method: method.toUpperCase(),
            description: 'Endpoint with object ID parameter has no authentication, risking BOLA/IDOR attacks.',
            remediation: 'Add authentication and implement proper authorization checks.',
            owasp: 'API1:2023 - Broken Object Level Authorization',
          });
        }
      }

      // Check DELETE without auth
      if (method === 'delete') {
        const effectiveSecurity = operationSecurity || globalSecurity;
        if (effectiveSecurity.length === 0) {
          findings.push({
            id: 'API-010',
            name: 'DELETE Without Authentication',
            severity: 'critical',
            path: pathUrl,
            method: 'DELETE',
            description: 'DELETE operation has no authentication requirement.',
            remediation: 'Add authentication and authorization for destructive operations.',
            owasp: 'API5:2023 - Broken Function Level Authorization',
          });
        }
      }
    }

    // Check for missing rate limiting indicators
    // (Note: OpenAPI doesn't have standard rate limit definition, checking for x-extensions)
  }

  // Check for admin/internal paths without extra security
  const sensitivePathPatterns = ['/admin', '/internal', '/management', '/actuator', '/debug'];
  for (const pathUrl of Object.keys(paths)) {
    for (const pattern of sensitivePathPatterns) {
      if (pathUrl.toLowerCase().includes(pattern)) {
        findings.push({
          id: 'API-011',
          name: 'Sensitive Path Exposed',
          severity: 'medium',
          path: pathUrl,
          description: `Path "${pathUrl}" appears to be an administrative/internal endpoint. Ensure extra security controls.`,
          remediation: 'Add additional authentication (admin role), consider removing from public API docs.',
          owasp: 'API5:2023 - Broken Function Level Authorization',
        });
        break;
      }
    }
  }

  return findings;
}

export function registerScanApiSpecTool(server: McpServer): void {
  server.tool(
    'scan-api-spec',
    'Scan OpenAPI/Swagger specifications for security vulnerabilities (OWASP API Top 10)',
    {
      target: z.string().describe('Path to OpenAPI/Swagger spec file (JSON or YAML)'),
    },
    async ({ target }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-api-spec', { target }, validation.warnings);

      try {
        const content = await fs.readFile(sanitizedTarget, 'utf-8');
        let spec: OpenApiSpec;

        // Parse JSON or YAML
        if (target.endsWith('.json')) {
          spec = JSON.parse(content);
        } else {
          // Simple YAML parsing (basic support)
          // For full YAML support, would need js-yaml package
          try {
            spec = JSON.parse(content);
          } catch {
            logOutput('scan-api-spec', {
              success: false,
              error: 'YAML parsing not fully supported',
            });
            return {
              isError: true,
              content: [{
                type: 'text' as const,
                text: 'YAML parsing not fully supported. Please convert to JSON or install js-yaml package.',
              }],
            };
          }
        }

        const findings = analyzeOpenApiSpec(spec);

        if (findings.length === 0) {
          logOutput('scan-api-spec', {
            success: true,
            summary: 'No security issues found',
          });
          return {
            content: [{
              type: 'text' as const,
              text: `# API Security Scan Results

**File:** ${target}
**API:** ${spec.info?.title || 'Unknown'} v${spec.info?.version || '?'}
**Spec Version:** ${spec.openapi || spec.swagger || 'Unknown'}

## Summary
No security issues found.

The API specification follows security best practices.`,
            }],
          };
        }

        // Sort by severity
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        findings.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));

        const summary = {
          critical: findings.filter(f => f.severity === 'critical').length,
          high: findings.filter(f => f.severity === 'high').length,
          medium: findings.filter(f => f.severity === 'medium').length,
          low: findings.filter(f => f.severity === 'low').length,
        };

        const report = findings.map(f =>
          `### [${f.severity.toUpperCase()}] ${f.name} (${f.id})
${f.path ? `**Endpoint:** ${f.method || ''} ${f.path}` : ''}
${f.owasp ? `**OWASP:** ${f.owasp}` : ''}
**Issue:** ${f.description}
**Fix:** ${f.remediation}`
        ).join('\n\n---\n\n');

        logOutput('scan-api-spec', {
          success: true,
          summary: `Found ${findings.length} issues`,
          metrics: { critical: summary.critical, high: summary.high, medium: summary.medium, low: summary.low, total: findings.length },
        });
        return {
          content: [{
            type: 'text' as const,
            text: `# API Security Scan Results

**File:** ${target}
**API:** ${spec.info?.title || 'Unknown'} v${spec.info?.version || '?'}
**Spec Version:** ${spec.openapi || spec.swagger || 'Unknown'}

## Summary
- **Total issues:** ${findings.length}
  - Critical: ${summary.critical}
  - High: ${summary.high}
  - Medium: ${summary.medium}
  - Low: ${summary.low}

## Findings

${report}`,
          }],
        };
      } catch (error) {
        logOutput('scan-api-spec', {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error scanning API spec: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );
}
