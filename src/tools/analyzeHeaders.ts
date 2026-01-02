import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

interface HeaderCheck {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
  validate: (value: string | undefined) => { passed: boolean; message: string };
}

const securityHeaders: HeaderCheck[] = [
  {
    name: 'Strict-Transport-Security',
    severity: 'high',
    description: 'HSTS ensures browsers only connect via HTTPS, preventing downgrade attacks.',
    recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Site vulnerable to SSL stripping attacks.' };
      }
      const maxAge = value.match(/max-age=(\d+)/i);
      if (!maxAge || parseInt(maxAge[1], 10) < 31536000) {
        return { passed: false, message: 'max-age should be at least 31536000 (1 year).' };
      }
      if (!value.toLowerCase().includes('includesubdomains')) {
        return { passed: false, message: 'Missing includeSubDomains directive.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Content-Security-Policy',
    severity: 'high',
    description: 'CSP prevents XSS and data injection attacks by controlling resource loading.',
    recommendation: "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'",
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Site vulnerable to XSS attacks.' };
      }
      const issues: string[] = [];
      if (value.includes("'unsafe-inline'")) {
        issues.push("Contains 'unsafe-inline' which weakens XSS protection.");
      }
      if (value.includes("'unsafe-eval'")) {
        issues.push("Contains 'unsafe-eval' which allows eval() execution.");
      }
      if (value.includes('*')) {
        issues.push('Contains wildcard (*) which is overly permissive.');
      }
      if (!value.includes('default-src')) {
        issues.push('Missing default-src directive.');
      }
      if (issues.length > 0) {
        return { passed: false, message: issues.join(' ') };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    description: 'Prevents MIME type sniffing which can lead to security vulnerabilities.',
    recommendation: 'X-Content-Type-Options: nosniff',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Browser may MIME-sniff responses.' };
      }
      if (value.toLowerCase() !== 'nosniff') {
        return { passed: false, message: 'Value should be "nosniff".' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'X-Frame-Options',
    severity: 'medium',
    description: 'Prevents clickjacking attacks by controlling if page can be framed.',
    recommendation: 'X-Frame-Options: DENY or SAMEORIGIN',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Site may be vulnerable to clickjacking.' };
      }
      const normalized = value.toLowerCase();
      if (normalized !== 'deny' && normalized !== 'sameorigin') {
        if (normalized.startsWith('allow-from')) {
          return { passed: false, message: 'ALLOW-FROM is deprecated. Use CSP frame-ancestors instead.' };
        }
        return { passed: false, message: 'Value should be DENY or SAMEORIGIN.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'X-XSS-Protection',
    severity: 'low',
    description: 'Legacy XSS filter. Modern browsers prefer CSP but this provides defense in depth.',
    recommendation: 'X-XSS-Protection: 1; mode=block (or 0 if CSP is properly configured)',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Consider adding for legacy browser support.' };
      }
      if (value === '0') {
        return { passed: true, message: 'Disabled. OK if CSP is properly configured.' };
      }
      if (!value.includes('mode=block')) {
        return { passed: false, message: 'Should include mode=block to prevent unsafe sanitization.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Referrer-Policy',
    severity: 'medium',
    description: 'Controls how much referrer information is sent with requests.',
    recommendation: 'Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Full URL may leak in referrer.' };
      }
      const secure = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
      const insecure = ['unsafe-url', 'no-referrer-when-downgrade'];
      const normalized = value.toLowerCase();
      if (insecure.includes(normalized)) {
        return { passed: false, message: `"${value}" may leak sensitive URL data.` };
      }
      if (!secure.includes(normalized)) {
        return { passed: false, message: `Unknown value. Use: ${secure.join(', ')}` };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Permissions-Policy',
    severity: 'medium',
    description: 'Controls which browser features can be used (geolocation, camera, etc.).',
    recommendation: 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. All browser features allowed by default.' };
      }
      // Check for overly permissive policies
      if (value.includes('*')) {
        return { passed: false, message: 'Contains wildcard (*) which is overly permissive.' };
      }
      return { passed: true, message: 'Configured. Review directives for your requirements.' };
    },
  },
  {
    name: 'Cache-Control',
    severity: 'medium',
    description: 'Controls caching behavior. Sensitive pages should not be cached.',
    recommendation: 'Cache-Control: no-store, no-cache, must-revalidate (for sensitive pages)',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Default caching behavior applies.' };
      }
      const hasNoStore = value.toLowerCase().includes('no-store');
      const isPublic = value.toLowerCase().includes('public');
      if (isPublic) {
        return { passed: false, message: 'Using "public" may cache sensitive data. Use "private" or "no-store" for sensitive pages.' };
      }
      if (!hasNoStore) {
        return { passed: true, message: 'Review if no-store is needed for sensitive pages.' };
      }
      return { passed: true, message: 'Properly configured for sensitive content.' };
    },
  },
  {
    name: 'X-Permitted-Cross-Domain-Policies',
    severity: 'low',
    description: 'Controls Adobe Flash/PDF cross-domain requests.',
    recommendation: 'X-Permitted-Cross-Domain-Policies: none',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Flash/PDF may make cross-domain requests.' };
      }
      if (value.toLowerCase() !== 'none') {
        return { passed: false, message: 'Value should be "none" unless cross-domain Flash/PDF is needed.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    severity: 'medium',
    description: 'Controls embedding of cross-origin resources. Required for SharedArrayBuffer.',
    recommendation: 'Cross-Origin-Embedder-Policy: require-corp',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Cross-origin isolation not enabled.' };
      }
      if (value.toLowerCase() === 'unsafe-none') {
        return { passed: false, message: '"unsafe-none" disables protection.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    severity: 'medium',
    description: 'Isolates browsing context from cross-origin documents.',
    recommendation: 'Cross-Origin-Opener-Policy: same-origin',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Browsing context not isolated.' };
      }
      if (value.toLowerCase() === 'unsafe-none') {
        return { passed: false, message: '"unsafe-none" disables protection.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    severity: 'medium',
    description: 'Controls which origins can embed this resource.',
    recommendation: 'Cross-Origin-Resource-Policy: same-origin',
    validate: (value) => {
      if (!value) {
        return { passed: false, message: 'Header missing. Resource may be embedded cross-origin.' };
      }
      if (value.toLowerCase() === 'cross-origin') {
        return { passed: false, message: '"cross-origin" allows any origin to embed this resource.' };
      }
      return { passed: true, message: 'Properly configured.' };
    },
  },
];

export function registerAnalyzeHeadersTool(server: McpServer): void {
  server.tool(
    'analyze-headers',
    'Analyze HTTP response headers for security best practices',
    {
      headers: z.record(z.string()).describe('HTTP headers as key-value pairs (e.g., {"Content-Security-Policy": "default-src self"})'),
      context: z.enum(['api', 'webapp', 'static']).default('webapp')
        .describe('Type of endpoint being analyzed'),
    },
    async ({ headers, context }) => {
      // Sanitize header values
      const sanitizedHeaders: Record<string, string> = {};
      const allWarnings: string[] = [];
      for (const [key, value] of Object.entries(headers)) {
        sanitizedHeaders[sanitize(key)] = sanitize(value);
        const validation = validateInput(value);
        if (!validation.safe) {
          allWarnings.push(...validation.warnings);
        }
      }

      // Audit log
      logToolInvocation('analyze-headers', { headerCount: Object.keys(headers).length, context }, allWarnings);

      const results: Array<{
        header: string;
        severity: string;
        status: 'pass' | 'fail' | 'warn';
        message: string;
        recommendation: string;
      }> = [];

      // Normalize header names to handle case variations
      const normalizedHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(headers)) {
        normalizedHeaders[key.toLowerCase()] = value;
      }

      for (const check of securityHeaders) {
        const headerValue = normalizedHeaders[check.name.toLowerCase()];
        const validation = check.validate(headerValue);

        results.push({
          header: check.name,
          severity: check.severity,
          status: validation.passed ? 'pass' : 'fail',
          message: validation.message,
          recommendation: check.recommendation,
        });
      }

      // Additional context-specific checks
      if (context === 'api') {
        // APIs should have CORS headers configured properly
        const cors = normalizedHeaders['access-control-allow-origin'];
        if (cors === '*') {
          results.push({
            header: 'Access-Control-Allow-Origin',
            severity: 'high',
            status: 'fail',
            message: 'Wildcard (*) CORS allows requests from any origin.',
            recommendation: 'Specify allowed origins explicitly or use credentials-based CORS.',
          });
        }

        const corsCredentials = normalizedHeaders['access-control-allow-credentials'];
        if (corsCredentials === 'true' && cors === '*') {
          results.push({
            header: 'CORS Configuration',
            severity: 'critical',
            status: 'fail',
            message: 'Credentials allowed with wildcard origin is invalid and dangerous.',
            recommendation: 'Specify exact origin when using credentials.',
          });
        }
      }

      // Check for information disclosure headers
      const serverHeader = normalizedHeaders['server'];
      if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
        results.push({
          header: 'Server',
          severity: 'low',
          status: 'warn',
          message: `Server version disclosed: "${serverHeader}"`,
          recommendation: 'Remove or minimize server version information.',
        });
      }

      const poweredBy = normalizedHeaders['x-powered-by'];
      if (poweredBy) {
        results.push({
          header: 'X-Powered-By',
          severity: 'low',
          status: 'warn',
          message: `Technology stack disclosed: "${poweredBy}"`,
          recommendation: 'Remove X-Powered-By header to reduce information leakage.',
        });
      }

      // Calculate score
      const totalChecks = results.length;
      const passed = results.filter(r => r.status === 'pass').length;
      const failed = results.filter(r => r.status === 'fail').length;
      const criticalFailed = results.filter(r => r.status === 'fail' && r.severity === 'critical').length;
      const highFailed = results.filter(r => r.status === 'fail' && r.severity === 'high').length;

      let grade: string;
      const score = Math.round((passed / totalChecks) * 100);
      if (criticalFailed > 0) grade = 'F';
      else if (highFailed > 1) grade = 'D';
      else if (highFailed > 0 || score < 50) grade = 'C';
      else if (score < 70) grade = 'B';
      else if (score < 90) grade = 'A';
      else grade = 'A+';

      const failedResults = results.filter(r => r.status === 'fail');
      const passedResults = results.filter(r => r.status === 'pass');
      const warnResults = results.filter(r => r.status === 'warn');

      const formatResult = (r: typeof results[0]) =>
        `### ${r.header}
**Severity:** ${r.severity.toUpperCase()}
**Status:** ${r.status.toUpperCase()}
**Finding:** ${r.message}
**Recommendation:** ${r.recommendation}`;

      logOutput('analyze-headers', {
        success: true,
        summary: `Grade: ${grade}, Score: ${score}%`,
        metrics: { grade, score, passed, failed, warnings: warnResults.length },
      });
      return {
        content: [{
          type: 'text' as const,
          text: `# HTTP Security Headers Analysis

## Summary
- **Grade:** ${grade}
- **Score:** ${score}%
- **Context:** ${context}
- **Passed:** ${passed}/${totalChecks}
- **Failed:** ${failed}
- **Warnings:** ${warnResults.length}

---

## Failed Checks (${failedResults.length})

${failedResults.length > 0 ? failedResults.map(formatResult).join('\n\n---\n\n') : 'None'}

---

## Warnings (${warnResults.length})

${warnResults.length > 0 ? warnResults.map(formatResult).join('\n\n---\n\n') : 'None'}

---

## Passed Checks (${passedResults.length})

${passedResults.map(r => `- **${r.header}**: ${r.message}`).join('\n')}
`,
        }],
      };
    }
  );
}
