import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation } from '../utils/auditLog.js';

// CVSS v3.1 Constants
const CVSS_WEIGHTS = {
  // Attack Vector
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  // Attack Complexity
  AC: { L: 0.77, H: 0.44 },
  // Privileges Required
  PR: {
    unchanged: { N: 0.85, L: 0.62, H: 0.27 },
    changed: { N: 0.85, L: 0.68, H: 0.5 },
  },
  // User Interaction
  UI: { N: 0.85, R: 0.62 },
  // Scope
  S: { U: 'unchanged', C: 'changed' },
  // Impact metrics
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

interface CvssMetrics {
  attackVector: 'N' | 'A' | 'L' | 'P';
  attackComplexity: 'L' | 'H';
  privilegesRequired: 'N' | 'L' | 'H';
  userInteraction: 'N' | 'R';
  scope: 'U' | 'C';
  confidentialityImpact: 'H' | 'L' | 'N';
  integrityImpact: 'H' | 'L' | 'N';
  availabilityImpact: 'H' | 'L' | 'N';
}

interface CvssResult {
  score: number;
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  vector: string;
  breakdown: {
    exploitability: number;
    impact: number;
  };
}

function calculateCvss31(metrics: CvssMetrics): CvssResult {
  const { attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact } = metrics;

  // Exploitability sub-score
  const scopeKey = scope === 'C' ? 'changed' : 'unchanged';
  const exploitability =
    8.22 *
    CVSS_WEIGHTS.AV[attackVector] *
    CVSS_WEIGHTS.AC[attackComplexity] *
    CVSS_WEIGHTS.PR[scopeKey][privilegesRequired] *
    CVSS_WEIGHTS.UI[userInteraction];

  // Impact sub-score
  const iscBase =
    1 -
    (1 - CVSS_WEIGHTS.CIA[confidentialityImpact]) *
      (1 - CVSS_WEIGHTS.CIA[integrityImpact]) *
      (1 - CVSS_WEIGHTS.CIA[availabilityImpact]);

  let impact: number;
  if (scope === 'U') {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  // Calculate base score
  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (scope === 'U') {
    score = Math.min(exploitability + impact, 10);
  } else {
    score = Math.min(1.08 * (exploitability + impact), 10);
  }

  // Round up to 1 decimal place
  score = Math.ceil(score * 10) / 10;

  // Determine severity
  let severity: CvssResult['severity'];
  if (score === 0) severity = 'None';
  else if (score <= 3.9) severity = 'Low';
  else if (score <= 6.9) severity = 'Medium';
  else if (score <= 8.9) severity = 'High';
  else severity = 'Critical';

  // Generate vector string
  const vector = `CVSS:3.1/AV:${attackVector}/AC:${attackComplexity}/PR:${privilegesRequired}/UI:${userInteraction}/S:${scope}/C:${confidentialityImpact}/I:${integrityImpact}/A:${availabilityImpact}`;

  return {
    score,
    severity,
    vector,
    breakdown: {
      exploitability: Math.round(exploitability * 100) / 100,
      impact: Math.round(impact * 100) / 100,
    },
  };
}

function parseVectorString(vector: string): CvssMetrics | null {
  const regex = /CVSS:3\.[01]\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([HLN])\/I:([HLN])\/A:([HLN])/;
  const match = vector.match(regex);

  if (!match) return null;

  return {
    attackVector: match[1] as CvssMetrics['attackVector'],
    attackComplexity: match[2] as CvssMetrics['attackComplexity'],
    privilegesRequired: match[3] as CvssMetrics['privilegesRequired'],
    userInteraction: match[4] as CvssMetrics['userInteraction'],
    scope: match[5] as CvssMetrics['scope'],
    confidentialityImpact: match[6] as CvssMetrics['confidentialityImpact'],
    integrityImpact: match[7] as CvssMetrics['integrityImpact'],
    availabilityImpact: match[8] as CvssMetrics['availabilityImpact'],
  };
}

// Common vulnerability type presets
const VULNERABILITY_PRESETS: Record<string, CvssMetrics> = {
  'sql-injection': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'H',
    availabilityImpact: 'H',
  },
  'xss-stored': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'L',
    userInteraction: 'R',
    scope: 'C',
    confidentialityImpact: 'L',
    integrityImpact: 'L',
    availabilityImpact: 'N',
  },
  'xss-reflected': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'R',
    scope: 'C',
    confidentialityImpact: 'L',
    integrityImpact: 'L',
    availabilityImpact: 'N',
  },
  'command-injection': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'H',
    availabilityImpact: 'H',
  },
  'path-traversal': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'N',
    availabilityImpact: 'N',
  },
  'idor': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'L',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'L',
    availabilityImpact: 'N',
  },
  'ssrf': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'C',
    confidentialityImpact: 'L',
    integrityImpact: 'N',
    availabilityImpact: 'N',
  },
  'csrf': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'R',
    scope: 'U',
    confidentialityImpact: 'N',
    integrityImpact: 'L',
    availabilityImpact: 'N',
  },
  'authentication-bypass': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'H',
    availabilityImpact: 'N',
  },
  'hardcoded-credentials': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'H',
    availabilityImpact: 'H',
  },
  'weak-cryptography': {
    attackVector: 'N',
    attackComplexity: 'H',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'N',
    availabilityImpact: 'N',
  },
  'deserialization': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'H',
    availabilityImpact: 'H',
  },
  'xxe': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'H',
    integrityImpact: 'N',
    availabilityImpact: 'N',
  },
  'open-redirect': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'R',
    scope: 'U',
    confidentialityImpact: 'N',
    integrityImpact: 'L',
    availabilityImpact: 'N',
  },
  'information-disclosure': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'L',
    integrityImpact: 'N',
    availabilityImpact: 'N',
  },
  'dos': {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentialityImpact: 'N',
    integrityImpact: 'N',
    availabilityImpact: 'H',
  },
};

const metricDescriptions = {
  attackVector: {
    N: 'Network - Exploitable remotely',
    A: 'Adjacent - Requires adjacent network access',
    L: 'Local - Requires local access',
    P: 'Physical - Requires physical access',
  },
  attackComplexity: {
    L: 'Low - No specialized conditions',
    H: 'High - Requires specific conditions',
  },
  privilegesRequired: {
    N: 'None - No privileges required',
    L: 'Low - Requires basic user privileges',
    H: 'High - Requires admin/elevated privileges',
  },
  userInteraction: {
    N: 'None - No user interaction required',
    R: 'Required - Requires user action',
  },
  scope: {
    U: 'Unchanged - Impact limited to vulnerable component',
    C: 'Changed - Can impact other components',
  },
  impactRating: {
    H: 'High - Total compromise',
    L: 'Low - Limited impact',
    N: 'None - No impact',
  },
};

export function registerCalculateCvssTool(server: McpServer): void {
  server.tool(
    'calculate-cvss',
    'Calculate CVSS v3.1 scores for vulnerabilities with detailed breakdown and severity classification',
    {
      // Option 1: Use preset
      preset: z
        .enum([
          'sql-injection',
          'xss-stored',
          'xss-reflected',
          'command-injection',
          'path-traversal',
          'idor',
          'ssrf',
          'csrf',
          'authentication-bypass',
          'hardcoded-credentials',
          'weak-cryptography',
          'deserialization',
          'xxe',
          'open-redirect',
          'information-disclosure',
          'dos',
        ])
        .optional()
        .describe('Use a preset vulnerability type'),

      // Option 2: Parse vector string
      vector: z.string().optional().describe('CVSS v3.1 vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)'),

      // Option 3: Individual metrics
      attackVector: z.enum(['N', 'A', 'L', 'P']).optional().describe('Attack Vector: N=Network, A=Adjacent, L=Local, P=Physical'),
      attackComplexity: z.enum(['L', 'H']).optional().describe('Attack Complexity: L=Low, H=High'),
      privilegesRequired: z.enum(['N', 'L', 'H']).optional().describe('Privileges Required: N=None, L=Low, H=High'),
      userInteraction: z.enum(['N', 'R']).optional().describe('User Interaction: N=None, R=Required'),
      scope: z.enum(['U', 'C']).optional().describe('Scope: U=Unchanged, C=Changed'),
      confidentialityImpact: z.enum(['H', 'L', 'N']).optional().describe('Confidentiality Impact: H=High, L=Low, N=None'),
      integrityImpact: z.enum(['H', 'L', 'N']).optional().describe('Integrity Impact: H=High, L=Low, N=None'),
      availabilityImpact: z.enum(['H', 'L', 'N']).optional().describe('Availability Impact: H=High, L=Low, N=None'),

      // Additional options
      showDetails: z.boolean().default(true).describe('Show detailed metric explanations'),
      listPresets: z.boolean().default(false).describe('List all available presets with their scores'),
    },
    async ({
      preset,
      vector,
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
      scope,
      confidentialityImpact,
      integrityImpact,
      availabilityImpact,
      showDetails,
      listPresets,
    }) => {
      // Audit log
      logToolInvocation('calculate-cvss', { preset, vector, listPresets }, []);

      // List presets mode
      if (listPresets) {
        const presetResults = Object.entries(VULNERABILITY_PRESETS).map(([name, metrics]) => {
          const result = calculateCvss31(metrics);
          return { name, ...result };
        });

        presetResults.sort((a, b) => b.score - a.score);

        const presetList = presetResults
          .map(p => `| ${p.name.padEnd(25)} | ${p.score.toFixed(1).padStart(4)} | ${p.severity.padEnd(8)} | \`${p.vector}\` |`)
          .join('\n');

        return {
          content: [{
            type: 'text' as const,
            text: `# CVSS v3.1 Vulnerability Presets

| Vulnerability Type        | Score | Severity | Vector |
|--------------------------|-------|----------|--------|
${presetList}

Use \`preset: "vulnerability-type"\` to calculate score for a specific type.`,
          }],
        };
      }

      let metrics: CvssMetrics | null = null;

      // Priority: preset > vector > individual metrics
      if (preset) {
        metrics = VULNERABILITY_PRESETS[preset];
      } else if (vector) {
        metrics = parseVectorString(vector);
        if (!metrics) {
          return {
            isError: true,
            content: [{
              type: 'text' as const,
              text: 'Invalid CVSS vector string format. Expected: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X',
            }],
          };
        }
      } else if (
        attackVector &&
        attackComplexity &&
        privilegesRequired &&
        userInteraction &&
        scope &&
        confidentialityImpact &&
        integrityImpact &&
        availabilityImpact
      ) {
        metrics = {
          attackVector,
          attackComplexity,
          privilegesRequired,
          userInteraction,
          scope,
          confidentialityImpact,
          integrityImpact,
          availabilityImpact,
        };
      }

      if (!metrics) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `# CVSS Calculator Usage

You must provide one of:

1. **Preset vulnerability type:**
   \`preset: "sql-injection"\`

2. **CVSS vector string:**
   \`vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"\`

3. **Individual metrics (all required):**
   - \`attackVector\`: N (Network), A (Adjacent), L (Local), P (Physical)
   - \`attackComplexity\`: L (Low), H (High)
   - \`privilegesRequired\`: N (None), L (Low), H (High)
   - \`userInteraction\`: N (None), R (Required)
   - \`scope\`: U (Unchanged), C (Changed)
   - \`confidentialityImpact\`: H (High), L (Low), N (None)
   - \`integrityImpact\`: H (High), L (Low), N (None)
   - \`availabilityImpact\`: H (High), L (Low), N (None)

Use \`listPresets: true\` to see all available presets.`,
          }],
        };
      }

      const result = calculateCvss31(metrics);

      // Severity color indicator
      const severityIndicator = {
        None: '⚪',
        Low: '🟢',
        Medium: '🟡',
        High: '🟠',
        Critical: '🔴',
      };

      let output = `# CVSS v3.1 Score Calculation

## Result

${severityIndicator[result.severity]} **Score: ${result.score}** - **${result.severity}**

**Vector String:** \`${result.vector}\`

## Score Breakdown
- **Exploitability Sub-score:** ${result.breakdown.exploitability}
- **Impact Sub-score:** ${result.breakdown.impact}`;

      if (showDetails) {
        output += `

## Metric Details

### Exploitability Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| Attack Vector | ${metrics.attackVector} | ${metricDescriptions.attackVector[metrics.attackVector]} |
| Attack Complexity | ${metrics.attackComplexity} | ${metricDescriptions.attackComplexity[metrics.attackComplexity]} |
| Privileges Required | ${metrics.privilegesRequired} | ${metricDescriptions.privilegesRequired[metrics.privilegesRequired]} |
| User Interaction | ${metrics.userInteraction} | ${metricDescriptions.userInteraction[metrics.userInteraction]} |

### Scope
| Metric | Value | Description |
|--------|-------|-------------|
| Scope | ${metrics.scope} | ${metricDescriptions.scope[metrics.scope]} |

### Impact Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| Confidentiality | ${metrics.confidentialityImpact} | ${metricDescriptions.impactRating[metrics.confidentialityImpact]} |
| Integrity | ${metrics.integrityImpact} | ${metricDescriptions.impactRating[metrics.integrityImpact]} |
| Availability | ${metrics.availabilityImpact} | ${metricDescriptions.impactRating[metrics.availabilityImpact]} |`;
      }

      output += `

## Severity Scale Reference

| Score Range | Severity |
|-------------|----------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |`;

      if (preset) {
        output += `

---
*Calculated using preset: "${preset}"*`;
      }

      return {
        content: [{
          type: 'text' as const,
          text: output,
        }],
      };
    }
  );
}
