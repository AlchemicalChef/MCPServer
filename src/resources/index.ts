import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerOwaspTop10Resource } from './owaspTop10.js';
import { registerCweReferenceResource } from './cweReference.js';
import { registerVulnerabilityPatternsResource } from './vulnerabilityPatterns.js';
// Sprint 2: New resources
import { registerComplianceMappingResource } from './complianceMapping.js';
// Sprint 3: New resources
import { registerRemediationGuidesResource } from './remediationGuides.js';
import { registerSecurityBenchmarksResource } from './securityBenchmarks.js';

export function registerResources(server: McpServer): void {
  registerOwaspTop10Resource(server);
  registerCweReferenceResource(server);
  registerVulnerabilityPatternsResource(server);

  // Sprint 2: Compliance mapping
  registerComplianceMappingResource(server);

  // Sprint 3: Remediation and benchmarks
  registerRemediationGuidesResource(server);
  registerSecurityBenchmarksResource(server);
}
