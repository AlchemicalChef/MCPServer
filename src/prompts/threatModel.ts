import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerThreatModelPrompt(server: McpServer): void {
  server.prompt(
    'threat-model',
    'Generate a threat model for a system or component',
    {
      systemDescription: z.string().describe('Description of the system or component to analyze'),
      architecture: z.string().optional().describe('Architecture details (components, data flows, trust boundaries)'),
      assets: z.array(z.string()).optional().describe('Key assets to protect'),
      threatActors: z.array(z.enum([
        'external-attacker',
        'insider-threat',
        'automated-tools',
        'nation-state',
        'competitor'
      ])).default(['external-attacker']).describe('Threat actors to consider'),
    },
    ({ systemDescription, architecture, assets, threatActors }) => {
      const architectureText = architecture ? `\n\n**Architecture:**\n${architecture}` : '';
      const assetsText = assets && assets.length > 0
        ? `\n\n**Key Assets:**\n${assets.map(a => `- ${a}`).join('\n')}`
        : '';
      const actorsText = `\n\n**Threat Actors:** ${threatActors.join(', ')}`;

      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `Generate a comprehensive threat model using the STRIDE methodology for the following system.

## System Description

${systemDescription}${architectureText}${assetsText}${actorsText}

## Threat Model Requirements

### 1. STRIDE Analysis
Analyze threats across all STRIDE categories:
- **S**poofing: Identity threats
- **T**ampering: Data integrity threats
- **R**epudiation: Accountability threats
- **I**nformation Disclosure: Confidentiality threats
- **D**enial of Service: Availability threats
- **E**levation of Privilege: Authorization threats

### 2. Attack Surface Analysis
- Entry points (APIs, user inputs, file uploads)
- Trust boundaries
- Data flows
- External dependencies

### 3. Threat Scenarios
For each threat identified:
- Attack vector
- Prerequisites
- Impact (confidentiality, integrity, availability)
- Likelihood (Low/Medium/High)
- Risk level (Low/Medium/High/Critical)

### 4. Mitigation Strategies
For each threat:
- Preventive controls
- Detective controls
- Corrective controls
- Recommended security controls

### 5. Security Requirements
- Authentication requirements
- Authorization requirements
- Data protection requirements
- Logging and monitoring requirements

## Output Format

Provide a structured threat model with:
1. Executive summary
2. System overview diagram description
3. Threat enumeration table
4. Risk assessment matrix
5. Prioritized mitigation recommendations`,
            },
          },
        ],
      };
    }
  );
}
