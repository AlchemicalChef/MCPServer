import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  generateAuditFormalModel,
  loadAuditHistoryFromFile,
  getAuditHistory,
  clearAuditHistory,
  logToolInvocation,
  logOutput,
} from '../utils/auditLog.js';

export function registerModelAuditTrailTool(server: McpServer): void {
  server.tool(
    'model-audit-trail',
    'Generate formal models (state machines, TLA+, Alloy, Petri nets, sequence diagrams) from the audit trail of tool invocations',
    {
      modelType: z.enum(['state-machine', 'tlaplus', 'alloy', 'petri-net', 'sequence'])
        .default('state-machine')
        .describe('Type of formal model to generate'),
      loadFromFile: z.string().optional()
        .describe('Optional: Load audit history from a log file path before generating'),
      clearHistory: z.boolean().default(false)
        .describe('Clear history after generating the model'),
    },
    async (params) => {
      logToolInvocation('model-audit-trail', {
        modelType: params.modelType,
        loadFromFile: params.loadFromFile ? '[path]' : undefined,
        clearHistory: params.clearHistory,
      });

      try {
        // Optionally load from file first
        let loadedCount = 0;
        if (params.loadFromFile) {
          loadedCount = loadAuditHistoryFromFile(params.loadFromFile);
        }

        // Get current history size
        const historySize = getAuditHistory().length;

        if (historySize === 0) {
          const msg = 'No audit history available. Run some tools first or load from a log file.';
          logOutput('model-audit-trail', { success: false, error: msg });
          return {
            content: [{ type: 'text', text: msg }],
          };
        }

        // Generate the formal model
        const model = generateAuditFormalModel(params.modelType);

        // Build output
        const lines: string[] = [];
        lines.push(`# Audit Trail Formal Model`);
        lines.push('');
        lines.push(`**Model Type:** ${model.type}`);
        lines.push(`**Generated:** ${model.generatedAt}`);
        lines.push(`**Audit Entries:** ${model.entryCount}`);
        if (loadedCount > 0) {
          lines.push(`**Loaded from file:** ${loadedCount} entries`);
        }
        lines.push('');
        lines.push('---');
        lines.push('');
        lines.push(model.specification);

        // Optionally clear history
        if (params.clearHistory) {
          clearAuditHistory();
          lines.push('');
          lines.push('---');
          lines.push('_Audit history cleared after model generation._');
        }

        const result = lines.join('\n');

        logOutput('model-audit-trail', {
          success: true,
          summary: `Generated ${model.type} model from ${model.entryCount} audit entries`,
          metrics: {
            modelType: model.type,
            entryCount: model.entryCount,
            stateCount: model.states.length,
            transitionCount: model.transitions.length,
          },
        });

        return {
          content: [{ type: 'text', text: result }],
        };
      } catch (error) {
        const errorMsg = `Error generating audit model: ${error instanceof Error ? error.message : String(error)}`;
        logOutput('model-audit-trail', { success: false, error: errorMsg });
        return {
          content: [{ type: 'text', text: errorMsg }],
          isError: true,
        };
      }
    }
  );
}
