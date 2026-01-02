import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerScanCodeTool } from './scanCode.js';
import { registerScanSecretsTool } from './scanSecrets.js';
import { registerScanDependenciesTool } from './scanDependencies.js';
import { registerFileSystemTools } from './fileSystem.js';
// Sprint 1: New tools
import { registerScanIaCTool } from './scanIaC.js';
import { registerExportSarifTool } from './exportSarif.js';
import { registerAnalyzeHeadersTool } from './analyzeHeaders.js';
import { registerScanLicensesTool } from './scanLicenses.js';
// Sprint 2: New tools
import { registerScanApiSpecTool } from './scanApiSpec.js';
import { registerScanGitHistoryTool } from './scanGitHistory.js';
// Sprint 3: Advanced analysis tools
import { registerGenerateSbomTool } from './generateSbom.js';
import { registerAnalyzeDataflowTool } from './analyzeDataflow.js';
import { registerCalculateCvssTool } from './calculateCvss.js';
// Lab/Research tools
import { registerInjectDebuggerTool } from './injectDebugger.js';

export function registerTools(server: McpServer): void {
  // Security scanning tools
  registerScanCodeTool(server);
  registerScanSecretsTool(server); // Enhanced with entropy detection
  registerScanDependenciesTool(server);

  // File system tools for analysis
  registerFileSystemTools(server);

  // Sprint 1: Infrastructure and compliance tools
  registerScanIaCTool(server);
  registerExportSarifTool(server);
  registerAnalyzeHeadersTool(server);
  registerScanLicensesTool(server);

  // Sprint 2: API and git history scanning
  registerScanApiSpecTool(server);
  registerScanGitHistoryTool(server);

  // Sprint 3: Advanced analysis and scoring
  registerGenerateSbomTool(server);
  registerAnalyzeDataflowTool(server);
  registerCalculateCvssTool(server);

  // Lab/Research tools (authorized use only)
  registerInjectDebuggerTool(server);
}
