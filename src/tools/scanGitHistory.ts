import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

const execAsync = promisify(exec);

interface GitSecretFinding {
  commit: string;
  author: string;
  date: string;
  file: string;
  line?: number;
  secretType: string;
  match: string;
  masked: string;
}

// Secret patterns (same as scanSecrets but tuned for git history scanning)
const secretPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key ID', pattern: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g },
  { name: 'GitHub Token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g },
  { name: 'GitLab Token', pattern: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g },
  { name: 'Slack Token', pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b/g },
  { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Stripe Key', pattern: /\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}\b/g },
  { name: 'npm Token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'JWT Token', pattern: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g },
  { name: 'Generic Secret', pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)\s*[=:]\s*['"][A-Za-z0-9\-_+/=]{16,}['"]/gi },
  { name: 'OpenAI Key', pattern: /\bsk-[A-Za-z0-9]{48}\b/g },
  { name: 'Anthropic Key', pattern: /\bsk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{80,}\b/g },
  { name: 'Discord Token', pattern: /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b/g },
  { name: 'SendGrid Key', pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g },
];

function maskSecret(value: string): string {
  if (value.length <= 10) return '*'.repeat(value.length);
  return value.slice(0, 5) + '*'.repeat(value.length - 10) + value.slice(-5);
}

async function isGitRepo(path: string): Promise<boolean> {
  try {
    await execAsync(`git -C "${path}" rev-parse --git-dir`, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function getGitLog(repoPath: string, maxCommits: number): Promise<Array<{
  hash: string;
  author: string;
  date: string;
  message: string;
}>> {
  const format = '%H|%an|%ai|%s';
  const { stdout } = await execAsync(
    `git -C "${repoPath}" log --all -n ${maxCommits} --format="${format}"`,
    { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
  );

  return stdout.trim().split('\n').filter(Boolean).map(line => {
    const [hash, author, date, message] = line.split('|');
    return { hash, author, date, message };
  });
}

async function getCommitDiff(repoPath: string, commitHash: string): Promise<string> {
  try {
    const { stdout } = await execAsync(
      `git -C "${repoPath}" show --format="" --patch ${commitHash}`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
    );
    return stdout;
  } catch {
    return '';
  }
}

async function scanCommitForSecrets(
  repoPath: string,
  commit: { hash: string; author: string; date: string },
): Promise<GitSecretFinding[]> {
  const findings: GitSecretFinding[] = [];
  const diff = await getCommitDiff(repoPath, commit.hash);

  // Parse diff to extract file paths and added lines
  const fileRegex = /^\+\+\+ b\/(.+)$/gm;
  const addedLineRegex = /^\+(?!\+\+)(.*)$/gm;

  let currentFile = '';
  const lines = diff.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Track current file
    const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      continue;
    }

    // Only scan added lines (starting with +)
    if (line.startsWith('+') && !line.startsWith('+++')) {
      const content = line.slice(1); // Remove the + prefix

      for (const { name, pattern } of secretPatterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(content)) !== null) {
          findings.push({
            commit: commit.hash.slice(0, 8),
            author: commit.author,
            date: commit.date,
            file: currentFile,
            secretType: name,
            match: match[0],
            masked: maskSecret(match[0]),
          });
        }
      }
    }
  }

  return findings;
}

export function registerScanGitHistoryTool(server: McpServer): void {
  server.tool(
    'scan-git-history',
    'Scan git commit history for accidentally committed secrets and credentials',
    {
      target: z.string().describe('Path to git repository'),
      maxCommits: z.number().default(100).describe('Maximum number of commits to scan'),
      branch: z.string().optional().describe('Specific branch to scan (default: all branches)'),
      showValues: z.boolean().default(false).describe('Show actual secret values (use with caution)'),
    },
    async ({ target, maxCommits, showValues }) => {
      // Sanitize inputs
      const sanitizedTarget = sanitize(target);
      const validation = validateInput(target);

      // Audit log
      logToolInvocation('scan-git-history', { target, maxCommits, showValues }, validation.warnings);

      // Check if git is available
      try {
        await execAsync('git --version', { timeout: 5000 });
      } catch {
        logOutput('scan-git-history', {
          success: false,
          error: 'Git is not installed or not accessible',
        });
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: 'Git is not installed or not accessible. Please install git to use this tool.',
          }],
        };
      }

      // Check if target is a git repository
      if (!(await isGitRepo(target))) {
        logOutput('scan-git-history', {
          success: false,
          error: 'Not a git repository',
        });
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `"${target}" is not a git repository. Please provide a valid git repository path.`,
          }],
        };
      }

      const findings: GitSecretFinding[] = [];

      try {
        const commits = await getGitLog(target, maxCommits);

        for (const commit of commits) {
          const commitFindings = await scanCommitForSecrets(target, commit);
          findings.push(...commitFindings);
        }

        if (findings.length === 0) {
          logOutput('scan-git-history', {
            success: true,
            summary: 'No secrets found',
            metrics: { commitsScanned: commits.length },
          });
          return {
            content: [{
              type: 'text' as const,
              text: `# Git History Secret Scan

**Repository:** ${target}
**Commits scanned:** ${commits.length}

## Result
No secrets found in commit history.

This is good! However, note that this scan only checks for common secret patterns. Always be vigilant about sensitive data in commits.`,
            }],
          };
        }

        // Group by commit
        const byCommit = findings.reduce((acc, f) => {
          if (!acc[f.commit]) acc[f.commit] = [];
          acc[f.commit].push(f);
          return acc;
        }, {} as Record<string, GitSecretFinding[]>);

        // Group by secret type
        const byType = findings.reduce((acc, f) => {
          if (!acc[f.secretType]) acc[f.secretType] = [];
          acc[f.secretType].push(f);
          return acc;
        }, {} as Record<string, GitSecretFinding[]>);

        const commitReport = Object.entries(byCommit).map(([commit, items]) => {
          const first = items[0];
          return `### Commit ${commit}
**Author:** ${first.author}
**Date:** ${first.date}
**Secrets found:** ${items.length}

${items.map(f => `- **${f.secretType}** in \`${f.file}\`
  Value: \`${showValues ? f.match : f.masked}\``).join('\n')}`;
        }).join('\n\n---\n\n');

        const typeReport = Object.entries(byType)
          .sort((a, b) => b[1].length - a[1].length)
          .map(([type, items]) => `- **${type}**: ${items.length} occurrences`)
          .join('\n');

        logOutput('scan-git-history', {
          success: true,
          summary: `Found ${findings.length} secrets in ${Object.keys(byCommit).length} commits`,
          metrics: { secretsFound: findings.length, commitsScanned: commits.length, affectedCommits: Object.keys(byCommit).length },
        });
        return {
          content: [{
            type: 'text' as const,
            text: `# Git History Secret Scan

## Summary
- **Repository:** ${target}
- **Commits scanned:** ${commits.length}
- **Secrets found:** ${findings.length}
- **Affected commits:** ${Object.keys(byCommit).length}

## Secret Types Found
${typeReport}

---

## Findings by Commit

${commitReport}

---

## Remediation

**CRITICAL:** These secrets may still be accessible in git history even if removed from current files.

To properly remediate:
1. **Rotate all exposed credentials immediately**
2. Use \`git filter-branch\` or \`BFG Repo-Cleaner\` to remove secrets from history
3. Force push the cleaned repository
4. All collaborators must re-clone the repository

**Example with BFG:**
\`\`\`bash
bfg --replace-text passwords.txt repo.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
\`\`\``,
          }],
        };
      } catch (error) {
        logOutput('scan-git-history', {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error scanning git history: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );
}
