import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation } from '../utils/auditLog.js';

export function registerFileSystemTools(server: McpServer): void {
  // Read file tool
  server.tool(
    'read-file',
    'Read the contents of a source file for security analysis',
    {
      path: z.string().describe('Absolute or relative path to the file'),
      startLine: z.number().optional().describe('Start reading from this line (1-indexed)'),
      endLine: z.number().optional().describe('Stop reading at this line (inclusive)'),
    },
    async ({ path: filePath, startLine, endLine }) => {
      // Sanitize inputs
      const sanitizedPath = sanitize(filePath);
      const validation = validateInput(filePath);

      // Audit log
      logToolInvocation('read-file', { path: filePath, startLine, endLine }, validation.warnings);

      try {
        const content = await fs.readFile(sanitizedPath, 'utf-8');
        const lines = content.split('\n');

        let result: string;
        if (startLine !== undefined || endLine !== undefined) {
          const start = (startLine || 1) - 1;
          const end = endLine || lines.length;
          result = lines.slice(start, end).map((line, idx) =>
            `${(start + idx + 1).toString().padStart(4, ' ')} | ${line}`
          ).join('\n');
        } else {
          result = lines.map((line, idx) =>
            `${(idx + 1).toString().padStart(4, ' ')} | ${line}`
          ).join('\n');
        }

        return {
          content: [{
            type: 'text' as const,
            text: `# File: ${filePath}\n\n\`\`\`\n${result}\n\`\`\``,
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `Error reading file: ${error instanceof Error ? error.message : 'Unknown error'}`,
          }],
        };
      }
    }
  );

  // List files tool
  server.tool(
    'list-files',
    'List files in a directory with optional filtering by extension',
    {
      path: z.string().describe('Directory path to list'),
      recursive: z.boolean().default(false).describe('Recursively list files'),
      extensions: z.array(z.string()).optional().describe('Filter by file extensions (e.g., [".js", ".ts"])'),
      showHidden: z.boolean().default(false).describe('Show hidden files (starting with .)'),
    },
    async ({ path: dirPath, recursive, extensions, showHidden }) => {
      // Sanitize inputs
      const sanitizedPath = sanitize(dirPath);
      const validation = validateInput(dirPath);

      // Audit log
      logToolInvocation('list-files', { path: dirPath, recursive, extensions, showHidden }, validation.warnings);

      const files: string[] = [];

      async function listDir(currentPath: string, depth: number = 0): Promise<void> {
        try {
          const entries = await fs.readdir(currentPath, { withFileTypes: true });

          for (const entry of entries) {
            // Skip hidden files unless requested
            if (!showHidden && entry.name.startsWith('.')) {
              continue;
            }

            // Skip common non-source directories
            if (entry.isDirectory() && ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'].includes(entry.name)) {
              continue;
            }

            const fullPath = path.join(currentPath, entry.name);

            if (entry.isFile()) {
              if (extensions && extensions.length > 0) {
                const ext = path.extname(entry.name).toLowerCase();
                if (!extensions.includes(ext)) {
                  continue;
                }
              }
              files.push(fullPath);
            } else if (entry.isDirectory() && recursive) {
              await listDir(fullPath, depth + 1);
            }
          }
        } catch (error) {
          // Skip directories we can't read
        }
      }

      await listDir(dirPath);

      // Sort files
      files.sort();

      if (files.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `No files found in ${dirPath}`,
          }],
        };
      }

      // Group by directory for better readability
      const grouped = files.reduce((acc, file) => {
        const dir = path.dirname(file);
        if (!acc[dir]) acc[dir] = [];
        acc[dir].push(path.basename(file));
        return acc;
      }, {} as Record<string, string[]>);

      const output = Object.entries(grouped).map(([dir, fileList]) =>
        `${dir}/\n${fileList.map(f => `  ${f}`).join('\n')}`
      ).join('\n\n');

      return {
        content: [{
          type: 'text' as const,
          text: `# Files in ${dirPath}\n\nTotal: ${files.length} files\n\n${output}`,
        }],
      };
    }
  );

  // Grep pattern tool
  server.tool(
    'grep-pattern',
    'Search for patterns across files using regex',
    {
      pattern: z.string().describe('Regular expression pattern to search for'),
      path: z.string().describe('File or directory to search in'),
      recursive: z.boolean().default(true).describe('Recursively search directories'),
      caseSensitive: z.boolean().default(false).describe('Case-sensitive search'),
      extensions: z.array(z.string()).optional().describe('Filter by file extensions'),
      contextLines: z.number().default(2).describe('Lines of context before and after match'),
    },
    async ({ pattern, path: searchPath, recursive, caseSensitive, extensions, contextLines }) => {
      // Sanitize inputs
      const sanitizedPattern = sanitize(pattern);
      const sanitizedPath = sanitize(searchPath);
      const validation = validateInput(pattern);

      // Audit log
      logToolInvocation('grep-pattern', { pattern, path: searchPath, recursive, caseSensitive, extensions, contextLines }, validation.warnings);

      interface Match {
        file: string;
        line: number;
        match: string;
        context: string[];
      }

      const matches: Match[] = [];
      const regex = new RegExp(pattern, caseSensitive ? 'g' : 'gi');

      async function searchFile(filePath: string): Promise<void> {
        try {
          const content = await fs.readFile(filePath, 'utf-8');
          const lines = content.split('\n');

          for (let i = 0; i < lines.length; i++) {
            if (regex.test(lines[i])) {
              const start = Math.max(0, i - contextLines);
              const end = Math.min(lines.length - 1, i + contextLines);
              const context = lines.slice(start, end + 1).map((line, idx) => {
                const lineNum = start + idx + 1;
                const prefix = lineNum === i + 1 ? '>' : ' ';
                return `${prefix}${lineNum.toString().padStart(4, ' ')} | ${line}`;
              });

              matches.push({
                file: filePath,
                line: i + 1,
                match: lines[i],
                context,
              });
            }
            // Reset regex for next iteration
            regex.lastIndex = 0;
          }
        } catch (error) {
          // Skip files we can't read
        }
      }

      async function searchDir(dirPath: string): Promise<void> {
        try {
          const stats = await fs.stat(dirPath);

          if (stats.isFile()) {
            if (extensions && extensions.length > 0) {
              const ext = path.extname(dirPath).toLowerCase();
              if (!extensions.includes(ext)) return;
            }
            await searchFile(dirPath);
          } else if (stats.isDirectory()) {
            const entries = await fs.readdir(dirPath, { withFileTypes: true });

            for (const entry of entries) {
              if (entry.name.startsWith('.') ||
                  ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'].includes(entry.name)) {
                continue;
              }

              const fullPath = path.join(dirPath, entry.name);

              if (entry.isFile()) {
                if (extensions && extensions.length > 0) {
                  const ext = path.extname(entry.name).toLowerCase();
                  if (!extensions.includes(ext)) continue;
                }
                await searchFile(fullPath);
              } else if (entry.isDirectory() && recursive) {
                await searchDir(fullPath);
              }
            }
          }
        } catch (error) {
          // Skip paths we can't access
        }
      }

      await searchDir(searchPath);

      if (matches.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `No matches found for pattern: ${pattern}`,
          }],
        };
      }

      const output = matches.map(m =>
        `## ${m.file}:${m.line}\n\n\`\`\`\n${m.context.join('\n')}\n\`\`\``
      ).join('\n\n---\n\n');

      return {
        content: [{
          type: 'text' as const,
          text: `# Search Results for: \`${pattern}\`

**Matches found:** ${matches.length}

${output}`,
        }],
      };
    }
  );

  // Find dangerous functions tool
  server.tool(
    'find-dangerous-functions',
    'Search for potentially dangerous function calls in code',
    {
      path: z.string().describe('Directory or file to search'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'all']).default('all')
        .describe('Programming language to focus on'),
    },
    async ({ path: searchPath, language }) => {
      // Sanitize inputs
      const sanitizedPath = sanitize(searchPath);
      const validation = validateInput(searchPath);

      // Audit log
      logToolInvocation('find-dangerous-functions', { path: searchPath, language }, validation.warnings);

      const dangerousFunctions: Record<string, string[]> = {
        javascript: [
          'eval', 'Function', 'setTimeout.*string', 'setInterval.*string',
          'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
          'exec', 'execSync', 'spawn', 'spawnSync',
          'createReadStream', 'createWriteStream', 'readFile', 'writeFile',
        ],
        typescript: [
          'eval', 'Function', 'setTimeout.*string', 'setInterval.*string',
          'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
          'exec', 'execSync', 'spawn', 'spawnSync',
          'createReadStream', 'createWriteStream', 'readFile', 'writeFile',
        ],
        python: [
          'eval', 'exec', 'compile', '__import__',
          'os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
          'pickle.load', 'pickle.loads', 'marshal.load',
          'yaml.load', 'yaml.unsafe_load',
          'input', 'raw_input',
        ],
        go: [
          'exec.Command', 'os.Exec',
          'html/template.*HTML', 'text/template',
          'sql.Query.*\\+', 'sql.Exec.*\\+',
        ],
      };

      const languagesToCheck = language === 'all'
        ? Object.keys(dangerousFunctions)
        : [language];

      const extensionMap: Record<string, string[]> = {
        javascript: ['.js', '.mjs', '.cjs', '.jsx'],
        typescript: ['.ts', '.tsx'],
        python: ['.py'],
        go: ['.go'],
      };

      interface DangerousCall {
        function: string;
        file: string;
        line: number;
        context: string;
        language: string;
      }

      const findings: DangerousCall[] = [];

      async function searchFile(filePath: string, lang: string): Promise<void> {
        try {
          const content = await fs.readFile(filePath, 'utf-8');
          const lines = content.split('\n');
          const functions = dangerousFunctions[lang] || [];

          for (const func of functions) {
            const regex = new RegExp(func, 'g');
            for (let i = 0; i < lines.length; i++) {
              if (regex.test(lines[i])) {
                findings.push({
                  function: func,
                  file: filePath,
                  line: i + 1,
                  context: lines[i].trim(),
                  language: lang,
                });
              }
              regex.lastIndex = 0;
            }
          }
        } catch (error) {
          // Skip files we can't read
        }
      }

      async function searchDir(dirPath: string): Promise<void> {
        try {
          const stats = await fs.stat(dirPath);

          if (stats.isFile()) {
            const ext = path.extname(dirPath).toLowerCase();
            for (const lang of languagesToCheck) {
              if (extensionMap[lang]?.includes(ext)) {
                await searchFile(dirPath, lang);
                break;
              }
            }
          } else if (stats.isDirectory()) {
            const entries = await fs.readdir(dirPath, { withFileTypes: true });

            for (const entry of entries) {
              if (entry.name.startsWith('.') ||
                  ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'].includes(entry.name)) {
                continue;
              }

              const fullPath = path.join(dirPath, entry.name);

              if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                for (const lang of languagesToCheck) {
                  if (extensionMap[lang]?.includes(ext)) {
                    await searchFile(fullPath, lang);
                    break;
                  }
                }
              } else if (entry.isDirectory()) {
                await searchDir(fullPath);
              }
            }
          }
        } catch (error) {
          // Skip paths we can't access
        }
      }

      await searchDir(searchPath);

      if (findings.length === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: `No dangerous function calls found in ${searchPath}`,
          }],
        };
      }

      // Group by function
      const grouped = findings.reduce((acc, f) => {
        if (!acc[f.function]) acc[f.function] = [];
        acc[f.function].push(f);
        return acc;
      }, {} as Record<string, DangerousCall[]>);

      const output = Object.entries(grouped).map(([func, calls]) =>
        `## \`${func}\` (${calls.length} occurrences)\n\n` +
        calls.map(c => `- **${c.file}:${c.line}**\n  \`${c.context}\``).join('\n\n')
      ).join('\n\n---\n\n');

      return {
        content: [{
          type: 'text' as const,
          text: `# Dangerous Function Analysis

**Path:** ${searchPath}
**Total findings:** ${findings.length}

${output}

---

**Note:** Not all occurrences are necessarily vulnerabilities. Review each usage in context.`,
        }],
      };
    }
  );
}
