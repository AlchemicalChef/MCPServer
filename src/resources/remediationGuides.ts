import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const remediationGuides = {
  description: 'Detailed remediation guidance for common vulnerability types with code examples',
  vulnerabilities: {
    'SQL Injection': {
      cwe: 'CWE-89',
      owasp: 'A03:2021 - Injection',
      severity: 'Critical',
      description: 'SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query',
      impact: [
        'Database data theft or corruption',
        'Authentication bypass',
        'Denial of service',
        'Remote code execution in some cases',
      ],
      remediation: {
        primary: 'Use parameterized queries or prepared statements',
        steps: [
          'Replace all string concatenation in SQL with parameterized queries',
          'Use ORM frameworks with proper escaping',
          'Implement input validation as defense-in-depth',
          'Apply principle of least privilege to database accounts',
          'Enable SQL query logging for monitoring',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);`,
          secure: `const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);`,
        },
        python: {
          vulnerable: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
          secure: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
        },
        java: {
          vulnerable: `String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);`,
          secure: `PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
stmt.executeQuery();`,
        },
      },
      testing: [
        'Test with SQL metacharacters: \' " ; -- /* */',
        'Test with boolean-based payloads: OR 1=1, AND 1=2',
        'Test with time-based payloads: SLEEP(5), pg_sleep(5)',
        'Use SQLMap for automated testing',
      ],
    },
    'Cross-Site Scripting (XSS)': {
      cwe: 'CWE-79',
      owasp: 'A03:2021 - Injection',
      severity: 'High',
      description: 'XSS attacks occur when an application includes untrusted data in a web page without proper validation or escaping',
      impact: [
        'Session hijacking',
        'Account takeover',
        'Defacement',
        'Malware distribution',
        'Credential theft',
      ],
      remediation: {
        primary: 'Context-aware output encoding and Content Security Policy',
        steps: [
          'Use framework auto-escaping (React, Vue, Angular)',
          'Encode output based on context (HTML, JS, URL, CSS)',
          'Implement strict Content Security Policy',
          'Use HTTPOnly and Secure flags on cookies',
          'Sanitize HTML if rich text is required',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `element.innerHTML = userInput;
document.write(userInput);`,
          secure: `element.textContent = userInput;
// Or use DOMPurify for HTML
element.innerHTML = DOMPurify.sanitize(userInput);`,
        },
        react: {
          vulnerable: `<div dangerouslySetInnerHTML={{__html: userInput}} />`,
          secure: `<div>{userInput}</div>
// Or with DOMPurify if HTML needed
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />`,
        },
        python: {
          vulnerable: `return f"<div>{user_input}</div>"`,
          secure: `from markupsafe import escape
return f"<div>{escape(user_input)}</div>"`,
        },
      },
      testing: [
        'Test with <script>alert(1)</script>',
        'Test with event handlers: <img onerror=alert(1) src=x>',
        'Test with SVG: <svg onload=alert(1)>',
        'Test in different contexts: attributes, JavaScript, CSS',
      ],
    },
    'Command Injection': {
      cwe: 'CWE-78',
      owasp: 'A03:2021 - Injection',
      severity: 'Critical',
      description: 'Command injection occurs when an application passes unsafe user data to a system shell',
      impact: [
        'Complete system compromise',
        'Data exfiltration',
        'Lateral movement',
        'Denial of service',
      ],
      remediation: {
        primary: 'Avoid shell execution; use language-native APIs',
        steps: [
          'Replace shell commands with native APIs when possible',
          'Use array-based execution without shell interpolation',
          'Implement strict input validation with allowlists',
          'Use least privilege for process execution',
          'Sandbox command execution if unavoidable',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `const { exec } = require('child_process');
exec('ping ' + userInput);`,
          secure: `const { execFile } = require('child_process');
execFile('ping', ['-c', '4', userInput]); // No shell interpolation`,
        },
        python: {
          vulnerable: `import os
os.system(f"ping {user_input}")`,
          secure: `import subprocess
subprocess.run(['ping', '-c', '4', user_input], shell=False)`,
        },
      },
      testing: [
        'Test with command separators: ; | & && || \\n',
        'Test with command substitution: $(cmd) `cmd`',
        'Test with argument injection: --help -v',
      ],
    },
    'Path Traversal': {
      cwe: 'CWE-22',
      owasp: 'A01:2021 - Broken Access Control',
      severity: 'High',
      description: 'Path traversal attacks attempt to access files outside the intended directory',
      impact: [
        'Unauthorized file access',
        'Source code disclosure',
        'Configuration file exposure',
        'Credential theft',
      ],
      remediation: {
        primary: 'Validate and canonicalize paths against a base directory',
        steps: [
          'Use path canonicalization (realpath, normalize)',
          'Validate resolved path starts with allowed base directory',
          'Reject paths containing .. or starting with /',
          'Use allowlist of permitted filenames if possible',
          'Implement chroot or containerization',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `const filePath = './uploads/' + req.params.filename;
fs.readFile(filePath);`,
          secure: `const path = require('path');
const baseDir = path.resolve('./uploads');
const filePath = path.resolve(baseDir, req.params.filename);
if (!filePath.startsWith(baseDir)) {
  throw new Error('Invalid path');
}
fs.readFile(filePath);`,
        },
        python: {
          vulnerable: `file_path = f"./uploads/{filename}"
with open(file_path) as f:`,
          secure: `import os
base_dir = os.path.realpath('./uploads')
file_path = os.path.realpath(os.path.join(base_dir, filename))
if not file_path.startswith(base_dir):
    raise ValueError('Invalid path')
with open(file_path) as f:`,
        },
      },
      testing: [
        'Test with ../../../etc/passwd',
        'Test with URL encoding: %2e%2e%2f',
        'Test with double encoding: %252e%252e%252f',
        'Test with null bytes: file.txt%00.jpg',
      ],
    },
    'Insecure Deserialization': {
      cwe: 'CWE-502',
      owasp: 'A08:2021 - Software and Data Integrity Failures',
      severity: 'Critical',
      description: 'Insecure deserialization occurs when untrusted data is used to abuse application logic or execute code',
      impact: [
        'Remote code execution',
        'Privilege escalation',
        'Denial of service',
        'Authentication bypass',
      ],
      remediation: {
        primary: 'Avoid deserializing untrusted data; use safe formats like JSON',
        steps: [
          'Replace native serialization with JSON or similar safe formats',
          'Implement integrity checks (HMAC) on serialized data',
          'Use allowlists for permitted classes',
          'Run deserialization in isolated/sandboxed environments',
          'Log and monitor deserialization events',
        ],
      },
      examples: {
        python: {
          vulnerable: `import pickle
data = pickle.loads(user_input)`,
          secure: `import json
data = json.loads(user_input)
# Validate schema after parsing`,
        },
        java: {
          vulnerable: `ObjectInputStream ois = new ObjectInputStream(userInputStream);
Object obj = ois.readObject();`,
          secure: `// Use JSON instead
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(userInput, MyClass.class);`,
        },
      },
      testing: [
        'Test with gadget chains for target language',
        'Use ysoserial for Java applications',
        'Test pickle/marshal payloads for Python',
      ],
    },
    'Hardcoded Credentials': {
      cwe: 'CWE-798',
      owasp: 'A07:2021 - Identification and Authentication Failures',
      severity: 'Critical',
      description: 'Credentials or cryptographic keys embedded in source code',
      impact: [
        'Unauthorized system access',
        'Cannot rotate credentials without code changes',
        'Credentials exposed in version control',
        'Insider threat risk',
      ],
      remediation: {
        primary: 'Use environment variables or secret management systems',
        steps: [
          'Move secrets to environment variables',
          'Use secret management (Vault, AWS Secrets Manager, etc.)',
          'Implement secret rotation capabilities',
          'Remove secrets from version control history',
          'Use .gitignore for configuration files',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `const apiKey = "sk-1234567890abcdef";
const dbPassword = "admin123";`,
          secure: `const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
// Or use a secret manager
const apiKey = await secretManager.getSecret('api-key');`,
        },
        python: {
          vulnerable: `API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"`,
          secure: `import os
API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')`,
        },
      },
      testing: [
        'Search code for common secret patterns',
        'Use tools like truffleHog, git-secrets',
        'Review environment variable loading',
      ],
    },
    'Weak Cryptography': {
      cwe: 'CWE-327',
      owasp: 'A02:2021 - Cryptographic Failures',
      severity: 'High',
      description: 'Use of broken or risky cryptographic algorithms',
      impact: [
        'Data confidentiality breach',
        'Authentication bypass',
        'Message forgery',
        'Compliance violations',
      ],
      remediation: {
        primary: 'Use modern cryptographic algorithms with proper parameters',
        steps: [
          'Replace MD5/SHA1 with SHA-256 or better for hashing',
          'Use bcrypt/argon2/scrypt for password hashing',
          'Use AES-256-GCM for encryption',
          'Use proper key derivation functions',
          'Ensure sufficient key lengths',
        ],
      },
      examples: {
        javascript: {
          vulnerable: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
          secure: `const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);`,
        },
        python: {
          vulnerable: `import hashlib
hash = hashlib.md5(password.encode()).hexdigest()`,
          secure: `import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))`,
        },
      },
      testing: [
        'Identify cryptographic algorithms in use',
        'Check key/hash lengths',
        'Verify IV/nonce uniqueness',
        'Check for ECB mode usage',
      ],
    },
  },
};

export function registerRemediationGuidesResource(server: McpServer): void {
  server.resource(
    'remediation-guides',
    'security://remediation-guides',
    {
      description: 'Detailed remediation guidance for common vulnerability types with code examples',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(remediationGuides, null, 2),
        },
      ],
    })
  );
}
