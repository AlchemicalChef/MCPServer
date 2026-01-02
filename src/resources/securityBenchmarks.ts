import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const securityBenchmarks = {
  description: 'Industry security benchmarks and best practices for secure development',
  benchmarks: {
    'CIS Docker Benchmark': {
      version: '1.6.0',
      description: 'Best practices for securing Docker containers',
      categories: {
        'Host Configuration': [
          {
            id: '1.1.1',
            title: 'Ensure a separate partition for containers has been created',
            level: 1,
            description: 'Docker stores data in /var/lib/docker by default. A separate partition prevents container data from filling the host filesystem.',
          },
          {
            id: '1.1.2',
            title: 'Ensure only trusted users are allowed to control Docker daemon',
            level: 1,
            description: 'Docker allows any user in the docker group to run commands. Limit membership to trusted users.',
          },
        ],
        'Docker Daemon Configuration': [
          {
            id: '2.1',
            title: 'Run the Docker daemon as a non-root user',
            level: 2,
            description: 'Use rootless mode or configure userns-remap for reduced attack surface.',
          },
          {
            id: '2.2',
            title: 'Ensure network traffic is restricted between containers',
            level: 1,
            description: 'Set icc=false to disable inter-container communication by default.',
          },
          {
            id: '2.3',
            title: 'Ensure logging is configured',
            level: 1,
            description: 'Configure log-driver to capture container logs for monitoring.',
          },
          {
            id: '2.4',
            title: 'Ensure insecure registries are not used',
            level: 1,
            description: 'Do not use registries without TLS (--insecure-registry).',
          },
        ],
        'Container Images': [
          {
            id: '4.1',
            title: 'Ensure a user for the container has been created',
            level: 1,
            description: 'Create a non-root user in Dockerfile using USER instruction.',
            check: 'Dockerfile should have USER instruction with non-root user',
          },
          {
            id: '4.2',
            title: 'Ensure containers use only trusted base images',
            level: 1,
            description: 'Use official images or verified publishers. Pin specific versions.',
          },
          {
            id: '4.3',
            title: 'Ensure unnecessary packages are not installed',
            level: 1,
            description: 'Minimize attack surface by only installing required packages.',
          },
          {
            id: '4.4',
            title: 'Ensure images are scanned for vulnerabilities',
            level: 1,
            description: 'Use vulnerability scanners like Trivy, Clair, or Snyk.',
          },
          {
            id: '4.5',
            title: 'Ensure Content Trust for Docker is enabled',
            level: 2,
            description: 'Set DOCKER_CONTENT_TRUST=1 to verify image signatures.',
          },
          {
            id: '4.6',
            title: 'Ensure HEALTHCHECK instructions have been added',
            level: 1,
            description: 'Add HEALTHCHECK to detect container health issues.',
          },
        ],
        'Container Runtime': [
          {
            id: '5.1',
            title: 'Do not disable AppArmor profile',
            level: 1,
            description: 'Keep AppArmor enabled for mandatory access control.',
          },
          {
            id: '5.2',
            title: 'Ensure SELinux security options are set',
            level: 2,
            description: 'Use SELinux labels for additional isolation.',
          },
          {
            id: '5.3',
            title: 'Ensure Linux kernel capabilities are restricted',
            level: 1,
            description: 'Drop all capabilities and add only required ones.',
          },
          {
            id: '5.4',
            title: 'Do not use privileged containers',
            level: 1,
            description: 'Never use --privileged flag unless absolutely necessary.',
          },
          {
            id: '5.5',
            title: 'Do not mount sensitive host system directories',
            level: 1,
            description: 'Avoid mounting /, /boot, /dev, /etc, /proc, /sys.',
          },
          {
            id: '5.6',
            title: 'Do not run containers with root user',
            level: 1,
            description: 'Use --user flag or USER in Dockerfile.',
          },
        ],
      },
    },
    'OWASP Application Security Verification Standard': {
      version: '4.0.3',
      description: 'Comprehensive security requirements for web applications',
      levels: {
        L1: 'Standard security for all applications',
        L2: 'Defense in depth for applications handling sensitive data',
        L3: 'High assurance for critical applications',
      },
      categories: {
        'V1 Architecture': [
          { id: 'V1.1.1', title: 'Secure development lifecycle in use', level: 'L1' },
          { id: 'V1.1.2', title: 'Threat modeling performed', level: 'L2' },
          { id: 'V1.1.3', title: 'Security documentation maintained', level: 'L2' },
        ],
        'V2 Authentication': [
          { id: 'V2.1.1', title: 'Password minimum 12 characters', level: 'L1' },
          { id: 'V2.1.2', title: 'Passwords max 128 characters allowed', level: 'L1' },
          { id: 'V2.1.5', title: 'Check passwords against breached lists', level: 'L1' },
          { id: 'V2.1.7', title: 'Secure password change mechanism', level: 'L1' },
          { id: 'V2.2.1', title: 'Anti-automation controls', level: 'L1' },
          { id: 'V2.5.1', title: 'Secure credential recovery', level: 'L1' },
        ],
        'V3 Session Management': [
          { id: 'V3.1.1', title: 'Secure session token generation', level: 'L1' },
          { id: 'V3.2.1', title: 'Session binding to user agent', level: 'L1' },
          { id: 'V3.2.2', title: 'Session invalidation on logout', level: 'L1' },
          { id: 'V3.2.3', title: 'Session timeout after inactivity', level: 'L1' },
        ],
        'V4 Access Control': [
          { id: 'V4.1.1', title: 'Deny by default access control', level: 'L1' },
          { id: 'V4.1.2', title: 'Access control at trusted server', level: 'L1' },
          { id: 'V4.2.1', title: 'Sensitive data access logging', level: 'L1' },
        ],
        'V5 Validation': [
          { id: 'V5.1.1', title: 'HTTP parameter pollution protected', level: 'L1' },
          { id: 'V5.1.3', title: 'Input validation using allowlists', level: 'L1' },
          { id: 'V5.2.1', title: 'HTML sanitization for untrusted input', level: 'L1' },
          { id: 'V5.3.1', title: 'Context-aware output encoding', level: 'L1' },
        ],
        'V6 Cryptography': [
          { id: 'V6.1.1', title: 'Regulated data encrypted at rest', level: 'L2' },
          { id: 'V6.2.1', title: 'Strong random number generators', level: 'L1' },
          { id: 'V6.2.3', title: 'Random values generated server-side', level: 'L1' },
          { id: 'V6.2.5', title: 'Password hashing with strong algorithms', level: 'L1' },
        ],
        'V7 Error Handling': [
          { id: 'V7.1.1', title: 'Generic error messages to users', level: 'L1' },
          { id: 'V7.1.2', title: 'Exception handling covers all code', level: 'L2' },
          { id: 'V7.4.1', title: 'Unique error ID for support correlation', level: 'L2' },
        ],
      },
    },
    'CIS Kubernetes Benchmark': {
      version: '1.8.0',
      description: 'Security best practices for Kubernetes deployments',
      categories: {
        'Control Plane': [
          { id: '1.1.1', title: 'Ensure API server --anonymous-auth is false', level: 1 },
          { id: '1.1.2', title: 'Ensure --basic-auth-file is not set', level: 1 },
          { id: '1.1.3', title: 'Ensure --token-auth-file is not set', level: 1 },
          { id: '1.2.1', title: 'Ensure --audit-log-path is set', level: 1 },
        ],
        'Worker Nodes': [
          { id: '4.1.1', title: 'Ensure kubelet service file permissions', level: 1 },
          { id: '4.2.1', title: 'Ensure --anonymous-auth is false for kubelet', level: 1 },
          { id: '4.2.2', title: 'Ensure --authorization-mode is not AlwaysAllow', level: 1 },
        ],
        'Policies': [
          { id: '5.1.1', title: 'Ensure cluster-admin role is only used where required', level: 1 },
          { id: '5.2.1', title: 'Minimize privileged containers', level: 1 },
          { id: '5.2.2', title: 'Minimize containers with allowPrivilegeEscalation', level: 1 },
          { id: '5.2.3', title: 'Minimize root containers', level: 1 },
          { id: '5.3.1', title: 'Ensure default network policies', level: 2 },
          { id: '5.4.1', title: 'Use secrets instead of environment variables', level: 2 },
        ],
      },
    },
    'AWS Security Best Practices': {
      version: '2024',
      description: 'Security recommendations for AWS deployments',
      categories: {
        'Identity and Access': [
          { id: 'IAM.1', title: 'Enable MFA for root account', priority: 'Critical' },
          { id: 'IAM.2', title: 'Do not use root account for daily tasks', priority: 'Critical' },
          { id: 'IAM.3', title: 'Rotate access keys regularly', priority: 'High' },
          { id: 'IAM.4', title: 'Use IAM roles instead of access keys', priority: 'High' },
          { id: 'IAM.5', title: 'Enforce least privilege', priority: 'High' },
          { id: 'IAM.6', title: 'Remove unused IAM users and roles', priority: 'Medium' },
        ],
        'Data Protection': [
          { id: 'S3.1', title: 'Block public access to S3 buckets', priority: 'Critical' },
          { id: 'S3.2', title: 'Enable S3 bucket versioning', priority: 'High' },
          { id: 'S3.3', title: 'Enable S3 server-side encryption', priority: 'High' },
          { id: 'RDS.1', title: 'Enable RDS encryption at rest', priority: 'High' },
          { id: 'RDS.2', title: 'Disable public accessibility for RDS', priority: 'Critical' },
        ],
        'Network Security': [
          { id: 'VPC.1', title: 'Use VPC flow logs', priority: 'High' },
          { id: 'VPC.2', title: 'Restrict default security group', priority: 'High' },
          { id: 'VPC.3', title: 'No security groups allow 0.0.0.0/0 to SSH', priority: 'Critical' },
          { id: 'VPC.4', title: 'Use private subnets for sensitive resources', priority: 'High' },
        ],
        'Logging and Monitoring': [
          { id: 'CT.1', title: 'Enable CloudTrail in all regions', priority: 'Critical' },
          { id: 'CT.2', title: 'Enable CloudTrail log file validation', priority: 'High' },
          { id: 'CW.1', title: 'Set up CloudWatch alarms for security events', priority: 'High' },
          { id: 'GD.1', title: 'Enable GuardDuty', priority: 'High' },
        ],
      },
    },
    'Secure Coding Standards': {
      version: '2024',
      description: 'Language-agnostic secure coding guidelines',
      principles: {
        'Input Validation': [
          'Validate all input on server side',
          'Use allowlists over denylists',
          'Validate data type, length, format, and range',
          'Reject invalid input rather than sanitizing',
          'Apply defense in depth with multiple validation layers',
        ],
        'Output Encoding': [
          'Encode output based on context (HTML, JS, URL, CSS, SQL)',
          'Use framework-provided encoding functions',
          'Never trust user data in any output context',
          'Apply encoding as close to output as possible',
        ],
        'Authentication': [
          'Use strong, adaptive password hashing (bcrypt, argon2)',
          'Implement account lockout after failed attempts',
          'Use MFA where possible',
          'Secure password reset mechanisms',
          'Session tokens must be unpredictable',
        ],
        'Authorization': [
          'Deny by default',
          'Check authorization on every request',
          'Validate object-level access',
          'Use role-based or attribute-based access control',
          'Log authorization failures',
        ],
        'Cryptography': [
          'Use strong, modern algorithms (AES-256, SHA-256+)',
          'Never implement custom cryptography',
          'Use proper key management',
          'Generate cryptographically secure random numbers',
          'Encrypt sensitive data at rest and in transit',
        ],
        'Error Handling': [
          'Use generic error messages for users',
          'Log detailed errors securely',
          'Never expose stack traces in production',
          'Fail securely (deny access on error)',
          'Handle all exceptions explicitly',
        ],
        'Logging': [
          'Log security-relevant events',
          'Never log sensitive data (passwords, tokens, PII)',
          'Include sufficient context for investigation',
          'Protect log integrity',
          'Set appropriate retention periods',
        ],
      },
    },
  },
};

export function registerSecurityBenchmarksResource(server: McpServer): void {
  server.resource(
    'security-benchmarks',
    'security://security-benchmarks',
    {
      description: 'Industry security benchmarks including CIS Docker, OWASP ASVS, and cloud security best practices',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(securityBenchmarks, null, 2),
        },
      ],
    })
  );
}
