import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const complianceMapping = {
  description: 'Mapping of vulnerability types to compliance framework requirements',
  frameworks: {
    'PCI-DSS': {
      name: 'Payment Card Industry Data Security Standard',
      version: '4.0',
      requirements: [
        {
          id: 'PCI-DSS 6.2.4',
          title: 'Secure Coding Practices',
          description: 'Software engineering techniques or other methods address at least the following common software attacks',
          mappedCWEs: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-22', 'CWE-352'],
          vulnerabilityTypes: ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal', 'CSRF'],
        },
        {
          id: 'PCI-DSS 6.3.1',
          title: 'Security Vulnerabilities',
          description: 'Security vulnerabilities are identified and managed',
          mappedCWEs: ['CWE-119', 'CWE-120', 'CWE-787', 'CWE-125'],
          vulnerabilityTypes: ['Buffer Overflow', 'Memory Corruption'],
        },
        {
          id: 'PCI-DSS 6.5.1',
          title: 'Injection Flaws',
          description: 'Injection flaws, particularly SQL injection',
          mappedCWEs: ['CWE-89', 'CWE-943', 'CWE-90', 'CWE-91'],
          vulnerabilityTypes: ['SQL Injection', 'NoSQL Injection', 'LDAP Injection', 'XML Injection'],
        },
        {
          id: 'PCI-DSS 6.5.7',
          title: 'Cross-site Scripting (XSS)',
          description: 'Cross-site scripting vulnerabilities',
          mappedCWEs: ['CWE-79'],
          vulnerabilityTypes: ['XSS', 'Reflected XSS', 'Stored XSS', 'DOM XSS'],
        },
        {
          id: 'PCI-DSS 8.3.1',
          title: 'Strong Authentication',
          description: 'Strong authentication for user access',
          mappedCWEs: ['CWE-287', 'CWE-306', 'CWE-798'],
          vulnerabilityTypes: ['Authentication Bypass', 'Hardcoded Credentials', 'Missing Authentication'],
        },
        {
          id: 'PCI-DSS 8.6.1',
          title: 'Password Complexity',
          description: 'Application and system account passwords meet complexity requirements',
          mappedCWEs: ['CWE-521', 'CWE-263'],
          vulnerabilityTypes: ['Weak Password', 'Password Policy'],
        },
        {
          id: 'PCI-DSS 3.4.1',
          title: 'Encryption of Stored Data',
          description: 'PAN is rendered unreadable using strong cryptography',
          mappedCWEs: ['CWE-311', 'CWE-312', 'CWE-327', 'CWE-328'],
          vulnerabilityTypes: ['Unencrypted Data', 'Weak Encryption', 'Weak Hashing'],
        },
        {
          id: 'PCI-DSS 4.2.1',
          title: 'Encryption in Transit',
          description: 'Strong cryptography during transmission',
          mappedCWEs: ['CWE-319', 'CWE-523'],
          vulnerabilityTypes: ['Cleartext Transmission', 'Missing TLS'],
        },
      ],
    },
    'HIPAA': {
      name: 'Health Insurance Portability and Accountability Act',
      version: '2013 Final Rule',
      requirements: [
        {
          id: 'HIPAA 164.312(a)(1)',
          title: 'Access Control',
          description: 'Implement technical policies to allow access only to authorized persons',
          mappedCWEs: ['CWE-284', 'CWE-285', 'CWE-862', 'CWE-863'],
          vulnerabilityTypes: ['Access Control', 'Authorization Bypass', 'IDOR'],
        },
        {
          id: 'HIPAA 164.312(a)(2)(iv)',
          title: 'Encryption and Decryption',
          description: 'Implement mechanism to encrypt and decrypt ePHI',
          mappedCWEs: ['CWE-311', 'CWE-312', 'CWE-326', 'CWE-327'],
          vulnerabilityTypes: ['Missing Encryption', 'Weak Encryption'],
        },
        {
          id: 'HIPAA 164.312(b)',
          title: 'Audit Controls',
          description: 'Implement hardware, software, and procedural mechanisms to record activity',
          mappedCWEs: ['CWE-778'],
          vulnerabilityTypes: ['Insufficient Logging', 'Missing Audit Trail'],
        },
        {
          id: 'HIPAA 164.312(c)(1)',
          title: 'Integrity Controls',
          description: 'Implement policies to protect ePHI from improper alteration or destruction',
          mappedCWEs: ['CWE-345', 'CWE-354', 'CWE-924'],
          vulnerabilityTypes: ['Data Integrity', 'Missing Integrity Check'],
        },
        {
          id: 'HIPAA 164.312(d)',
          title: 'Person or Entity Authentication',
          description: 'Verify that person or entity seeking access is the one claimed',
          mappedCWEs: ['CWE-287', 'CWE-290', 'CWE-294'],
          vulnerabilityTypes: ['Authentication Bypass', 'Spoofing'],
        },
        {
          id: 'HIPAA 164.312(e)(1)',
          title: 'Transmission Security',
          description: 'Implement technical security measures to guard against unauthorized access during transmission',
          mappedCWEs: ['CWE-319', 'CWE-523', 'CWE-300'],
          vulnerabilityTypes: ['Cleartext Transmission', 'Missing TLS', 'Man-in-the-Middle'],
        },
      ],
    },
    'SOC2': {
      name: 'Service Organization Control 2',
      version: '2017',
      requirements: [
        {
          id: 'SOC2 CC6.1',
          title: 'Logical Access Security',
          description: 'The entity implements logical access security measures',
          mappedCWEs: ['CWE-284', 'CWE-287', 'CWE-285'],
          vulnerabilityTypes: ['Access Control', 'Authentication', 'Authorization'],
        },
        {
          id: 'SOC2 CC6.6',
          title: 'Security of Data in Transit',
          description: 'The entity implements logical access security measures',
          mappedCWEs: ['CWE-319', 'CWE-326'],
          vulnerabilityTypes: ['Cleartext Transmission', 'Weak Encryption'],
        },
        {
          id: 'SOC2 CC6.7',
          title: 'Security of Data at Rest',
          description: 'The entity restricts the transmission, movement, and removal of information',
          mappedCWEs: ['CWE-311', 'CWE-312'],
          vulnerabilityTypes: ['Unencrypted Data at Rest'],
        },
        {
          id: 'SOC2 CC7.1',
          title: 'Detection of Malicious Code',
          description: 'System processing is accurate and complete',
          mappedCWEs: ['CWE-94', 'CWE-95', 'CWE-96'],
          vulnerabilityTypes: ['Code Injection', 'Malicious Code'],
        },
        {
          id: 'SOC2 CC7.2',
          title: 'Vulnerability Management',
          description: 'The entity monitors system components for anomalies',
          mappedCWEs: ['All CWEs'],
          vulnerabilityTypes: ['All Vulnerability Types'],
        },
      ],
    },
    'GDPR': {
      name: 'General Data Protection Regulation',
      version: '2016/679',
      requirements: [
        {
          id: 'GDPR Article 25',
          title: 'Data Protection by Design',
          description: 'Implement appropriate technical measures to protect personal data',
          mappedCWEs: ['CWE-311', 'CWE-312', 'CWE-359'],
          vulnerabilityTypes: ['Data Exposure', 'Missing Encryption', 'Privacy Violation'],
        },
        {
          id: 'GDPR Article 32',
          title: 'Security of Processing',
          description: 'Implement appropriate technical and organizational measures',
          mappedCWEs: ['CWE-284', 'CWE-311', 'CWE-326'],
          vulnerabilityTypes: ['Access Control', 'Encryption', 'Data Protection'],
        },
        {
          id: 'GDPR Article 33',
          title: 'Breach Notification',
          description: 'Notification of personal data breach',
          mappedCWEs: ['CWE-778', 'CWE-223'],
          vulnerabilityTypes: ['Insufficient Logging', 'Missing Breach Detection'],
        },
        {
          id: 'GDPR Article 5(1)(f)',
          title: 'Integrity and Confidentiality',
          description: 'Processed in a manner that ensures security of personal data',
          mappedCWEs: ['CWE-89', 'CWE-79', 'CWE-287', 'CWE-311'],
          vulnerabilityTypes: ['Injection', 'XSS', 'Authentication', 'Encryption'],
        },
      ],
    },
    'NIST-CSF': {
      name: 'NIST Cybersecurity Framework',
      version: '2.0',
      requirements: [
        {
          id: 'NIST PR.AC-1',
          title: 'Identity Management and Access Control',
          description: 'Identities and credentials are managed',
          mappedCWEs: ['CWE-284', 'CWE-287', 'CWE-798'],
          vulnerabilityTypes: ['Access Control', 'Authentication', 'Hardcoded Credentials'],
        },
        {
          id: 'NIST PR.DS-1',
          title: 'Data-at-Rest Protection',
          description: 'Data-at-rest is protected',
          mappedCWEs: ['CWE-311', 'CWE-312'],
          vulnerabilityTypes: ['Unencrypted Data'],
        },
        {
          id: 'NIST PR.DS-2',
          title: 'Data-in-Transit Protection',
          description: 'Data-in-transit is protected',
          mappedCWEs: ['CWE-319', 'CWE-523'],
          vulnerabilityTypes: ['Cleartext Transmission'],
        },
        {
          id: 'NIST DE.CM-4',
          title: 'Malicious Code Detection',
          description: 'Malicious code is detected',
          mappedCWEs: ['CWE-94', 'CWE-502'],
          vulnerabilityTypes: ['Code Injection', 'Deserialization'],
        },
        {
          id: 'NIST DE.CM-8',
          title: 'Vulnerability Scans',
          description: 'Vulnerability scans are performed',
          mappedCWEs: ['All CWEs'],
          vulnerabilityTypes: ['All Vulnerability Types'],
        },
      ],
    },
  },
  cweToCompliance: {
    'CWE-89': ['PCI-DSS 6.5.1', 'GDPR Article 5(1)(f)', 'SOC2 CC6.1'],
    'CWE-79': ['PCI-DSS 6.5.7', 'GDPR Article 5(1)(f)', 'NIST DE.CM-4'],
    'CWE-78': ['PCI-DSS 6.2.4', 'NIST DE.CM-4'],
    'CWE-287': ['PCI-DSS 8.3.1', 'HIPAA 164.312(d)', 'GDPR Article 5(1)(f)', 'SOC2 CC6.1'],
    'CWE-311': ['PCI-DSS 3.4.1', 'HIPAA 164.312(a)(2)(iv)', 'GDPR Article 32', 'NIST PR.DS-1'],
    'CWE-319': ['PCI-DSS 4.2.1', 'HIPAA 164.312(e)(1)', 'SOC2 CC6.6', 'NIST PR.DS-2'],
    'CWE-798': ['PCI-DSS 8.3.1', 'NIST PR.AC-1'],
    'CWE-502': ['NIST DE.CM-4', 'SOC2 CC7.1'],
    'CWE-22': ['PCI-DSS 6.2.4'],
    'CWE-352': ['PCI-DSS 6.2.4'],
  },
};

export function registerComplianceMappingResource(server: McpServer): void {
  server.resource(
    'compliance-mapping',
    'security://compliance-mapping',
    {
      description: 'Mapping of vulnerabilities to compliance frameworks (PCI-DSS, HIPAA, SOC2, GDPR, NIST CSF)',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(complianceMapping, null, 2),
        },
      ],
    })
  );
}
