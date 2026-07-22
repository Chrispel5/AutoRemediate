const COMPLIANCE_MAP = {
  "spf-missing": [
    { framework: "NIST", control: "SP 800-177 Email Security" },
    { framework: "SOC 2", control: "CC6.1" }
  ],
  "dmarc-missing": [
    { framework: "NIST", control: "SP 800-177 Email Security" },
    { framework: "SOC 2", control: "CC6.1" }
  ],
  "dkim-missing": [
    { framework: "NIST", control: "SP 800-177 Email Security" },
    { framework: "SOC 2", control: "CC6.1" }
  ],
  "csp-missing": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" },
    { framework: "OWASP", control: "A03:2021 Injection" },
    { framework: "SOC 2", control: "CC6.6" }
  ],
  "hsts-missing": [
    { framework: "OWASP", control: "A02:2021 Cryptographic Failures" },
    { framework: "PCI-DSS", control: "4.2.1" }
  ],
  "xframe-missing": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" }
  ],
  "xcto-missing": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" }
  ],
  "server-version-exposed": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" },
    { framework: "SOC 2", control: "CC7.1" }
  ],
  "cookie-insecure": [
    { framework: "OWASP", control: "A01:2021 Broken Access Control" },
    { framework: "PCI-DSS", control: "6.4.3" }
  ],
  "error-disclosure": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" },
    { framework: "SOC 2", control: "CC7.2" }
  ],
  "subdomain-takeover": [
    { framework: "OWASP", control: "A05:2021 Security Misconfiguration" },
    { framework: "NIST", control: "CM-8 Asset Management" }
  ],
  "stale-txt-token": [
    { framework: "NIST", control: "CM-8 Asset Management" }
  ]
};

function applyCompliance(findings) {
  return findings.map(finding => ({
    ...finding,
    compliance: COMPLIANCE_MAP[finding.id] || []
  }));
}

module.exports = { COMPLIANCE_MAP, applyCompliance };
