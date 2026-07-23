# AutoRemediate

![AutoRemediate Interface Preview](public/images/dashboard_preview.png)

AutoRemediate is an automated web security scanner and remediation engine designed for Cloudflare, Amazon CloudFront, and Amazon Route 53. It audits target domains for security vulnerabilities, presents actionable findings on a browser dashboard, and automatically applies verified remediation policies across cloud edge networks and DNS.

---

## Purpose and Research Scope

AutoRemediate is developed strictly for research, educational security auditing, authorized vulnerability management, and infrastructure hardening. It provides cloud engineers and security researchers with a controlled framework to evaluate edge security posture, audit DNS and HTTP response headers, and validate automated remediation workflows in authorized environments.

---

## Key Features

- **Dual-Cloud Remediation**: Supports automated fixes for Cloudflare Transform Rulesets, Amazon CloudFront Response Headers Policies, and Route 53 DNS records.
- **Comprehensive Auditing**: Inspects HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), DNS records (SPF, DMARC, MX, DKIM), TLS certificates, software version leaks, and cookie security.
- **Enterprise Authentication**: Supports IAM Role Assumption (`AssumeRole`), local AWS CLI credential auto-detection (`~/.aws/credentials`), and Cloudflare API Tokens.
- **Direct Authoritative Scanning**: Uses direct public DNS resolvers (`1.1.1.1` and `8.8.8.8`) to bypass local OS DNS caching and ensure real-time accuracy.
- **Infrastructure-as-Code Export**: Generates production-ready HashiCorp Terraform (`.tf`) configuration files for all findings.

---

## Getting Started

### Prerequisites

- Node.js 18 or later
- npm

### Installation

```bash
git clone https://github.com/Chrispel5/AutoRemediate.git
cd AutoRemediate
npm install
```

### Running the Application

```bash
npm start
```

Open `http://localhost:3000` in your web browser.

---

## How to Use

1. **Connect Cloud Provider**: Click **Settings** in the top-right header and enter your Cloudflare API Token or AWS Credentials / IAM Role ARN.
2. **Scan Target Domain**: Enter a target domain name (e.g. `topnotchguides.com.ng`) into the central search box and click **Scan Target**.
3. **Remediate Vulnerabilities**: Review detected findings on the dashboard. Click **Auto-Fix** on any failing security card to automatically deploy the fix to Cloudflare or AWS.
4. **Export Infrastructure Code**: Click **Export Terraform** on any finding card to review, copy, or download HCL configuration files.

---

## Architecture Overview

AutoRemediate consists of a lightweight browser dashboard (`public/`), an Express backend server (`server/index.js`), parallel security scanner modules (`server/scanners/`), cloud provider API connectors (`server/connectors/`), and automated remediators (`server/remediators/`).

---

## License

This project is licensed under the MIT License.
