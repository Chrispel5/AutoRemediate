# AutoRemediate

![AutoRemediate Interface Preview](public/images/dashboard_preview.png)

AutoRemediate is an automated web security scanner and remediation engine designed for Cloudflare, Amazon CloudFront, Amazon Route 53, and Application Load Balancers (ALB). It audits target domains for security vulnerabilities, presents actionable findings on a browser dashboard, and automatically applies verified remediation policies across cloud edge networks and DNS.

---

## Purpose and Research Scope

AutoRemediate is developed strictly for research, educational security auditing, authorized vulnerability management, and infrastructure hardening. It provides cloud engineers and security researchers with a controlled framework to evaluate edge security posture, audit DNS and HTTP response headers, and validate automated remediation workflows in authorized environments.

---

## Key Features

- **Multi-Cloud Remediation**: Supports automated fixes for Cloudflare Transform Rulesets, Amazon CloudFront Response Headers Policies, ALB listener header attributes (HSTS, CSP, X-Content-Type-Options, X-Frame-Options), and Route 53 DNS records.
- **Comprehensive Auditing**: Inspects HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), DNS records (SPF, DMARC, MX, stale verification TXT), TLS certificates, software version leaks, error disclosure, and cookie security.
- **Verified Fixes**: After every remediation, the tool re-checks live DNS records and HTTP response headers and reports whether the fix is verified or still propagating — results are never assumed.
- **Honest Results**: DNS lookups that time out or fail are reported as inconclusive rather than as false "missing record" failures. Multi-chunk TXT records are joined before parsing.
- **Scan History**: Every scan and remediation is persisted to a local SQLite database (`node:sqlite`, no external dependencies). Past scans, severity counts, and remediation evidence are available from the History panel, and report links survive server restarts.
- **Enterprise Authentication**: Supports IAM Role Assumption (`AssumeRole`), local AWS CLI credential auto-detection (`~/.aws/credentials`), and Cloudflare API Tokens (including zone-scoped tokens).
- **Direct Authoritative Scanning**: Uses direct public DNS resolvers (`1.1.1.1` and `8.8.8.8`) to bypass local OS DNS caching and ensure real-time accuracy.
- **Infrastructure-as-Code Export**: Generates production-ready HashiCorp Terraform (`.tf`) configuration files for all findings, including comment-only compliant-state exports for passing checks.
- **Guided Remediation**: Findings that cannot be auto-fixed (TLS policy, server-level config, application code issues) ship with step-by-step instructions, rollback plans, and verification steps.

---

## Getting Started

### Prerequisites

- Node.js 22.5 or later (the scan history feature uses the built-in `node:sqlite` module)
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
3. **Remediate Vulnerabilities**: Review detected findings on the dashboard. Click **Auto-Fix** on any failing security card to automatically deploy the fix to Cloudflare or AWS. On AWS, header fixes are applied at the ALB listener when the site fronts an Application Load Balancer, and at the CloudFront distribution otherwise; DNS fixes go through Route 53.
4. **Export Infrastructure Code**: Click **Export Terraform** on any finding card to review, copy, or download HCL configuration files.
5. **Review Scan History**: Click **History** in the header to browse previous scans, their severity breakdowns, and links to their reports.

### Notes on AWS Connectivity

- Route 53 and CloudFront are global services; ALB remediation is regional, so set the **AWS Region** field to the region where the load balancer lives.
- The IAM user or role only needs permissions for the services in use (Route 53, CloudFront, and/or Elastic Load Balancing). Least-privilege scoping is recommended.

---

## Architecture Overview

AutoRemediate consists of a lightweight browser dashboard (`public/`), an Express backend server (`server/index.js`), parallel security scanner modules (`server/scanners/`), cloud provider API connectors (`server/connectors/`), automated remediators (`server/remediators/`), and a SQLite persistence layer (`server/db.js`) for scan history.

---

## License

This project is licensed under the MIT License.
