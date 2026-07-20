# AutoRemediate 🛡️
> **Automated Web Security Scanner & Remediation Engine**

AutoRemediate is a lightweight, full-stack cybersecurity operations dashboard designed to automate the scanning, detection, and remediation of common web application vulnerabilities. 

Inspired by real-world VAPT assessments, this project transitions security verification from slow, manual ticketing back-and-forths into a fast, automated pipeline.

---

## Key Features

1. **Active/Passive Scanner Suite**
   - **DNS Auditor**: Real TXT record parsing to validate SPF (soft fail vs hard fail enforcement), DMARC policy levels (`p=none` alerts), and MX/DKIM configurations.
   - **HTTP Header Analyzer**: Checks for presence and configuration of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
   - **TLS Certificate Inspector**: Fetches SSL properties to assess expiry dates, cipher suites, and encryption protocols.
   - **Information Leak Detectors**: Analyzes response signatures to catch Server/PHP build versions or stack traces in HTML body errors.
   - **Subdomain Takeover Auditor**: Scans subdomains to map CNAME pointer paths to unclaimed external third-party resources.

2. **One-Click Auto-Remediation**
   - Integrates with the **Cloudflare API v4** using edge rulesets (Transform Rules) to inject security headers without modifying backend application code.
   - Updates DNS SPF and DMARC TXT configurations directly at the nameserver edge.

3. **Infrastructure Fingerprinting**
   - Dynamically determines the target tech stack (Apache, Nginx, S3 Bucket, Vercel, Cloudflare) and selects corresponding remediation code instructions.

4. **PDF/HTML Report Generation**
   - Outputs a print-ready audit report with visual severity metrics, evidence, and applied auto-fixes.

5. **Demo Mode**
   - Includes a sandbox environment showcasing simulated scan findings for testing and presentation purposes.

---

## Tech Stack

- **Backend**: Node.js, Express
- **Frontend**: Vanilla HTML5, CSS3 Custom Properties, Vanilla JavaScript (ES6)
- **APIs & DNS**: Native Node.js `dns.promises` module, `node-fetch` (v2), Cloudflare v4 REST API

---

## Visual Design

- **Cybersecurity Operations Theme**: Sleek, glassmorphism dashboard styled in deep navy (`#05070f`), electric cyan, and glowing red/amber severity badges.
- **Micro-animations**: Interactive grid backdrops, sequential scanning card states, and smooth slide-in panels.
- **Developer-Focused UI**: Code blocks rendered in monospace with clean syntax-like highlights for copy-paste-ready server instructions.

---

## Local Setup & Installation

### Prerequisites
- Node.js (v18+)

### Installation
1. Navigate to the project directory:
   ```bash
   cd AutoRemediate
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the application:
   ```bash
   npm run dev
   ```

4. Access the dashboard:
   - Open your browser to `http://localhost:3000`

---

## Usage Guide

1. **Connect Infrastructure** (Optional)
   - Click **Settings** in the header.
   - Enter a Cloudflare API Token (needs zone read/write privileges).
   - Click **Connect** to link.

2. **Scan target**
   - Enter your target domain in the hero search (e.g. `topnotchguides.com.ng`).
   - Click **Scan Target** and watch the security check cards compile results.

3. **Auto-Remediate**
   - Locate failing findings (e.g., *No DMARC Record Found*).
   - Click **View Fix** to see code blocks or click **Auto-Fix** to push the record directly via Cloudflare API.

4. **Verify & Report**
   - Click **Export Report** to review audit proofs and generate a PDF summary.
