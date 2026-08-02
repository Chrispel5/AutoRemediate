// Dashboard UI Renderer
window.dashboard = (() => {
  function renderInfra(infraType, target) {
    const details = document.getElementById('infra-details');
    let providerName = 'Unknown Web Server';
    let remediationPath = 'Manual / Config modifications';

    switch (infraType) {
      case 'apache':
        providerName = 'Apache HTTP Server';
        remediationPath = 'SSH Access / Configuration patches (Server Agent)';
        break;
      case 'nginx':
        providerName = 'Nginx Reverse Proxy';
        remediationPath = 'SSH Access / config rewrite files';
        break;
      case 's3':
        providerName = 'Amazon S3 Bucket (Static Web) via CloudFront CDN';
        remediationPath = window.connectedProviders && window.connectedProviders.aws
          ? 'CloudFront Response Headers Policy / Route 53 DNS (AWS API)'
          : 'AWS CLI / S3 Bucket metadata config policy';
        break;
      case 'cloudflare':
        providerName = 'Cloudflare proxy edge network';
        remediationPath = 'Cloudflare Rulesets / Transform rules (Cloudflare API)';
        break;
      case 'vercel':
        providerName = 'Vercel Serverless Functions';
        remediationPath = 'Vercel Deployment configuration config file';
        break;
    }

    details.innerHTML = `
      <div class="infra-item">
        <span class="infra-label">Target host</span>
        <span class="infra-value">${escapeHtml(target)}</span>
      </div>
      <div class="infra-item">
        <span class="infra-label">Web infrastructure</span>
        <span class="infra-value">${providerName}</span>
      </div>
      <div class="infra-item">
        <span class="infra-label">Remediation capability</span>
        <span class="infra-value">${remediationPath}</span>
      </div>
    `;
  }

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

  // Operational risk = likelihood that APPLYING the fix breaks production.
  // Independent of vulnerability severity (see server/templates/remediation.js
  // for the full rationale). Mirrors FIX_RISK there — keep the two in sync.
  const FIX_RISK = {
    "hsts-missing":          { level: "high",   basis: "Forces HTTPS across the domain and any subdomains. Browsers cache the max-age (1 year), so an incorrect rollout cannot be quickly reversed." },
    "csp-missing":           { level: "high",   basis: "A policy that misses a legitimate script, style, or third-party origin will block it outright. The most common cause of breakage among header fixes." },
    "spf-missing":           { level: "high",   basis: "Publishing -all rejects mail from any sender not listed. Missing a legitimate sender causes their mail to bounce." },
    "spf-softfail":          { level: "high",   basis: "Tightening ~all to -all converts 'flag as suspicious' into 'reject'. Unlisted legitimate senders start bouncing immediately." },
    "dmarc-missing":         { level: "high",   basis: "A quarantine policy sends unaligned mail to spam. Incomplete SPF/DKIM alignment affects legitimate mail as soon as the record propagates." },
    "dmarc-none":            { level: "high",   basis: "Moving from monitoring to quarantine starts acting on failures that were previously only reported." },
    "subdomain-takeover":    { level: "high",   basis: "Deleting the CNAME takes the subdomain offline if the target was still in use. Confirm the resource is genuinely unclaimed before applying." },
    "xframe-missing":        { level: "medium", basis: "Blocks framing of the site. Breaks legitimate embedding in partner sites or internal tools. Reversible by removing the header." },
    "cookie-insecure":       { level: "medium", basis: "SameSite=Strict can break cross-site sign-in flows and payment redirects." },
    "stale-txt-token":       { level: "medium", basis: "If the associated service is still active, deleting the token revokes its domain verification. Reversible by re-adding the record." },
    "xcto-missing":          { level: "low",    basis: "nosniff only stops MIME-type guessing. Affects legacy browsers serving files with mismatched Content-Type." },
    "referrer-missing":      { level: "low",    basis: "Reduces referrer detail sent to third parties. May affect analytics attribution; no functional impact." },
    "permissions-missing":   { level: "low",    basis: "Restricts browser feature access. Only affects features the site actually requests." },
    "server-version-exposed":{ level: "low",    basis: "Suppresses a diagnostic banner. No functional change to request handling." },
    "xpoweredby-exposed":    { level: "low",    basis: "Removes a purely informational header. No operational impact." },
    "error-disclosure":      { level: "low",    basis: "Errors go to server logs instead of the browser. Behaviour is unchanged." },
    "dkim-missing":          { level: "low",    basis: "Publishing a DKIM key is additive — existing mail flow is unaffected until the provider signs with it." },
    "software-fingerprint-ver": { level: "low", basis: "Removing the generator tag is cosmetic; no functional change." }
  };

  const FIX_TYPE_RISK = {
    "dns":             { level: "medium", basis: "Adds a DNS record. Effects appear as caches expire; reversed by deleting the record." },
    "dns-update":      { level: "medium", basis: "Modifies an existing DNS record. Keep the previous value so it can be restored." },
    "dns-delete":      { level: "medium", basis: "Removes a DNS record. Disruptive if still relied upon; reversible by re-creating it." },
    "cloudflare-rule": { level: "medium", basis: "Injects a response header at the edge for every request. Reversible by disabling the rule." },
    "config":          { level: "medium", basis: "Requires a server configuration change and a service reload. Stage it before production." }
  };

  function computeFixRisk(finding) {
    // No fix is being applied to a passing check, so there is no operational
    // risk to report — the UI omits the row rather than printing "LOW".
    if (finding.status === "PASS") return { level: null, basis: null };
    if (FIX_RISK[finding.id]) return FIX_RISK[finding.id];
    if (finding.fix && FIX_TYPE_RISK[finding.fix.type]) return FIX_TYPE_RISK[finding.fix.type];
    return { level: "medium", basis: "No risk assessment is recorded for this fix. Review the change manually before applying it." };
  }

  function getFallbackRemediation(finding) {
    const risk = computeFixRisk(finding);
    const isTerraformable = ['csp-missing', 'csp', 'hsts-missing', 'hsts', 'xframe-missing', 'xframe-present', 'xcto-missing', 'xcto-present', 'spf-missing', 'spf-softfail', 'spf', 'dmarc-missing', 'dmarc-none', 'dmarc', 'subdomain-takeover', 'subdomain-takeover-clean', 'stale-txt-token', 'stale-txt'].includes(finding.id) || !!finding.fix;

    if (finding.status === "PASS") {
      return {
        readiness: "verified",
        label: "Verified",
        riskLevel: risk.level,
        riskBasis: risk.basis,
        requires: [],
        canAutoFix: false,
        canExportTerraform: isTerraformable
      };
    }
    if (finding.id === "dkim-missing") {
      return {
        readiness: "needs_input",
        label: "Needs DKIM value",
        riskLevel: risk.level,
        riskBasis: risk.basis,
        requires: ["Email provider DKIM key"],
        canAutoFix: false,
        canExportTerraform: false
      };
    }
    if (finding.fix) {
      if (['dns', 'dns-update', 'cloudflare-rule'].includes(finding.fix.type)) {
        return {
          readiness: "auto_fixable",
          label: "Auto-fixable",
          riskLevel: risk.level,
          riskBasis: risk.basis,
          requires: ["Cloud provider API access"],
          canAutoFix: true,
          canExportTerraform: true
        };
      }
      if (finding.fix.type === "dns-delete") {
        return {
          readiness: "auto_fixable",
          label: "Auto-fixable",
          riskLevel: risk.level,
          riskBasis: risk.basis,
          requires: ["DNS write access"],
          canAutoFix: true,
          canExportTerraform: true
        };
      }
      if (finding.fix.type === "config") {
        return {
          readiness: "generate_patch",
          label: "Generate patch",
          riskLevel: risk.level,
          riskBasis: risk.basis,
          requires: ["Server configuration access"],
          canAutoFix: false,
          canExportTerraform: false
        };
      }
    }
    return {
      readiness: "manual",
      label: "Manual Fix",
      riskLevel: risk.level,
      riskBasis: risk.basis,
      requires: ["Administrator access"],
      canAutoFix: false,
      canExportTerraform: false
    };
  }

  function renderFindings(findings, scanId) {
    const list = document.getElementById('findings-list');
    list.innerHTML = '';

    window.currentFindings = findings;
    window.currentScanId = scanId;

    // Calculate counters
    let counts = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, PASS: 0 };
    findings.forEach(f => {
      if (f.status === 'PASS') {
        counts.PASS++;
      } else {
        counts[f.severity]++;
      }
    });

    // Update stats
    document.getElementById('stat-critical').textContent = `${counts.CRITICAL} Critical`;
    document.getElementById('stat-high').textContent = `${counts.HIGH} High`;
    document.getElementById('stat-moderate').textContent = `${counts.MODERATE} Moderate`;
    document.getElementById('stat-low').textContent = `${counts.LOW} Low`;
    document.getElementById('stat-pass').textContent = `${counts.PASS} Passed / Fixed`;

    // Sort findings: FAIL (Critical -> High -> Moderate -> Low) then PASS
    const sorted = [...findings].sort((a, b) => {
      if (a.status === 'PASS' && b.status !== 'PASS') return 1;
      if (a.status !== 'PASS' && b.status === 'PASS') return -1;
      
      const severityOrder = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, PASS: 0 };
      const aSev = a.status === 'PASS' ? 0 : severityOrder[a.severity];
      const bSev = b.status === 'PASS' ? 0 : severityOrder[b.severity];
      return bSev - aSev;
    });

    sorted.forEach((finding, idx) => {
      const card = document.createElement('div');
      const isPass = finding.status === 'PASS';
      const severityClass = isPass ? 'pass' : finding.severity.toLowerCase();

      // Ensure remediation metadata & compliance are populated
      if (!finding.remediation) {
        finding.remediation = getFallbackRemediation(finding);
      }
      if (!finding.compliance) {
        finding.compliance = COMPLIANCE_MAP[finding.id] || [];
      }

      card.className = `finding-card ${severityClass}`;
      card.style.animationDelay = `${idx * 0.05}s`;

      const severityBadge = `<span class="severity-badge ${severityClass}">${isPass ? 'PASS' : finding.severity}</span>`;
      const readinessBadge = `<span class="badge-readiness ${finding.remediation.readiness}">${finding.remediation.label}</span>`;
      
      let complianceBadges = '';
      if (finding.compliance && finding.compliance.length > 0) {
        complianceBadges = `<div class="compliance-container">` + 
          finding.compliance.map(c => `<span class="badge-compliance">${escapeHtml(c.framework)} ${escapeHtml(c.control)}</span>`).join('') + 
          `</div>`;
      }

      // Build Action Buttons
      let actionButtons = `<button class="btn-action btn-view-fix" onclick="window.remediation.openCopilot('${finding.id}')">Copilot</button>`;

      if (!isPass) {
        if (finding.remediation.canAutoFix) {
          actionButtons += ` <button class="btn-action btn-fix" onclick="window.remediation.apply('${scanId}', '${finding.id}')">Auto-Fix</button>`;
        }
        
        if (finding.remediation.readiness === 'needs_input') {
          actionButtons += ` <button class="btn-action btn-view-fix" disabled title="Coming soon">Provide Details</button>`;
        }
        
        if (finding.remediation.readiness === 'generate_patch') {
          actionButtons += ` <button class="btn-action btn-view-fix" disabled title="Coming soon">Generate Patch</button>`;
        }
      }

      if (finding.remediation.canExportTerraform) {
        actionButtons += ` <button class="btn-action btn-view-fix" onclick="window.remediation.exportTerraform('${finding.id}')">Export Terraform</button>`;
      }

      // Remediation proof banner.
      // BUG A2: this always said "Fix Verified", even when the remediator
      // explicitly reported "propagation pending" / "not yet visible" — i.e.
      // the change was pushed but never observed live. Label from the
      // verification text so a pending fix is not presented as confirmed.
      let proofBanner = '';
      if (finding.remediationDetails) {
        const verificationText = finding.remediationDetails.verification || '';
        const isConfirmed = /^verified/i.test(verificationText.trim())
          && !/pending|not yet|verify manually/i.test(verificationText);
        const proofLabel = isConfirmed ? 'Fix Verified:' : 'Fix Applied — Not Yet Confirmed:';
        proofBanner = `<div class="remediation-proof ${isConfirmed ? '' : 'pending'}" style="margin-top: 10px;">
             <strong>${proofLabel}</strong> ${escapeHtml(verificationText)}
           </div>`;
      }

      card.innerHTML = `
        <div class="finding-main">
          <div class="finding-title-row">
            ${severityBadge}
            ${readinessBadge}
            <span class="finding-name-text">${escapeHtml(finding.name)}</span>
          </div>
          <div class="finding-desc-text">
            ${escapeHtml(finding.description || 'No vulnerability description provided.')}
            ${proofBanner}
            ${complianceBadges}
          </div>
          <button class="evidence-toggle" onclick="window.dashboard.toggleEvidence(this)">
            ▶ Show raw evidence
          </button>
          <div class="evidence-content hidden">${escapeHtml(finding.evidence)}</div>
        </div>
        <div class="finding-actions">
          ${actionButtons}
        </div>
      `;

      list.appendChild(card);

      // Update the scanner card status indicator
      const scannerId = mapFindingToScanner(finding.id);
      const scannerCard = document.getElementById(scannerId);
      if (scannerCard) {
        if (finding.status === 'FAIL') {
          scannerCard.className = 'scanner-card fail';
          scannerCard.querySelector('.scanner-card-status').textContent = 'Vulnerable';
        } else if (!scannerCard.classList.contains('fail')) {
          scannerCard.className = 'scanner-card pass';
          scannerCard.querySelector('.scanner-card-status').textContent = 'Secure';
        }
      }
    });

    // Sweep any scanner cards left in the scanning state (no finding produced)
    if (window.scanner && window.scanner.finishGrid) {
      window.scanner.finishGrid();
    }
  }

  function toggleEvidence(btn) {
    const parent = btn.parentElement;
    const content = parent.querySelector('.evidence-content');
    if (content.classList.contains('hidden')) {
      content.classList.remove('hidden');
      btn.textContent = '▼ Hide evidence';
    } else {
      content.classList.add('hidden');
      btn.textContent = '▶ Show raw evidence';
    }
  }

  function mapFindingToScanner(findingId) {
    if (findingId.startsWith('spf') || findingId.startsWith('dmarc') || findingId.startsWith('mx') || findingId.startsWith('dkim') || findingId.startsWith('stale-txt')) {
      return 'scanner-dns';
    }
    if (findingId.startsWith('csp') || findingId.startsWith('hsts') || findingId.startsWith('xframe') || findingId.startsWith('xcto') || findingId.startsWith('referrer') || findingId.startsWith('permissions') || findingId.startsWith('server-version') || findingId.startsWith('xpoweredby')) {
      return 'scanner-headers';
    }
    if (findingId.startsWith('tls')) return 'scanner-tls';
    if (findingId.startsWith('software-fingerprint')) return 'scanner-software';
    if (findingId.startsWith('error-disclosure')) return 'scanner-errors';
    if (findingId.startsWith('cookie')) return 'scanner-cookies';
    if (findingId.startsWith('subdomain')) return 'scanner-subdomains';
    return 'scanner-headers';
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  return {
    renderInfra,
    renderFindings,
    toggleEvidence,
    getFallbackRemediation
  };
})();
