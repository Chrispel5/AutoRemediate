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
        remediationPath = window.isCloudflareConnected 
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
        <span class="infra-value">${target}</span>
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

  function renderFindings(findings, scanId) {
    const list = document.getElementById('findings-list');
    list.innerHTML = '';

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

      card.className = `finding-card ${severityClass}`;
      card.style.animationDelay = `${idx * 0.05}s`;

      const severityBadge = `<span class="severity-badge ${severityClass}">${isPass ? 'PASS' : finding.severity}</span>`;
      
      // Auto-fix controls
      let fixBtn = '';
      let viewFixBtn = '';
      if (finding.fix && !isPass) {
        const fixJson = JSON.stringify(finding.fix).replace(/"/g, '&quot;').replace(/'/g, "&#39;");
        viewFixBtn = `<button class="btn-action btn-view-fix" onclick="window.remediation.open('${finding.id}', '${finding.name}', ${fixJson})">View Fix</button>`;
        const canAutoRemediate = ['dns', 'dns-update', 'dns-delete', 'cloudflare-rule'].includes(finding.fix.type);
        if (canAutoRemediate && window.isCloudflareConnected) {
          fixBtn = `<button class="btn-action btn-fix" onclick="window.remediation.apply('${scanId}', '${finding.id}')">Auto-Fix</button>`;
        }
      }

      // Remediation proof banner
      const proofBanner = finding.remediationDetails
        ? `<div class="remediation-proof" style="margin-top: 10px;">
             <strong>Fix Verified:</strong> ${finding.remediationDetails.verification}
           </div>`
        : '';

      card.innerHTML = `
        <div class="finding-main">
          <div class="finding-title-row">
            ${severityBadge}
            <span class="finding-name-text">${finding.name}</span>
          </div>
          <div class="finding-desc-text">
            ${finding.description || 'No vulnerability description provided.'}
            ${proofBanner}
          </div>
          <button class="evidence-toggle" onclick="window.dashboard.toggleEvidence(this)">
            ▶ Show raw evidence
          </button>
          <div class="evidence-content hidden">${escapeHtml(finding.evidence)}</div>
        </div>
        <div class="finding-actions">
          ${viewFixBtn}
          ${fixBtn}
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
        } else if (scannerCard.className !== 'scanner-card fail') {
          scannerCard.className = 'scanner-card pass';
          scannerCard.querySelector('.scanner-card-status').textContent = 'Secure';
        }
      }
    });
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
    toggleEvidence
  };
})();
