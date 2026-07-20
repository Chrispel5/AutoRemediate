// Remediation Panel Manager
window.remediation = (() => {
  const panel = document.getElementById('remediation-panel');
  const title = document.getElementById('remediation-title');
  const content = document.getElementById('remediation-content');
  const closeBtn = document.getElementById('btn-close-remediation');

  closeBtn.addEventListener('click', close);

  // Client-side mapping of remediation fix details
  const FIX_TEMPLATES = {
    'csp-missing': {
      title: 'Missing Content-Security-Policy Header',
      apache: {
        file: '/etc/apache2/sites-enabled/your-site.conf',
        code: `<LocationMatch "^/">\n    Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"\n</LocationMatch>`,
        notes: 'Add inside virtual host block, then reload Apache.'
      },
      nginx: {
        file: '/etc/nginx/sites-enabled/your-site',
        code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;`,
        notes: 'Add inside server or location / block, then reload Nginx.'
      },
      cloudflare: {
        code: `Cloudflare Transform Rule:\nAction: Modify Response Header\nHeader: Content-Security-Policy\nValue: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"`,
        notes: 'No server reboot required. Fix applies instantly at the CDN edge.'
      },
      s3: {
        code: `aws cloudfront create-response-headers-policy \\\n  --response-headers-policy-config '{\n    "Name": "SetCSPPolicy",\n    "SecurityHeadersConfig": {\n      "ContentSecurityPolicy": {\n        "Expression": "default-src '"'self'"'",\n        "Override": true\n      }\n    }\n  }'`,
        notes: 'Apply custom header policy configuration on target CloudFront distribution.'
      }
    },
    'server-version-exposed': {
      title: 'Server Version Disclosure',
      apache: {
        file: '/etc/apache2/conf-enabled/security.conf',
        code: `ServerTokens Prod\nServerSignature Off`,
        notes: 'Reduces Server header signature back to "Apache" instead of full version/OS tags.'
      },
      nginx: {
        file: '/etc/nginx/nginx.conf',
        code: `server_tokens off;`,
        notes: 'Add inside the http block.'
      },
      s3: { notes: 'N/A — Amazon S3 does not expose build numbers.' },
      cloudflare: { notes: 'N/A — Cloudflare conceals internal build parameters.' }
    },
    'dmarc-missing': {
      title: 'DMARC Policy Not Enabled',
      all: {
        type: 'dns',
        record: 'TXT',
        name: '_dmarc.YOUR_DOMAIN',
        value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@YOUR_DOMAIN;',
        notes: 'Quarantines spoofed/unauthenticated emails to recipient spam/quarantine bins.'
      }
    },
    'dmarc-none': {
      title: 'DMARC Policy p=none Not Enforcing',
      all: {
        type: 'dns',
        record: 'TXT',
        name: '_dmarc.YOUR_DOMAIN',
        value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@YOUR_DOMAIN;',
        notes: 'Transition policy from monitoring (p=none) to quarantine or reject status.'
      }
    },
    'spf-softfail': {
      title: 'SPF Soft Fail Enabled (~all)',
      all: {
        type: 'dns',
        record: 'TXT',
        name: 'YOUR_DOMAIN',
        value: 'v=spf1 include:_spf.google.com -all',
        notes: 'Change the ending mechanism parameters from ~all to -all for strict IP blocking.'
      }
    },
    'hsts-missing': {
      title: 'HTTP Strict Transport Security (HSTS) Missing',
      apache: {
        file: '/etc/apache2/sites-enabled/your-site.conf',
        code: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
        notes: 'Enforces HTTPS redirecting before browser handshake executes.'
      },
      nginx: {
        file: '/etc/nginx/sites-enabled/your-site',
        code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
        notes: 'Must be placed inside the server SSL block.'
      },
      cloudflare: {
        notes: 'Enable HSTS under Edge Certificates within Cloudflare SSL/TLS tab panel.'
      }
    },
    'error-disclosure': {
      title: 'Database Exceptions / Verbose Errors exposed',
      apache: {
        file: 'php.ini',
        code: `display_errors = Off\nlog_errors = On\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT`,
        notes: 'Redirects PHP engine runtime alerts to backend disk logging instead of render paths.'
      },
      nginx: {
        file: 'php-fpm pool config',
        code: `php_flag[display_errors] = off`,
        notes: 'Set display flags to off inside the fpm virtual configurations pool.'
      },
      s3: { notes: 'N/A — static folders cannot leak dynamic stack traces.' }
    },
    'cookie-insecure': {
      title: 'Session Cookies Lack Security Directives',
      apache: {
        file: '/etc/apache2/sites-enabled/your-site.conf',
        code: `Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"`,
        notes: 'Enforces HttpOnly, Secure, and SameSite parameters on standard headers.'
      },
      nginx: {
        file: '/etc/nginx/nginx.conf',
        code: `proxy_cookie_flags ~ secure httponly samesite=strict;`,
        notes: 'Requires proxy module headers injection enabled.'
      }
    },
    'xframe-missing': {
      title: 'X-Frame-Options Clickjacking unprotected',
      apache: { code: `Header always set X-Frame-Options "DENY"` },
      nginx: { code: `add_header X-Frame-Options "DENY" always;` },
      cloudflare: { notes: 'Add custom response header transform rule setting X-Frame-Options to DENY.' }
    },
    'xcto-missing': {
      title: 'X-Content-Type-Options Missing',
      apache: { code: `Header always set X-Content-Type-Options "nosniff"` },
      nginx: { code: `add_header X-Content-Type-Options "nosniff" always;` },
      cloudflare: { notes: 'Configure header rewrite adding nosniff parameters.' }
    },
    'xpoweredby-exposed': {
      title: 'X-Powered-By Tech Stack Exposing',
      apache: {
        file: 'php.ini',
        code: `expose_php = Off`,
        notes: 'Disables default compiler metadata header outputs.'
      },
      nginx: {
        code: `proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;`,
        notes: 'Prevents backend application runtime servers info leakage.'
      }
    },
    'stale-txt-token': {
      title: 'Stale DNS TXT Tokens',
      all: {
        type: 'dns-delete',
        record: 'TXT',
        name: 'YOUR_DOMAIN',
        value: 'Verification token string',
        notes: 'Clean up legacy Search Console or verification entries no longer in active use.'
      }
    },
    'subdomain-takeover': {
      title: 'Dangling CNAME Takeover Vulnerability',
      all: {
        type: 'dns-delete',
        record: 'CNAME',
        name: 'dangling.example.com',
        value: 'unclaimed-service.cloudfront.net',
        notes: 'Remove the stale CNAME DNS routing mapping configuration.'
      }
    }
  };

  function open(findingId, name, fixObj) {
    title.textContent = name;
    panel.classList.remove('hidden');

    const template = FIX_TEMPLATES[findingId];
    if (!template) {
      content.innerHTML = `
        <div class="fix-instruction">No detailed remediation instructions indexed for this finding.</div>
        <pre><code>${escapeHtml(JSON.stringify(fixObj, null, 2))}</code></pre>
      `;
      return;
    }

    let innerHTML = '';

    // Render client fixes tabs based on platforms
    if (template.all) {
      // DNS Record Configuration
      const dnsRec = template.all;
      innerHTML += `
        <div class="fix-instruction">
          <p style="margin-bottom:10px;">Configure the following DNS record at your Domain Nameserver hosting provider (e.g. Cloudflare, Route53, GoDaddy):</p>
          <p style="margin-bottom:15px;"><strong>${dnsRec.notes}</strong></p>
        </div>
        <div class="code-container">
          <button class="btn-copy" onclick="window.remediation.copy(this)">Copy</button>
          <pre><code>Type:   ${dnsRec.record}\nName:   ${dnsRec.name}\nValue:  ${dnsRec.value}</code></pre>
        </div>
      `;
    } else {
      // Server-Specific configurations
      if (template.cloudflare) {
        innerHTML += `
          <div class="glass-card" style="margin-bottom:15px; border-color: rgba(0, 212, 255, 0.2);">
            <strong style="color:var(--primary); font-size:13px; display:block; margin-bottom:5px;">Edge Fix (Cloudflare Transform Rules)</strong>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px;">${template.cloudflare.notes}</p>
            <pre style="background:#090c15; padding:10px; border-radius:6px; font-size:11px; font-family:var(--font-mono); overflow-x:auto;"><code>${template.cloudflare.code || 'Transform Rule Configuration'}</code></pre>
          </div>
        `;
      }
      
      if (template.apache) {
        innerHTML += `
          <div class="glass-card" style="margin-bottom:15px;">
            <strong style="color:#ff6b35; font-size:13px; display:block; margin-bottom:5px;">Apache Configuration (Traditional Server)</strong>
            <p style="font-size:11px; color:var(--text-muted); margin-bottom:5px;">Target file: <code>${template.apache.file}</code></p>
            <div class="code-container">
              <button class="btn-copy" onclick="window.remediation.copy(this)">Copy</button>
              <pre><code>${escapeHtml(template.apache.code)}</code></pre>
            </div>
            <small style="display:block; margin-top:5px; font-size:11px; color:var(--text-muted);">${template.apache.notes}</small>
          </div>
        `;
      }

      if (template.nginx) {
        innerHTML += `
          <div class="glass-card" style="margin-bottom:15px;">
            <strong style="color:#ffb800; font-size:13px; display:block; margin-bottom:5px;">Nginx Configuration (Traditional Server)</strong>
            <p style="font-size:11px; color:var(--text-muted); margin-bottom:5px;">Target file: <code>${template.nginx.file || 'sites-enabled config'}</code></p>
            <div class="code-container">
              <button class="btn-copy" onclick="window.remediation.copy(this)">Copy</button>
              <pre><code>${escapeHtml(template.nginx.code)}</code></pre>
            </div>
            <small style="display:block; margin-top:5px; font-size:11px; color:var(--text-muted);">${template.nginx.notes}</small>
          </div>
        `;
      }
    }

    content.innerHTML = innerHTML;
  }

  function close() {
    panel.classList.add('hidden');
  }

  async function apply(scanId, findingId) {
    // Target Auto-Fix directly
    const verifyConfirm = confirm('Are you sure you want to apply this auto-remediation rule via Cloudflare API?');
    if (!verifyConfirm) return;

    try {
      const response = await fetch('/api/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId, findingId })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        alert('Vulnerability successfully auto-remediated and verified!');
        
        // Update the specific finding card in-place using backend response
        const card = document.querySelector(`[onclick*="'${findingId}'"]`);
        if (card) {
          const findingCard = card.closest('.finding-card');
          if (findingCard) {
            findingCard.className = 'finding-card pass';
            const badge = findingCard.querySelector('.severity-badge');
            if (badge) { badge.className = 'severity-badge pass'; badge.textContent = 'PASS'; }
            const actions = findingCard.querySelector('.finding-actions');
            if (actions) { actions.innerHTML = '<span style="color:var(--pass);font-weight:700;">✅ Fixed</span>'; }
          }
        }
      } else {
        alert(`Remediation Failed: ${data.error}`);
      }
    } catch (e) {
      alert(`Error applying fix: ${e.message}`);
    }
  }

  function copy(btn) {
    const pre = btn.parentElement.querySelector('pre');
    navigator.clipboard.writeText(pre.textContent.replace('Copy', '').trim());
    btn.textContent = 'Copied!';
    setTimeout(() => {
      btn.textContent = 'Copy';
    }, 2000);
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
    open,
    close,
    apply,
    copy
  };
})();
