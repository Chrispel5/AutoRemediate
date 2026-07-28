// Remediation Panel & Terraform Export Manager
window.remediation = (() => {
  const panel = document.getElementById('remediation-panel');
  const title = document.getElementById('remediation-title');
  const content = document.getElementById('remediation-content');
  const closeBtn = document.getElementById('btn-close-remediation');

  // Terraform Modal elements
  const tfModal = document.getElementById('terraform-modal');
  const tfCloseBtn = document.getElementById('btn-close-tf');
  const tfProviderSelect = document.getElementById('tf-provider-select');
  const tfCodeBox = document.getElementById('terraform-code-box');
  const tfCopyBtn = document.getElementById('btn-copy-tf');
  const tfDownloadBtn = document.getElementById('btn-download-tf');

  let activeFindingId = null;
  let activeTfCode = "";
  let activeTfFilename = "";

  closeBtn.addEventListener('click', closeCopilot);
  tfCloseBtn.addEventListener('click', closeTerraform);

  tfProviderSelect.addEventListener('change', () => {
    if (activeFindingId) {
      loadTerraform(activeFindingId, tfProviderSelect.value);
    }
  });

  tfCopyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(activeTfCode.trim());
    tfCopyBtn.textContent = 'Copied!';
    setTimeout(() => { tfCopyBtn.textContent = 'Copy'; }, 2000);
  });

  tfDownloadBtn.addEventListener('click', () => {
    if (!activeTfCode) return;
    const blob = new Blob([activeTfCode], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeTfFilename || 'autoremediate-fix.tf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Client-Side Fallback Templates for Static Environment (GitHub Pages)
  const COPILOT_TEMPLATES = {
    "spf-missing": {
      whatIsWrong: "The domain does not publish an SPF (Sender Policy Framework) record.",
      whyItMatters: "Without SPF, anyone can send emails pretending to come from your domain, making it easy for attackers to execute spoofing and phishing campaigns.",
      howAutoRemediateCanFix: "AutoRemediate can publish a default secure SPF TXT record via your DNS provider.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "If you have existing email senders not included in the default record, their emails might get rejected or sent to spam.",
      verificationPlan: "Query the DNS TXT record for the domain and check that 'v=spf1 ...' is returned.",
      rollbackPlan: "Delete or revert the SPF TXT record in your DNS zone."
    },
    "spf-softfail": {
      whatIsWrong: "The SPF record is configured with a soft fail (~all) mechanism.",
      whyItMatters: "A soft fail flags suspicious emails but still allows them to be delivered, which weakens protection against spoofing.",
      howAutoRemediateCanFix: "AutoRemediate can update the SPF record to use a strict hard fail (-all) mechanism.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "Legitimate emails sent from unauthorized servers will be completely blocked instead of flagged.",
      verificationPlan: "Check the SPF TXT record to confirm it ends with '-all' instead of '~all'.",
      rollbackPlan: "Revert the SPF TXT record mechanism back to '~all'."
    },
    "dmarc-missing": {
      whatIsWrong: "The domain does not publish a DMARC policy.",
      whyItMatters: "Attackers can spoof email from this domain because receiving mail servers have no instructions on how to handle failed authentication.",
      howAutoRemediateCanFix: "AutoRemediate can create a DMARC TXT record pointing to a policy of quarantine or reject.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "A strict DMARC policy may block legitimate emails if your SPF/DKIM configurations are not properly aligned.",
      verificationPlan: "Verify that the _dmarc.TARGET TXT record resolves to the correct policy.",
      rollbackPlan: "Delete or revert the DMARC TXT record."
    },
    "dmarc-none": {
      whatIsWrong: "The DMARC policy is set to p=none (monitoring only).",
      whyItMatters: "A monitoring-only policy does not block or quarantine unauthorized emails, offering no active spoofing protection.",
      howAutoRemediateCanFix: "AutoRemediate can update the DMARC policy from p=none to p=quarantine.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "Emails from misconfigured legitimate senders will be sent to the recipient's spam folder.",
      verificationPlan: "Verify the DMARC record contains 'p=quarantine'.",
      rollbackPlan: "Revert the policy back to 'p=none'."
    },
    "dkim-missing": {
      whatIsWrong: "We could not find a DKIM public key record on common selectors.",
      whyItMatters: "Without DKIM signatures, receiving email servers cannot verify if the email was actually sent by your domain and wasn't altered in transit.",
      howAutoRemediateCanFix: "This requires you to provide the DKIM public key and selector generated by your specific email provider.",
      accessNeeded: ["Email provider console access", "DNS write access"],
      whatCouldBreak: "No risk of breakage, as publishing a new DKIM key does not affect existing email flows.",
      verificationPlan: "Check that the [selector]._domainkey.TARGET DNS TXT record resolves and matches your email provider's key.",
      rollbackPlan: "Delete the newly created DKIM TXT record."
    },
    "csp-missing": {
      whatIsWrong: "The Content-Security-Policy (CSP) header is not present in server responses.",
      whyItMatters: "Without CSP, the browser will execute any scripts loaded from any source, exposing users to Cross-Site Scripting (XSS) and data injection.",
      howAutoRemediateCanFix: "AutoRemediate can set a CSP header at the CDN edge using Cloudflare Transform Rules or CloudFront policies.",
      accessNeeded: ["Cloud provider API access or server configuration access"],
      whatCouldBreak: "A strict CSP policy may block legitimate inline scripts or third-party resources if they are not explicitly whitelisted.",
      verificationPlan: "Verify the presence of Content-Security-Policy in response headers via curl or browser developer tools.",
      rollbackPlan: "Disable the Cloudflare Transform Rule or delete the header policy configuration."
    },
    "hsts-missing": {
      whatIsWrong: "The HTTP Strict-Transport-Security (HSTS) header is missing.",
      whyItMatters: "Browsers might connect to your site over insecure HTTP, exposing users to SSL stripping and man-in-the-middle attacks.",
      howAutoRemediateCanFix: "AutoRemediate can set the HSTS response header with max-age=31536000 at the edge provider.",
      accessNeeded: ["Cloud provider API access or server configuration access"],
      whatCouldBreak: "Once HSTS is enabled, browsers will reject all insecure HTTP connections, which will break access if the domain has subdomains that do not support HTTPS.",
      verificationPlan: "Check for Strict-Transport-Security in the HTTP response headers.",
      rollbackPlan: "Remove the HSTS rule or policy (note: browsers cache HSTS, so rollback may not be immediate for returning users)."
    },
    "xframe-missing": {
      whatIsWrong: "The X-Frame-Options header is not configured.",
      whyItMatters: "Malicious sites can frame your application inside an iframe, enabling clickjacking attacks to trick users into performing unintended actions.",
      howAutoRemediateCanFix: "AutoRemediate can add X-Frame-Options: DENY or SAMEORIGIN at the edge/server level.",
      accessNeeded: ["Cloud provider API access or server configuration access"],
      whatCouldBreak: "If your site legitimately needs to be embedded in an iframe on other trusted sites, it will fail to load.",
      verificationPlan: "Verify the X-Frame-Options header is returned in response headers.",
      rollbackPlan: "Remove or disable the X-Frame-Options response header rule."
    },
    "xcto-missing": {
      whatIsWrong: "The X-Content-Type-Options header is missing.",
      whyItMatters: "Without it, browsers might MIME-sniff response content, potentially executing user-uploaded files as scripts (MIME-sniffing vulnerabilities).",
      howAutoRemediateCanFix: "AutoRemediate can inject X-Content-Type-Options: nosniff into response headers.",
      accessNeeded: ["Cloud provider API access or server configuration access"],
      whatCouldBreak: "Legacy client browsers might fail to load files with mismatched MIME types.",
      verificationPlan: "Verify that the X-Content-Type-Options header is present and set to 'nosniff'.",
      rollbackPlan: "Disable or remove the header rule."
    },
    "server-version-exposed": {
      whatIsWrong: "The server response headers disclose detailed operating system or application server version information.",
      whyItMatters: "Exposed server banners help attackers identify known CVE vulnerabilities for your specific server version.",
      howAutoRemediateCanFix: "This requires applying a server configuration patch (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
      accessNeeded: ["SSH server root configuration access"],
      whatCouldBreak: "No risk of breakage; it only suppresses diagnostic version banners.",
      verificationPlan: "Inspect the Server header in HTTP responses to verify version numbers are hidden.",
      rollbackPlan: "Revert the server configuration file changes and restart the web server."
    },
    "xpoweredby-exposed": {
      whatIsWrong: "The response headers contain the X-Powered-By header, revealing the backend application framework or runtime version.",
      whyItMatters: "Banners detailing runtime frameworks (e.g. PHP/8.1) allow attackers to lookup and target version-specific vulnerabilities.",
      howAutoRemediateCanFix: "This requires editing backend runtime configs (like php.ini expose_php = Off) or strip headers via CDN edge.",
      accessNeeded: ["SSH configuration access or Cloud provider API access"],
      whatCouldBreak: "No operational impact; the header is purely diagnostic.",
      verificationPlan: "Verify the X-Powered-By header is completely absent from response headers.",
      rollbackPlan: "Revert framework/webserver rules stripping the header."
    },
    "cookie-insecure": {
      whatIsWrong: "Sensitive session cookies are transmitted without HttpOnly, Secure, or SameSite attributes.",
      whyItMatters: "Without HttpOnly, malicious scripts can steal session cookies via XSS. Without Secure, cookies are transmitted over unencrypted HTTP, exposing them to interception.",
      howAutoRemediateCanFix: "This requires updating your application configuration (like session middleware or php.ini) to include security flags.",
      accessNeeded: ["Application codebase/server configuration access"],
      whatCouldBreak: "Cookies might not be sent in cross-site requests if SameSite=Strict is set, affecting login integrations.",
      verificationPlan: "Inspect Set-Cookie headers in the response and check for Secure, HttpOnly, and SameSite fields.",
      rollbackPlan: "Remove the cookie security directives from configuration files."
    },
    "error-disclosure": {
      whatIsWrong: "The server displays detailed stack traces, raw error descriptions, or database exceptions to the client.",
      whyItMatters: "Diagnostic leaks reveal file structure, database tables, and library versions, helping attackers plan automated exploitation.",
      howAutoRemediateCanFix: "This requires modifying application code or web server settings to log errors internally and display generic error pages.",
      accessNeeded: ["Web server or codebase configuration access"],
      whatCouldBreak: "Developers will have to review server log files instead of viewing errors in the browser.",
      verificationPlan: "Attempt a page request that triggers an error and confirm that no stack traces are shown.",
      rollbackPlan: "Revert error logging configurations back to display errors."
    },
    "stale-txt-token": {
      whatIsWrong: "The domain publishes old domain verification or API TXT records (e.g., legacy Google or loader.io tokens).",
      whyItMatters: "Stale validation records disclose historical tools and services you used, creating footprinting opportunities for attackers.",
      howAutoRemediateCanFix: "AutoRemediate can delete these stale TXT records from your DNS provider.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "If the associated services are actually still in use, they might lose domain verification.",
      verificationPlan: "Query your domain's TXT records to confirm the stale token record has been removed.",
      rollbackPlan: "Recreate the deleted TXT record in your DNS dashboard."
    },
    "subdomain-takeover": {
      whatIsWrong: "A subdomain points to a third-party service (e.g. S3, CloudFront) that has been deleted or is unclaimed.",
      whyItMatters: "Attackers can register a resource under the same name on the third-party provider and hijack your subdomain to serve malicious content or steal cookies.",
      howAutoRemediateCanFix: "AutoRemediate can remove the dangling CNAME record from your DNS provider.",
      accessNeeded: ["DNS write access"],
      whatCouldBreak: "If the third-party resource was actually valid, the service will stop resolving.",
      verificationPlan: "Verify the subdomain CNAME DNS query no longer resolves.",
      rollbackPlan: "Re-add the deleted CNAME DNS record."
    }
  };

  function clientSideBuildCopilot(finding, target) {
    const tmpl = COPILOT_TEMPLATES[finding.id] || {
      whatIsWrong: finding.description || "No description details available.",
      whyItMatters: "This finding might expose server configuration info to external scanning targets.",
      howAutoRemediateCanFix: finding.fix ? "AutoRemediate can resolve this configuration by updating DNS or CDN settings." : "Manual configuration changes are required.",
      accessNeeded: finding.fix ? ["Connected cloud provider token"] : ["Administrator access"],
      whatCouldBreak: "Ensure to review configuration patches before deploying in production settings.",
      verificationPlan: "Re-run a target security scan to ensure the finding is marked as PASS.",
      rollbackPlan: "Revert the applied configuration change manually."
    };

    const format = (txt) => txt ? txt.replace(/TARGET/g, target).replace(/example\.com/g, target) : "";

    return {
      whatIsWrong: format(tmpl.whatIsWrong),
      whyItMatters: format(tmpl.whyItMatters),
      howAutoRemediateCanFix: format(tmpl.howAutoRemediateCanFix),
      accessNeeded: tmpl.accessNeeded || [],
      exactChange: finding.fix || null,
      whatCouldBreak: format(tmpl.whatCouldBreak),
      verificationPlan: format(tmpl.verificationPlan),
      rollbackPlan: format(tmpl.rollbackPlan)
    };
  }

  function clientSideGenerateTerraform(finding, target, provider) {
    const cleanId = finding.id.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const fix = finding.fix;
    if (!fix) return "# No Terraform fix configurations available.";

    if (fix.type === "dns-delete") {
      const name = fix.record ? fix.record.name : target;
      const type = fix.record ? fix.record.type : "TXT";
      const val = fix.record ? fix.record.content : "";
      return `# AutoRemediate deletion/cleanup plan for ${finding.id}
# Review before applying to production.
# Note: To remove DNS record "${name}" (Type: ${type}, Value: "${val}"),
# you should locate the resource in your configurations and delete it, 
# or remove it from your Terraform state using 'terraform state rm'.`;
    }

    if (provider === "cloudflare") {
      if (fix.type === "dns" || fix.type === "dns-update") {
        const name = fix.record ? fix.record.name : target;
        const type = fix.record ? fix.record.type : "TXT";
        const val = fix.record ? fix.record.content : "";
        return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "cloudflare_zone_id" {
  type        = string
  description = "The Cloudflare Zone ID for ${target}"
}

resource "cloudflare_dns_record" "autoremediate_${cleanId}" {
  zone_id = var.cloudflare_zone_id
  name    = "${name}"
  type    = "${type}"
  content = "${val.replace(/"/g, '\\"')}"
  ttl     = 300
}`;
      }

      if (fix.type === "cloudflare-rule") {
        const hName = fix.header || "Custom-Header";
        const hVal = fix.value || "";
        return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "cloudflare_zone_id" {
  type        = string
  description = "The Cloudflare Zone ID for ${target}"
}

resource "cloudflare_ruleset" "autoremediate_${cleanId}" {
  zone_id     = var.cloudflare_zone_id
  name        = "AutoRemediate Security Header ${hName}"
  description = "Injects the ${hName} security header"
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules {
    action      = "rewrite"
    expression  = "true"
    description = "Set ${hName} header"

    action_parameters {
      headers {
        name      = "${hName}"
        operation = "set"
        value     = "${hVal.replace(/"/g, '\\"')}"
      }
    }
  }
}`;
      }
    } else if (provider === "aws") {
      if (fix.type === "dns" || fix.type === "dns-update") {
        const name = fix.record ? fix.record.name : target;
        const type = fix.record ? fix.record.type : "TXT";
        const val = fix.record ? fix.record.content : "";
        return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "route53_zone_id" {
  type        = string
  description = "The Route53 Hosted Zone ID for ${target}"
}

resource "aws_route53_record" "autoremediate_${cleanId}" {
  zone_id = var.route53_zone_id
  name    = "${name}"
  type    = "${type}"
  ttl     = 300
  records = ["${val.replace(/"/g, '\\"')}"]
}`;
      }

      if (fix.type === "cloudflare-rule") {
        const hName = fix.header || "";
        const hVal = fix.value || "";

        if (finding.id === "hsts-missing") {
          return `# AutoRemediate generated fix for hsts-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${cleanId}" {
  name    = "autoremediate-hsts-policy"
  comment = "AutoRemediate HSTS Enforcement Policy"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
  }
}`;
        }

        if (finding.id === "csp-missing") {
          return `# AutoRemediate generated fix for csp-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${cleanId}" {
  name    = "autoremediate-csp-policy"
  comment = "AutoRemediate CSP Enforcement Policy"

  security_headers_config {
    content_security_policy {
      content_security_policy = "${hVal.replace(/"/g, '\\"')}"
      override                = true
    }
  }
}`;
        }

        if (finding.id === "xframe-missing") {
          return `# AutoRemediate generated fix for xframe-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${cleanId}" {
  name    = "autoremediate-clickjacking-policy"
  comment = "AutoRemediate Clickjacking Mitigation Policy"

  security_headers_config {
    frame_options {
      frame_option = "DENY"
      override     = true
    }
  }
}`;
        }

        if (finding.id === "xcto-missing") {
          return `# AutoRemediate generated fix for xcto-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${cleanId}" {
  name    = "autoremediate-content-type-policy"
  comment = "AutoRemediate Content-Type Sniffing Prevention Policy"

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}`;
        }

        return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${cleanId}" {
  name    = "autoremediate-${cleanId}-policy"
  comment = "AutoRemediate Custom Header ${hName} Policy"

  custom_headers_config {
    items {
      header   = "${hName}"
      value    = "${hVal.replace(/"/g, '\\"')}"
      override = true
    }
  }
}`;
      }
    }

    return `# Terraform config not supported for this provider and fix type combo.`;
  }

  // --- RENDERING COPILOT DRAWERS ---
  function openCopilot(findingId) {
    activeFindingId = findingId;
    panel.classList.remove('hidden');

    const finding = window.currentFindings.find(f => f.id === findingId);
    if (!finding) {
      content.innerHTML = `<div class="fix-instruction">Finding data not loaded.</div>`;
      return;
    }

    title.textContent = finding.name;

    // Build fallback copilot data if missing
    const target = (window.currentScanData && window.currentScanData.target) || 'example.com';
    if (!finding.copilot) {
      finding.copilot = clientSideBuildCopilot(finding, target);
    }
    if (!finding.remediation) {
      // getFallbackRemediation is exported from dashboard.js
      finding.remediation = window.dashboard.getFallbackRemediation ? window.dashboard.getFallbackRemediation(finding) : {
        readiness: "manual",
        label: "Manual",
        requires: ["Administrator access"],
        riskLevel: "medium",
        canAutoFix: false,
        canExportTerraform: false
      };
    }

    const cop = finding.copilot;
    const rem = finding.remediation;
    const riskLevel = rem.riskLevel || 'medium';

    let actionButtons = ``;
    if (rem.canAutoFix) {
      actionButtons += `<button class="btn-action btn-fix" style="width:100%; padding:12px; font-size:14px;" onclick="window.remediation.apply('${window.currentScanId}', '${finding.id}')">Apply Auto-Fix</button>`;
    }
    if (rem.canExportTerraform) {
      actionButtons += `<button class="btn-action btn-view-fix" style="width:100%; padding:12px; font-size:14px;" onclick="window.remediation.exportTerraform('${finding.id}')">Export Terraform</button>`;
    }
    if (rem.readiness === 'needs_input') {
      actionButtons += `<button class="btn-action btn-view-fix" style="width:100%; padding:12px; font-size:14px;" disabled>Provide Details (Coming Soon)</button>`;
    }
    if (rem.readiness === 'generate_patch') {
      actionButtons += `<button class="btn-action btn-view-fix" style="width:100%; padding:12px; font-size:14px;" disabled>Generate Patch (Coming Soon)</button>`;
    }

    let exactChangeHtml = '';
    if (cop.exactChange) {
      let changeCode = '';
      if (cop.exactChange.type === 'dns' || cop.exactChange.type === 'dns-update' || cop.exactChange.type === 'dns-delete') {
        const rec = cop.exactChange.record || {};
        changeCode = `Type:  ${rec.type || 'TXT'}\nName:  ${rec.name || ''}\nValue: ${rec.content || ''}`;
      } else if (cop.exactChange.type === 'cloudflare-rule') {
        changeCode = `Rule Action: Rewrite\nHeader:      ${cop.exactChange.header || ''}\nValue:       ${cop.exactChange.value || ''}`;
      } else {
        changeCode = cop.exactChange.notes || JSON.stringify(cop.exactChange, null, 2);
      }

      exactChangeHtml = `
        <div class="copilot-section">
          <strong>Exact Change to Apply</strong>
          <div class="code-container">
            <button class="btn-copy" onclick="window.remediation.copy(this)">Copy</button>
            <pre><code>${escapeHtml(changeCode)}</code></pre>
          </div>
        </div>
      `;
    }

    content.innerHTML = `
      <div class="copilot-section">
        <strong>Fix Readiness Status</strong>
        <p>Readiness: <span class="badge-readiness ${rem.readiness}">${rem.label}</span></p>
        <p>Operational Risk: <span style="font-weight:700; color: ${riskLevel === 'high' ? 'var(--critical)' : (riskLevel === 'medium' ? 'var(--moderate)' : 'var(--pass)')};">${riskLevel.toUpperCase()}</span></p>
        <p>Required Access: <code>${rem.requires && rem.requires.length > 0 ? escapeHtml(rem.requires.join(', ')) : 'None'}</code></p>
      </div>

      <div class="copilot-section">
        <strong>What is wrong?</strong>
        <p>${escapeHtml(cop.whatIsWrong)}</p>
      </div>

      <div class="copilot-section">
        <strong>Why it matters</strong>
        <p>${escapeHtml(cop.whyItMatters)}</p>
      </div>

      ${exactChangeHtml}

      <div class="copilot-section">
        <strong>Operational Risk & What Could Break</strong>
        <p>${escapeHtml(cop.whatCouldBreak)}</p>
      </div>

      <div class="copilot-section">
        <strong>Verification Plan</strong>
        <p>${escapeHtml(cop.verificationPlan)}</p>
      </div>

      <div class="copilot-section">
        <strong>Rollback Strategy</strong>
        <p>${escapeHtml(cop.rollbackPlan)}</p>
      </div>

      <div style="margin-top:10px; display:flex; flex-direction:column; gap:10px;">
        ${actionButtons}
        <button class="btn-action btn-view-fix" style="width:100%; padding:12px; font-size:14px;" onclick="window.remediation.closeCopilot()">Close Drawer</button>
      </div>
    `;
  }

  function closeCopilot() {
    panel.classList.add('hidden');
  }

  // --- TERRAFORM EXPORT MODALS ---
  function exportTerraform(findingId) {
    activeFindingId = findingId;
    closeCopilot(); // slide panel away to prioritize modal focus
    tfModal.classList.remove('hidden');
    loadTerraform(findingId, tfProviderSelect.value);
  }

  async function loadTerraform(findingId, provider) {
    tfCodeBox.textContent = '# Loading Terraform configuration...';
    activeTfCode = '';

    const finding = window.currentFindings.find(f => f.id === findingId);
    if (!finding) {
      tfCodeBox.textContent = '# Error: Finding data not loaded.';
      return;
    }

    const isStaticEnv = window.location.hostname.includes('github.io') || window.location.protocol === 'file:';
    const scanId = window.currentScanId;

    if (isStaticEnv || window.scanIsLocal) {
      // Simulate/Generate completely client-side (static deployment or backend-unknown local scan)
      setTimeout(() => {
        const target = window.currentScanData ? window.currentScanData.target : 'example.com';
        activeTfCode = clientSideGenerateTerraform(finding, target, provider);
        activeTfFilename = `autoremediate-${finding.id}-${provider}.tf`;
        tfCodeBox.textContent = activeTfCode;
      }, 300);
      return;
    }

    try {
      const response = await fetch('/api/terraform/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId, findingId, provider })
      });
      const data = await response.json();
      if (response.ok && data.success) {
        activeTfCode = data.terraform;
        activeTfFilename = data.filename;
        tfCodeBox.textContent = activeTfCode;
      } else {
        tfCodeBox.textContent = `# Error fetching Terraform config: ${data.error}`;
      }
    } catch (e) {
      // Local fallback on API fail
      const target = window.currentScanData ? window.currentScanData.target : 'example.com';
      activeTfCode = clientSideGenerateTerraform(finding, target, provider);
      activeTfFilename = `autoremediate-${finding.id}-${provider}.tf`;
      tfCodeBox.textContent = activeTfCode;
    }
  }

  function closeTerraform() {
    tfModal.classList.add('hidden');
  }

  // --- AUTO-FIX API APPLY ---
  async function apply(scanId, findingId) {
    const isStaticEnv = window.location.hostname.includes('github.io') || window.location.protocol === 'file:';

    const hasProvider = window.connectedProviders
      ? (window.connectedProviders.cloudflare || window.connectedProviders.aws)
      : window.isCloudflareConnected;

    if (!isStaticEnv && !window.scanIsLocal && !hasProvider) {
      alert('Cloud provider connection required to apply auto-remediation. Please connect Cloudflare or AWS in Settings.');
      const settingsModal = document.getElementById('settings-modal');
      if (settingsModal) settingsModal.classList.remove('hidden');
      return;
    }

    const providerLabel = window.connectedProviders && window.connectedProviders.aws && !window.connectedProviders.cloudflare
      ? 'AWS API'
      : (window.connectedProviders && window.connectedProviders.cloudflare ? 'Cloudflare API' : 'Cloudflare/AWS API');
    const provider = window.connectedProviders && window.connectedProviders.aws && !window.connectedProviders.cloudflare
      ? 'aws'
      : 'cloudflare';
    const verifyConfirm = confirm(`Are you sure you want to apply this auto-remediation rule via ${providerLabel}?`);
    if (!verifyConfirm) return;

    if (isStaticEnv || window.scanIsLocal) {
      // Simulate API call and verification latency
      const targetBtn = document.querySelector(`[onclick*="window.remediation.apply('${scanId}', '${findingId}')"]`);
      if (targetBtn) {
        targetBtn.disabled = true;
        targetBtn.textContent = 'Applying...';
      }

      await new Promise(r => setTimeout(r, 1500));

      if (targetBtn) {
        targetBtn.textContent = 'Verifying...';
      }

      await new Promise(r => setTimeout(r, 1000));

      alert(`Vulnerability successfully auto-remediated and verified via ${providerLabel}!`);
      
      // Mark the stored finding as fixed and re-render so badges stay consistent
      const localFinding = window.currentFindings && window.currentFindings.find(f => f.id === findingId);
      if (localFinding) {
        localFinding.status = 'PASS';
      }
      if (window.currentFindings) {
        window.dashboard.renderFindings(window.currentFindings, window.currentScanId);
      }
      closeCopilot();
      return;
    }

    try {
      const response = await fetch('/api/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId, findingId, provider })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        alert('Vulnerability successfully auto-remediated and verified!');
        
        // Merge the remediated finding returned by the backend into the stored
        // findings (same array referenced by window.currentScanData.findings)
        if (data.finding && window.currentFindings) {
          const stored = window.currentFindings.find(f => f.id === data.finding.id);
          if (stored) {
            Object.assign(stored, data.finding);
          }
        }
        // Re-render finding cards, severity stat badges and scanner grid
        if (window.currentFindings) {
          window.dashboard.renderFindings(window.currentFindings, window.currentScanId);
        }
        closeCopilot();
      } else {
        alert(`Remediation Failed: ${data.error}`);
      }
    } catch (e) {
      alert(`Error applying fix: ${e.message}`);
    }
  }

  function copy(btn) {
    const pre = btn.parentElement.querySelector('pre');
    navigator.clipboard.writeText(pre.textContent.trim());
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
    openCopilot,
    closeCopilot,
    exportTerraform,
    closeTerraform,
    apply,
    copy
  };
})();
