const { quoteRoute53Txt } = require('../utils/route53Txt');

function sanitizeResourceName(name) {
  if (!name) return "resource";
  return name.toLowerCase().replace(/[^a-z0-9_]/g, "_");
}

function escapeTerraformString(str) {
  if (!str) return "";
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function generateCloudflareTerraform(finding, target) {
  const sanitizedId = sanitizeResourceName(finding.id);
  const fix = finding.fix;

  if (fix.type === "dns-delete") {
    const recordName = fix.record ? fix.record.name : target;
    const recordType = fix.record ? fix.record.type : "TXT";
    const recordContent = fix.record ? fix.record.content : "";
    return `# AutoRemediate deletion/cleanup plan for ${finding.id}
# Review before applying to production.
# Note: To remove the DNS record "${recordName}" (Type: ${recordType}, Value: "${escapeTerraformString(recordContent)}"),
# you should locate the resource in your configurations and delete it, 
# or remove it from your Terraform state using 'terraform state rm'.`;
  }

  if (fix.type === "dns" || fix.type === "dns-update") {
    const recordName = fix.record ? fix.record.name : target;
    const recordType = fix.record ? fix.record.type : "TXT";
    const recordContent = fix.record ? fix.record.content : "";
    
    // For Cloudflare records matching root domain, it is common to use target domain name or var.domain
    return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "cloudflare_zone_id" {
  type        = string
  description = "The Cloudflare Zone ID for ${target}"
}

resource "cloudflare_dns_record" "autoremediate_${sanitizedId}" {
  zone_id = var.cloudflare_zone_id
  name    = "${recordName}"
  type    = "${recordType}"
  content = "${escapeTerraformString(recordContent)}"
  ttl     = 300
}`;
  }

  if (fix.type === "cloudflare-rule") {
    const headerName = fix.header || "Custom-Header";
    const headerValue = fix.value || "";

    return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "cloudflare_zone_id" {
  type        = string
  description = "The Cloudflare Zone ID for ${target}"
}

resource "cloudflare_ruleset" "autoremediate_${sanitizedId}" {
  zone_id     = var.cloudflare_zone_id
  name        = "AutoRemediate Security Header ${headerName}"
  description = "Injects the ${headerName} security header"
  kind        = "zone"
  phase       = "http_response_headers_transform"

  rules {
    action      = "rewrite"
    expression  = "true"
    description = "Set ${headerName} header"

    action_parameters {
      headers {
        name      = "${headerName}"
        operation = "set"
        value     = "${escapeTerraformString(headerValue)}"
      }
    }
  }
}`;
  }

  throw new Error(`Unsupported fix type "${fix.type}" for Cloudflare export.`);
}

function generateAwsTerraform(finding, target) {
  const sanitizedId = sanitizeResourceName(finding.id);
  const fix = finding.fix;

  if (fix.type === "dns-delete") {
    const recordName = fix.record ? fix.record.name : target;
    const recordType = fix.record ? fix.record.type : "TXT";
    const recordContent = fix.record ? fix.record.content : "";
    return `# AutoRemediate deletion/cleanup plan for ${finding.id}
# Review before applying to production.
# Note: To remove Route53 record "${recordName}" (Type: ${recordType}, Value: "${escapeTerraformString(recordContent)}"),
# you should remove the resource block from your Terraform configurations, 
# or run 'terraform state rm' to untrack it from your state file.`;
  }

  if (fix.type === "dns" || fix.type === "dns-update") {
    const recordName = fix.record ? fix.record.name : target;
    const recordType = fix.record ? fix.record.type : "TXT";
    const recordContent = fix.record ? fix.record.content : "";
    // Route53 TXT values must carry literal inner quotes (and be chunked at
    // 255 chars) or `terraform apply` fails.
    const recordValue = recordType === "TXT" ? quoteRoute53Txt(recordContent) : recordContent;

    return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

variable "route53_zone_id" {
  type        = string
  description = "The Route53 Hosted Zone ID for ${target}"
}

resource "aws_route53_record" "autoremediate_${sanitizedId}" {
  zone_id = var.route53_zone_id
  name    = "${recordName}"
  type    = "${recordType}"
  ttl     = 300
  records = ["${escapeTerraformString(recordValue)}"]
}`;
  }

  // Security headers on AWS utilize CloudFront Response Headers Policies
  if (fix.type === "cloudflare-rule") {
    const headerName = fix.header || "";
    const headerValue = fix.value || "";

    if (finding.id === "hsts-missing") {
      return `# AutoRemediate generated fix for hsts-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${sanitizedId}" {
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

resource "aws_cloudfront_response_headers_policy" "autoremediate_${sanitizedId}" {
  name    = "autoremediate-csp-policy"
  comment = "AutoRemediate CSP Enforcement Policy"

  security_headers_config {
    content_security_policy {
      content_security_policy = "${escapeTerraformString(headerValue)}"
      override                = true
    }
  }
}`;
    }

    if (finding.id === "xframe-missing") {
      return `# AutoRemediate generated fix for xframe-missing
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${sanitizedId}" {
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

resource "aws_cloudfront_response_headers_policy" "autoremediate_${sanitizedId}" {
  name    = "autoremediate-content-type-policy"
  comment = "AutoRemediate Content-Type Sniffing Prevention Policy"

  security_headers_config {
    content_type_options {
      override = true
    }
  }
}`;
    }

    // Generic header fallback using custom headers item block
    return `# AutoRemediate generated fix for ${finding.id}
# Review before applying to production.

resource "aws_cloudfront_response_headers_policy" "autoremediate_${sanitizedId}" {
  name    = "autoremediate-${sanitizedId}-policy"
  comment = "AutoRemediate Custom Header ${headerName} Policy"

  custom_headers_config {
    items {
      header   = "${headerName}"
      value    = "${escapeTerraformString(headerValue)}"
      override = true
    }
  }
}`;
  }

  throw new Error(`Unsupported fix type "${fix.type}" for AWS export.`);
}

function generateTerraform(finding, target, provider = "cloudflare") {
  if (!finding) {
    throw new Error("No Terraform export available for this finding.");
  }

  if (provider !== "cloudflare" && provider !== "aws") {
    throw new Error("Unsupported provider. Choose 'cloudflare' or 'aws'.");
  }

  // PASS findings without a fix are already compliant — emit a comment-only
  // file instead of erroring out (mirrors the client's fallback behavior).
  if (!finding.fix) {
    if (finding.status === "PASS") {
      return `# AutoRemediate Terraform export for ${finding.id} (${provider})
# ${finding.name}
# This control is already compliant for ${target} (scan status: PASS).
# No infrastructure changes are required.`;
    }
    throw new Error("No Terraform export available for this finding.");
  }

  if (provider === "cloudflare") {
    return generateCloudflareTerraform(finding, target);
  }

  return generateAwsTerraform(finding, target);
}

module.exports = { generateTerraform };
