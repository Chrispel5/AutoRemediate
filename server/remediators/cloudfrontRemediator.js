// AWS CloudFront Headers Remediator

const MANAGED_SECURITY_HEADERS_POLICY_ID = '67f7725c-6f97-4210-82d7-5512b31e9d03';
const MANAGED_SECURITY_HEADERS = new Set([
  'Strict-Transport-Security',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'Referrer-Policy'
]);

function isFreePlanCustomPolicyError(err) {
  return /Free pricing plan[\s\S]*Custom response headers policy/i.test(err.message || '');
}

async function deleteUnattachedPolicy(connector, policyId) {
  try {
    const policy = await connector.getResponseHeadersPolicy(policyId);
    await connector.deleteResponseHeadersPolicy(policyId, policy.etag);
  } catch (cleanupErr) {
    console.error(`[CloudFront] Could not delete unattached policy ${policyId}:`, cleanupErr.message);
  }
}

function unescapeXml(value) {
  return value.toString()
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

// Build a policy config containing ONLY the header the user asked to fix —
// force-setting all six headers with defaults can break the site.
function buildHeadersConfigForFix(fix) {
  const config = {};
  switch (fix.header) {
    case 'Content-Security-Policy':
      config.ContentSecurityPolicy = fix.value;
      break;
    case 'Strict-Transport-Security': {
      const maxAgeMatch = (fix.value || '').match(/max-age=(\d+)/i);
      config.StrictTransportSecurity = {
        maxAge: maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 31536000,
        includeSubdomains: /includesubdomains/i.test(fix.value || '') ? 'true' : 'false',
        preload: /preload/i.test(fix.value || '') ? 'true' : 'false'
      };
      break;
    }
    case 'X-Frame-Options':
      config.FrameOptions = fix.value || 'DENY';
      break;
    case 'X-Content-Type-Options':
      config.ContentTypeOptions = 'true';
      break;
    case 'Referrer-Policy':
      config.ReferrerPolicy = fix.value || 'strict-origin-when-cross-origin';
      break;
    default:
      config.CustomHeaders = [{ name: fix.header, value: fix.value || '' }];
      break;
  }
  return config;
}

// Parse an existing ResponseHeadersPolicyConfig XML back into a config object
function parsePolicyXmlToConfig(xml) {
  const config = {};

  const csp = xml.match(/<ContentSecurityPolicy>[\s\S]*?<ContentSecurityPolicy>([^<]*)<\/ContentSecurityPolicy>/);
  if (csp) config.ContentSecurityPolicy = unescapeXml(csp[1]);

  if (/<ContentTypeOptions>/.test(xml)) config.ContentTypeOptions = 'true';

  const frameOption = xml.match(/<FrameOption>([^<]+)<\/FrameOption>/);
  if (frameOption) config.FrameOptions = frameOption[1];

  const referrer = xml.match(/<ReferrerPolicy>[\s\S]*?<ReferrerPolicy>([^<]*)<\/ReferrerPolicy>/);
  if (referrer) config.ReferrerPolicy = unescapeXml(referrer[1]);

  const stsBlock = xml.match(/<StrictTransportSecurity>([\s\S]*?)<\/StrictTransportSecurity>/);
  if (stsBlock) {
    const maxAge = stsBlock[1].match(/<AccessControlMaxAgeSec>(\d+)<\/AccessControlMaxAgeSec>/);
    const includeSub = stsBlock[1].match(/<IncludeSubdomains>([^<]+)<\/IncludeSubdomains>/);
    const preload = stsBlock[1].match(/<Preload>([^<]+)<\/Preload>/);
    config.StrictTransportSecurity = {
      maxAge: maxAge ? parseInt(maxAge[1], 10) : 31536000,
      includeSubdomains: includeSub ? includeSub[1] : 'false',
      preload: preload ? preload[1] : 'false'
    };
  }

  const customItems = xml.matchAll(/<ResponseHeadersPolicyCustomHeader>([\s\S]*?)<\/ResponseHeadersPolicyCustomHeader>/g);
  const customs = [];
  for (const item of customItems) {
    const header = item[1].match(/<Header>([^<]+)<\/Header>/);
    const value = item[1].match(/<Value>([^<]*)<\/Value>/);
    if (header) customs.push({ name: unescapeXml(header[1]), value: value ? unescapeXml(value[1]) : '' });
  }
  if (customs.length > 0) config.CustomHeaders = customs;

  return config;
}

// Merge the requested header into the existing policy config
function mergeHeadersConfig(existing, requested) {
  const merged = { ...existing, ...requested };
  if (existing.CustomHeaders || requested.CustomHeaders) {
    const byName = new Map();
    [...(existing.CustomHeaders || []), ...(requested.CustomHeaders || [])]
      .forEach(ch => byName.set(ch.name.toLowerCase(), ch));
    merged.CustomHeaders = [...byName.values()];
  }
  return merged;
}

async function applyFix(connector, domain, finding) {
  const fix = finding.fix;
  
  try {
    // 1. List distributions to find the one matching the target domain
    const distributions = await connector.listDistributions();
    const targetDomain = domain.toLowerCase();
    const targetDist = distributions.find(d => {
      return d.domainName.toLowerCase() === targetDomain || d.aliases.includes(targetDomain);
    });

    if (!targetDist) {
      throw new Error(`No CloudFront distribution found matching domain: ${domain}`);
    }

    const distId = targetDist.id;

    // 2. Fetch the current distribution configuration to mutate
    const { xml, etag } = await connector.getDistributionConfig(distId);

    const dcbMatch = xml.match(/<DefaultCacheBehavior>([\s\S]*?)<\/DefaultCacheBehavior>/);
    if (!dcbMatch) {
      throw new Error('DefaultCacheBehavior section not found in CloudFront distribution configuration.');
    }

    let dcbContent = dcbMatch[1];
    const requestedConfig = buildHeadersConfigForFix(fix);
    const existingPolicyMatch = dcbContent.match(/<ResponseHeadersPolicyId>([^<]+)<\/ResponseHeadersPolicyId>/);

    let policyId;
    let policyNote;

    if (existingPolicyMatch) {
      // 3a. A policy is already attached — merge the requested header into it
      // and UPDATE that same policy (no orphan policies, no default headers).
      policyId = existingPolicyMatch[1];
      const policy = await connector.getResponseHeadersPolicy(policyId);
      const nameMatch = policy.xml.match(/<Name>([^<]+)<\/Name>/);
      const commentMatch = policy.xml.match(/<Comment>([^<]*)<\/Comment>/);
      const mergedConfig = mergeHeadersConfig(parsePolicyXmlToConfig(policy.xml), requestedConfig);
      const updatedPolicyXml = connector.buildResponseHeadersPolicyXml(
        nameMatch ? unescapeXml(nameMatch[1]) : 'AutoRemediate-Policy',
        commentMatch ? unescapeXml(commentMatch[1]) : '',
        mergedConfig
      );
      await connector.updateResponseHeadersPolicy(policyId, policy.etag, updatedPolicyXml);
      policyNote = `merged ${fix.header} into existing Response Headers Policy (${policyId})`;
    } else {
      // 3b. No policy attached — create one containing only the requested header
      const policyName = `AutoRemediate-${fix.header.replace(/[^a-zA-Z0-9-]/g, '')}-${Date.now()}`;
      policyId = await connector.createResponseHeadersPolicy(policyName, requestedConfig);

      // 4. Attach it inside DefaultCacheBehavior. Per the DistributionConfig
      // schema sequence, ResponseHeadersPolicyId sits after OriginRequestPolicyId
      // and before ForwardedValues / MinTTL.
      if (dcbContent.includes('<ForwardedValues>')) {
        dcbContent = dcbContent.replace('<ForwardedValues>', `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>\n<ForwardedValues>`);
      } else if (dcbContent.includes('<MinTTL>')) {
        dcbContent = dcbContent.replace('<MinTTL>', `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>\n<MinTTL>`);
      } else {
        dcbContent += `\n<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>`;
      }

      let updatedConfig = xml.replace(/<DefaultCacheBehavior>[\s\S]*?<\/DefaultCacheBehavior>/, `<DefaultCacheBehavior>${dcbContent}</DefaultCacheBehavior>`);

      // We must clean up top level distribution wrapper wrapper if any to just keep <DistributionConfig>
      const configMatch = updatedConfig.match(/<DistributionConfig[\s\S]*<\/DistributionConfig>/);
      if (configMatch) {
        updatedConfig = configMatch[0];
      }

      // 5. Push configuration updates to CloudFront. Flat-rate Free plans do
      // not allow custom policies, but they do allow AWS-managed policies.
      try {
        await connector.updateDistributionConfig(distId, etag, updatedConfig);
        policyNote = `attached new Response Headers Policy (${policyId})`;
      } catch (updateErr) {
        await deleteUnattachedPolicy(connector, policyId);

        if (!isFreePlanCustomPolicyError(updateErr) || !MANAGED_SECURITY_HEADERS.has(fix.header)) {
          throw updateErr;
        }

        const managedConfig = updatedConfig.replace(
          `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>`,
          `<ResponseHeadersPolicyId>${MANAGED_SECURITY_HEADERS_POLICY_ID}</ResponseHeadersPolicyId>`
        );
        await connector.updateDistributionConfig(distId, etag, managedConfig);
        policyId = MANAGED_SECURITY_HEADERS_POLICY_ID;
        policyNote = `attached AWS managed SecurityHeadersPolicy (${policyId}) for CloudFront Free plan compatibility`;
      }
    }

    return {
      success: true,
      action: 'UPDATE_CLOUDFRONT_HEADERS_POLICY',
      policyId,
      verification: `CloudFront ${policyNote} to inject ${fix.header}. Deploying to CloudFront edge nodes (takes 3-5 mins).`
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
