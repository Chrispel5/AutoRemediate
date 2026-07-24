// AWS CloudFront Headers Remediator
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

    // 3. Build a comprehensive security headers policy covering all security header standards
    const headersConfig = {
      ContentSecurityPolicy: fix.header === 'Content-Security-Policy' ? fix.value : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
      StrictTransportSecurity: {
        maxAge: 31536000,
        includeSubdomains: 'true',
        preload: 'true'
      },
      FrameOptions: fix.header === 'X-Frame-Options' ? (fix.value || 'DENY') : 'DENY',
      ContentTypeOptions: 'true',
      ReferrerPolicy: fix.header === 'Referrer-Policy' ? (fix.value || 'strict-origin-when-cross-origin') : 'strict-origin-when-cross-origin',
      CustomHeaders: [
        { name: 'Permissions-Policy', value: fix.header === 'Permissions-Policy' ? (fix.value || 'geolocation=(), microphone=(), camera=()') : 'geolocation=(), microphone=(), camera=()' }
      ]
    };

    // 4. Create the new Response Headers Policy via CloudFront API
    const policyName = `AutoRemediate-${fix.header.replace(/[^a-zA-Z0-9-]/g, '')}-${Date.now()}`;
    const policyId = await connector.createResponseHeadersPolicy(policyName, headersConfig);

    // 5. Update the distribution configuration XML to attach the policyId
    // Parse CacheBehaviors or DefaultCacheBehavior block and inject ResponseHeadersPolicyId
    let updatedConfig = xml;
    
    // We locate the <DefaultCacheBehavior> section and replace/inject <ResponseHeadersPolicyId>
    const dcbMatch = xml.match(/<DefaultCacheBehavior>([\s\S]*?)<\/DefaultCacheBehavior>/);
    if (!dcbMatch) {
      throw new Error('DefaultCacheBehavior section not found in CloudFront distribution configuration.');
    }

    let dcbContent = dcbMatch[1];
    if (dcbContent.includes('<ResponseHeadersPolicyId>')) {
      // Replace existing policy reference
      dcbContent = dcbContent.replace(/<ResponseHeadersPolicyId>[^<]*<\/ResponseHeadersPolicyId>/, `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>`);
    } else {
      // Append right before ViewerProtocolPolicy or at the end of DefaultCacheBehavior content
      if (dcbContent.includes('<Compress>')) {
        dcbContent = dcbContent.replace('<Compress>', `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>\n<Compress>`);
      } else if (dcbContent.includes('<ViewerProtocolPolicy>')) {
        dcbContent = dcbContent.replace('<ViewerProtocolPolicy>', `<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>\n<ViewerProtocolPolicy>`);
      } else {
        dcbContent += `\n<ResponseHeadersPolicyId>${policyId}</ResponseHeadersPolicyId>`;
      }
    }

    updatedConfig = updatedConfig.replace(/<DefaultCacheBehavior>[\s\S]*?<\/DefaultCacheBehavior>/, `<DefaultCacheBehavior>${dcbContent}</DefaultCacheBehavior>`);

    // We must clean up top level distribution wrapper wrapper if any to just keep <DistributionConfig>
    const configMatch = updatedConfig.match(/<DistributionConfig[\s\S]*<\/DistributionConfig>/);
    if (configMatch) {
      updatedConfig = configMatch[0];
    }

    // 6. Push configuration updates to CloudFront
    await connector.updateDistributionConfig(distId, etag, updatedConfig);

    return {
      success: true,
      action: 'UPDATE_CLOUDFRONT_HEADERS_POLICY',
      policyId,
      verification: `Attached Response Headers Policy (${policyId}) to inject ${fix.header}. Deploying to CloudFront edge nodes (takes 3-5 mins).`
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
