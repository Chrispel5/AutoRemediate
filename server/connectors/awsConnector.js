const crypto = require('crypto');
const fetch = require('node-fetch');

class AWSConnector {
  constructor(accessKeyId, secretAccessKey, region = 'us-east-1', sessionToken = null) {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.region = region;
    this.sessionToken = sessionToken;
  }

  // AWS Signature Version 4 Helper
  sign(method, service, host, path, queryParams = {}, headers = {}, body = '') {
    const datetime = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
    const date = datetime.substr(0, 8);

    // Route53, CloudFront, and the global STS endpoint are global services:
    // they must be signed against us-east-1 regardless of the configured region.
    const signingRegion = (service === 'route53' || service === 'cloudfront' ||
      (service === 'sts' && host === 'sts.amazonaws.com')) ? 'us-east-1' : this.region;

    const signingHeaders = {};
    Object.keys(headers).forEach((key) => {
      signingHeaders[key.toLowerCase()] = headers[key];
    });
    signingHeaders.host = host;
    signingHeaders['x-amz-date'] = datetime;
    if (this.sessionToken) {
      signingHeaders['x-amz-security-token'] = this.sessionToken;
    }

    // 1. Create Canonical Request
    const canonicalUri = path || '/';
    
    // Sort query parameters
    const sortedQuery = Object.keys(queryParams)
      .sort()
      .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
      .join('&');

    // Canonical Headers
    const canonicalHeaders = Object.keys(signingHeaders)
      .sort()
      .map(key => `${key}:${signingHeaders[key].toString().trim().replace(/\s+/g, ' ')}`)
      .join('\n') + '\n';

    const signedHeaders = Object.keys(signingHeaders)
      .sort()
      .join(';');

    const payloadHash = crypto.createHash('sha256').update(body).digest('hex');

    const canonicalRequest = [
      method,
      canonicalUri,
      sortedQuery,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    // 2. Create String to Sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = [date, signingRegion, service, 'aws4_request'].join('/');
    const canonicalRequestHash = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
    const stringToSign = [algorithm, datetime, credentialScope, canonicalRequestHash].join('\n');

    // 3. Calculate Signature
    const kDate = crypto.createHmac('sha256', `AWS4${this.secretAccessKey}`).update(date).digest();
    const kRegion = crypto.createHmac('sha256', kDate).update(signingRegion).digest();
    const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
    const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
    const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

    // 4. Add Authorization Header
    signingHeaders.Authorization = `${algorithm} Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return signingHeaders;
  }

  async request(service, host, method, path, queryParams = {}, additionalHeaders = {}, body = '') {
    const headers = this.sign(method, service, host, path, queryParams, { ...additionalHeaders }, body);
    
    let url = `https://${host}${path}`;
    const sortedQuery = Object.keys(queryParams)
      .sort()
      .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
      .join('&');
    if (sortedQuery) {
      url += `?${sortedQuery}`;
    }

    const res = await fetch(url, {
      method,
      headers,
      body: method !== 'GET' && method !== 'HEAD' ? body : undefined,
      timeout: 15000
    });

    const text = await res.text();
    if (!res.ok) {
      const parsedError = parseAwsError(text, res.status);
      throw new Error(parsedError);
    }
    return text;
  }

  // --- ELBv2 (Application Load Balancer) — regional Query API ---

  async elbv2(params) {
    const host = `elasticloadbalancing.${this.region}.amazonaws.com`;
    return this.request('elasticloadbalancing', host, 'GET', '/', { Version: '2015-12-01', ...params });
  }

  async describeLoadBalancers() {
    const xml = await this.elbv2({ Action: 'DescribeLoadBalancers' });
    const lbs = [];
    const matches = xml.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const m of matches) {
      const arn = m[1].match(/<LoadBalancerArn>([^<]+)<\/LoadBalancerArn>/);
      const dns = m[1].match(/<DNSName>([^<]+)<\/DNSName>/);
      const type = m[1].match(/<Type>([^<]+)<\/Type>/);
      if (arn && dns && type && type[1] === 'application') {
        lbs.push({ arn: arn[1], dnsName: dns[1].toLowerCase() });
      }
    }
    return lbs;
  }

  async describeListeners(loadBalancerArn) {
    const xml = await this.elbv2({ Action: 'DescribeListeners', LoadBalancerArn: loadBalancerArn });
    const listeners = [];
    const matches = xml.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const m of matches) {
      const arn = m[1].match(/<ListenerArn>([^<]+)<\/ListenerArn>/);
      const port = m[1].match(/<Port>(\d+)<\/Port>/);
      if (arn) listeners.push({ arn: arn[1], port: port ? parseInt(port[1], 10) : null });
    }
    return listeners;
  }

  async modifyListenerAttributes(listenerArn, attributes) {
    const params = { Action: 'ModifyListenerAttributes', ListenerArn: listenerArn };
    Object.entries(attributes).forEach(([key, value], i) => {
      params[`Attributes.member.${i + 1}.Key`] = key;
      params[`Attributes.member.${i + 1}.Value`] = value;
    });
    return this.elbv2(params);
  }

  // Verify credentials by calling GetCallerIdentity on STS
  async verifyCredentials() {
    // Let AWS authentication errors reach the API response. The connector's
    // error parser removes response noise while preserving the useful cause.
    const xml = await this.request(
      'sts',
      'sts.amazonaws.com',
      'POST',
      '/',
      {},
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      'Action=GetCallerIdentity&Version=2011-06-15'
    );
    return xml.includes('GetCallerIdentityResult');
  }

  // Assume an IAM Role via STS and return temporary session credentials
  async assumeRole(roleArn, sessionName = 'AutoRemediateSession') {
    const body = `Action=AssumeRole&Version=2011-06-15&RoleArn=${encodeURIComponent(roleArn)}&RoleSessionName=${encodeURIComponent(sessionName)}&DurationSeconds=3600`;
    const xml = await this.request(
      'sts',
      'sts.amazonaws.com',
      'POST',
      '/',
      {},
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    );

    const accessKeyIdMatch = xml.match(/<AccessKeyId>([^<]+)<\/AccessKeyId>/);
    const secretAccessKeyMatch = xml.match(/<SecretAccessKey>([^<]+)<\/SecretAccessKey>/);
    const sessionTokenMatch = xml.match(/<SessionToken>([^<]+)<\/SessionToken>/);

    if (!accessKeyIdMatch || !secretAccessKeyMatch || !sessionTokenMatch) {
      throw new Error(`Failed to assume IAM Role ${roleArn}. STS XML Response: ${xml}`);
    }

    return {
      accessKeyId: accessKeyIdMatch[1],
      secretAccessKey: secretAccessKeyMatch[1],
      sessionToken: sessionTokenMatch[1]
    };
  }

  // List Hosted Zones in Route 53 (paginates via marker/IsTruncated)
  async listHostedZones() {
    const zones = [];
    let marker = null;

    do {
      const queryParams = marker ? { marker } : {};
      const xml = await this.request('route53', 'route53.amazonaws.com', 'GET', '/2013-04-01/hostedzone', queryParams);
      const matches = xml.matchAll(/<HostedZone>([\s\S]*?)<\/HostedZone>/g);
      for (const match of matches) {
        const content = match[1];
        const idMatch = content.match(/<Id>\/hostedzone\/([^<]+)<\/Id>/);
        const nameMatch = content.match(/<Name>([^<]+)<\/Name>/);
        if (idMatch && nameMatch) {
          zones.push({
            id: idMatch[1],
            name: nameMatch[1].replace(/\.$/, '') // strip trailing dot
          });
        }
      }
      const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
      const nextMarkerMatch = xml.match(/<NextMarker>([^<]+)<\/NextMarker>/);
      marker = truncated && nextMarkerMatch ? nextMarkerMatch[1] : null;
    } while (marker);

    return zones;
  }

  // Fetch the existing RRset for an exact name+type (null when absent).
  // TXT values are returned with their Route 53 quoting preserved.
  async listResourceRecordSets(hostedZoneId, recordName, recordType) {
    const fqdn = recordName.endsWith('.') ? recordName : `${recordName}.`;
    const xml = await this.request(
      'route53',
      'route53.amazonaws.com',
      'GET',
      `/2013-04-01/hostedzone/${hostedZoneId}/rrset`,
      { name: fqdn, type: recordType }
    );

    const setMatch = xml.match(/<ResourceRecordSet>([\s\S]*?)<\/ResourceRecordSet>/);
    if (!setMatch) {
      return null;
    }

    const content = setMatch[1];
    const nameMatch = content.match(/<Name>([^<]+)<\/Name>/);
    const typeMatch = content.match(/<Type>([^<]+)<\/Type>/);
    if (!nameMatch || !typeMatch || typeMatch[1] !== recordType) {
      return null;
    }

    const ttlMatch = content.match(/<TTL>(\d+)<\/TTL>/);
    const values = [];
    const valueMatches = content.matchAll(/<Value>([\s\S]*?)<\/Value>/g);
    for (const v of valueMatches) {
      values.push(unescapeXml(v[1].trim()));
    }

    return {
      name: nameMatch[1].replace(/\.$/, ''),
      type: recordType,
      ttl: ttlMatch ? parseInt(ttlMatch[1], 10) : 300,
      values
    };
  }

  // Create, replace or delete DNS Records in Route 53.
  // recordValues is the FULL list of values the RRset should carry
  // (Route 53 UPSERT/DELETE always replaces/matches the entire RRset).
  // TXT values must already carry Route 53 quoting (see utils/route53Txt).
  async changeResourceRecordSets(hostedZoneId, action, recordName, recordType, recordValues, ttl = 300) {
    const path = `/2013-04-01/hostedzone/${hostedZoneId}/rrset`;
    
    // Build change batch XML payload
    // XML value escaping
    const escapedName = escapeXml(recordName.endsWith('.') ? recordName : `${recordName}.`);
    const escapedType = escapeXml(recordType);
    const values = Array.isArray(recordValues) ? recordValues : [recordValues];
    const recordsXml = values
      .map(v => `<ResourceRecord><Value>${escapeXml(v)}</Value></ResourceRecord>`)
      .join('\n            ');
    const xmlBody = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>${action}</Action>
        <ResourceRecordSet>
          <Name>${escapedName}</Name>
          <Type>${escapedType}</Type>
          <TTL>${ttl}</TTL>
          <ResourceRecords>
            ${recordsXml}
          </ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>`;

    return await this.request(
      'route53',
      'route53.amazonaws.com',
      'POST',
      path,
      {},
      { 'Content-Type': 'application/xml' },
      xmlBody
    );
  }

  // List CloudFront Distributions (paginates via Marker/IsTruncated)
  async listDistributions() {
    const dists = [];
    let marker = null;

    do {
      const queryParams = marker ? { Marker: marker } : {};
      const xml = await this.request('cloudfront', 'cloudfront.amazonaws.com', 'GET', '/2020-05-31/distribution', queryParams);
      
      // Parse CloudFront DistributionSummary nodes
      const matches = xml.matchAll(/<DistributionSummary>([\s\S]*?)<\/DistributionSummary>/g);
      for (const match of matches) {
        const content = match[1];
        const idMatch = content.match(/<Id>([^<]+)<\/Id>/);
        const domainMatch = content.match(/<DomainName>([^<]+)<\/DomainName>/);
        
        const aliases = [];
        const aliasesMatch = content.match(/<Aliases>([\s\S]*?)<\/Aliases>/);
        if (aliasesMatch) {
          const items = aliasesMatch[1].matchAll(/<CNAME>([^<]+)<\/CNAME>/g);
          for (const item of items) {
            aliases.push(item[1].toLowerCase());
          }
        }

        if (idMatch && domainMatch) {
          dists.push({
            id: idMatch[1],
            domainName: domainMatch[1],
            aliases
          });
        }
      }

      const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
      const nextMarkerMatch = xml.match(/<NextMarker>([^<]+)<\/NextMarker>/);
      marker = truncated && nextMarkerMatch ? nextMarkerMatch[1] : null;
    } while (marker);

    return dists;
  }

  // Get CloudFront Distribution Config (returns XML config + ETag via headers callback)
  async getDistributionConfig(distributionId) {
    const path = `/2020-05-31/distribution/${distributionId}/config`;
    
    // We need both the body (XML) and the ETag header returned by CloudFront.
    // So we'll run fetch directly with headers.
    const headers = this.sign('GET', 'cloudfront', 'cloudfront.amazonaws.com', path, {}, {});
    const res = await fetch(`https://cloudfront.amazonaws.com${path}`, {
      method: 'GET',
      headers,
      timeout: 10000
    });

    const xml = await res.text();
    if (!res.ok) {
      throw new Error(`CloudFront config fetch failed: ${xml}`);
    }
    const etag = res.headers.get('etag');
    return { xml, etag };
  }

  // Build a ResponseHeadersPolicyConfig document with elements in the order
  // the CloudFront schema requires: config-level Comment before Name;
  // CustomHeadersConfig before SecurityHeadersConfig; inside
  // SecurityHeadersConfig: ContentSecurityPolicy, ContentTypeOptions,
  // FrameOptions, ReferrerPolicy, StrictTransportSecurity, XSSProtection.
  buildResponseHeadersPolicyXml(policyName, comment, headersConfig) {
    let securityHeadersXml = '';
    if (headersConfig.ContentSecurityPolicy) {
      securityHeadersXml += `<ContentSecurityPolicy>
        <Override>true</Override>
        <ContentSecurityPolicy>${escapeXml(headersConfig.ContentSecurityPolicy)}</ContentSecurityPolicy>
      </ContentSecurityPolicy>`;
    }
    if (headersConfig.ContentTypeOptions) {
      securityHeadersXml += `<ContentTypeOptions>
        <Override>true</Override>
      </ContentTypeOptions>`;
    }
    if (headersConfig.FrameOptions) {
      securityHeadersXml += `<FrameOptions>
        <Override>true</Override>
        <FrameOption>${headersConfig.FrameOptions}</FrameOption>
      </FrameOptions>`;
    }
    if (headersConfig.ReferrerPolicy) {
      securityHeadersXml += `<ReferrerPolicy>
        <Override>true</Override>
        <ReferrerPolicy>${escapeXml(headersConfig.ReferrerPolicy)}</ReferrerPolicy>
      </ReferrerPolicy>`;
    }
    if (headersConfig.StrictTransportSecurity) {
      securityHeadersXml += `<StrictTransportSecurity>
        <Override>true</Override>
        <AccessControlMaxAgeSec>${headersConfig.StrictTransportSecurity.maxAge || 31536000}</AccessControlMaxAgeSec>
        <IncludeSubdomains>${headersConfig.StrictTransportSecurity.includeSubdomains || 'true'}</IncludeSubdomains>
        <Preload>${headersConfig.StrictTransportSecurity.preload || 'true'}</Preload>
      </StrictTransportSecurity>`;
    }

    let customHeadersXml = '';
    if (headersConfig.CustomHeaders && Array.isArray(headersConfig.CustomHeaders) && headersConfig.CustomHeaders.length > 0) {
      const items = headersConfig.CustomHeaders.map(ch => `
        <ResponseHeadersPolicyCustomHeader>
          <Header>${escapeXml(ch.name)}</Header>
          <Value>${escapeXml(ch.value)}</Value>
          <Override>true</Override>
        </ResponseHeadersPolicyCustomHeader>`).join('');

      customHeadersXml = `
  <CustomHeadersConfig>
    <Quantity>${headersConfig.CustomHeaders.length}</Quantity>
    <Items>${items}
    </Items>
  </CustomHeadersConfig>`;
    }

    let fullSecurityHeadersBlock = '';
    if (securityHeadersXml.trim().length > 0) {
      fullSecurityHeadersBlock = `
  <SecurityHeadersConfig>
    ${securityHeadersXml}
  </SecurityHeadersConfig>`;
    }

    return `<?xml version="1.0" encoding="UTF-8"?>
<ResponseHeadersPolicyConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Comment>${escapeXml(comment || 'AutoRemediate Security Headers Policy')}</Comment>
  <Name>${escapeXml(policyName)}</Name>${customHeadersXml}${fullSecurityHeadersBlock}
</ResponseHeadersPolicyConfig>`;
  }

  // Create Response Headers Policy
  async createResponseHeadersPolicy(policyName, headersConfig) {
    const path = `/2020-05-31/response-headers-policy`;
    const xmlBody = this.buildResponseHeadersPolicyXml(policyName, 'AutoRemediate Security Headers Policy', headersConfig);

    const resXml = await this.request(
      'cloudfront',
      'cloudfront.amazonaws.com',
      'POST',
      path,
      {},
      { 'Content-Type': 'application/xml' },
      xmlBody
    );

    const idMatch = resXml.match(/<Id>([^<]+)<\/Id>/);
    if (!idMatch) {
      throw new Error(`Failed to extract Policy ID from response XML: ${resXml}`);
    }
    return idMatch[1];
  }

  // Get an existing Response Headers Policy config (XML + ETag for If-Match)
  async getResponseHeadersPolicy(policyId) {
    const path = `/2020-05-31/response-headers-policy/${policyId}`;
    const headers = this.sign('GET', 'cloudfront', 'cloudfront.amazonaws.com', path, {}, {});
    const res = await fetch(`https://cloudfront.amazonaws.com${path}`, {
      method: 'GET',
      headers,
      timeout: 10000
    });

    const xml = await res.text();
    if (!res.ok) {
      throw new Error(`CloudFront response headers policy fetch failed: ${xml}`);
    }
    const etag = res.headers.get('etag');
    return { xml, etag };
  }

  // Update an existing Response Headers Policy (versioned via If-Match ETag)
  async updateResponseHeadersPolicy(policyId, etag, updatedConfigXml) {
    const path = `/2020-05-31/response-headers-policy/${policyId}`;
    return await this.request(
      'cloudfront',
      'cloudfront.amazonaws.com',
      'PUT',
      path,
      {},
      {
        'Content-Type': 'application/xml',
        'If-Match': etag
      },
      updatedConfigXml
    );
  }

  // Update CloudFront Distribution Configuration
  async updateDistributionConfig(distributionId, etag, updatedConfigXml) {
    const path = `/2020-05-31/distribution/${distributionId}/config`;
    return await this.request(
      'cloudfront',
      'cloudfront.amazonaws.com',
      'PUT',
      path,
      {},
      {
        'Content-Type': 'application/xml',
        'If-Match': etag
      },
      updatedConfigXml
    );
  }
}

function parseAwsError(text, status) {
  if (!text) return `AWS HTTP ${status} error (empty response)`;
  
  const codeMatch = text.match(/<Code>([^<]+)<\/Code>/);
  const msgMatch = text.match(/<Message>([^<]+)<\/Message>/);

  const code = codeMatch ? codeMatch[1].trim() : `HTTP_${status}`;
  const message = msgMatch ? msgMatch[1].trim() : (text.length < 250 ? text : `AWS API returned status ${status}`);

  if (code === 'InvalidClientTokenId' || code === 'UnrecognizedClientException') {
    return `Invalid AWS Access Key or Security Token (${code}): The credentials provided were not recognized by AWS. Please verify your Access Key ID and Secret Access Key.`;
  }
  if (code === 'AccessDenied' || code === 'AccessDeniedException') {
    return `Access Denied (${code}): Your AWS identity does not have permission to assume this role or perform this operation. Check your IAM policy / Trust Policy.`;
  }
  if (code === 'SignatureDoesNotMatch') {
    return `Invalid Secret Access Key (${code}): The AWS Secret Access Key provided does not match your Access Key ID.`;
  }
  if (code === 'ExpiredToken' || code === 'ExpiredTokenException') {
    return `Session Token Expired (${code}): The temporary AWS session token has expired. Please refresh your session credentials.`;
  }

  return `AWS API Error [${code}]: ${message}`;
}

function escapeXml(value) {
  return value.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function unescapeXml(value) {
  return value.toString()
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

module.exports = AWSConnector;
