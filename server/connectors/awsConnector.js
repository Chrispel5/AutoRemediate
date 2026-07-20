const crypto = require('crypto');
const fetch = require('node-fetch');

class AWSConnector {
  constructor(accessKeyId, secretAccessKey, region = 'us-east-1') {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.region = region;
  }

  // AWS Signature Version 4 Helper
  sign(method, service, host, path, queryParams = {}, headers = {}, body = '') {
    const datetime = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
    const date = datetime.substr(0, 8);

    headers['host'] = host;
    headers['x-amz-date'] = datetime;

    // 1. Create Canonical Request
    const canonicalUri = path || '/';
    
    // Sort query parameters
    const sortedQuery = Object.keys(queryParams)
      .sort()
      .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
      .join('&');

    // Canonical Headers
    const canonicalHeaders = Object.keys(headers)
      .sort()
      .map(key => `${key.toLowerCase()}:${headers[key].toString().trim()}`)
      .join('\n') + '\n';

    const signedHeaders = Object.keys(headers)
      .map(key => key.toLowerCase())
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
    const credentialScope = [date, this.region, service, 'aws4_request'].join('/');
    const canonicalRequestHash = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
    const stringToSign = [algorithm, datetime, credentialScope, canonicalRequestHash].join('\n');

    // 3. Calculate Signature
    const kDate = crypto.createHmac('sha256', `AWS4${this.secretAccessKey}`).update(date).digest();
    const kRegion = crypto.createHmac('sha256', kDate).update(this.region).digest();
    const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
    const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
    const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

    // 4. Add Authorization Header
    headers['Authorization'] = `${algorithm} Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return headers;
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
      throw new Error(`AWS request failed: Status ${res.status}. Body: ${text}`);
    }
    return text;
  }

  // Verify credentials by calling GetCallerIdentity on STS
  async verifyCredentials() {
    try {
      // STS is global but default endpoint is sts.amazonaws.com
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
    } catch (err) {
      console.error('STS verification error:', err);
      return false;
    }
  }

  // List Hosted Zones in Route 53
  async listHostedZones() {
    const xml = await this.request('route53', 'route53.amazonaws.com', 'GET', '/2013-04-01/hostedzone');
    const zones = [];
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
    return zones;
  }

  // Create or Update DNS Records in Route 53
  async changeResourceRecordSets(hostedZoneId, action, recordName, recordType, recordValue, ttl = 300) {
    const path = `/2013-04-01/hostedzone/${hostedZoneId}/rrset`;
    
    // Build change batch XML payload
    // XML value escaping
    const escapedValue = recordValue.startsWith('"') ? recordValue : `"${recordValue}"`;
    const xmlBody = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>${action}</Action>
        <ResourceRecordSet>
          <Name>${recordName}</Name>
          <Type>${recordType}</Type>
          <TTL>${ttl}</TTL>
          <ResourceRecords>
            <ResourceRecord>
              <Value>${escapedValue}</Value>
            </ResourceRecord>
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

  // List CloudFront Distributions
  async listDistributions() {
    const xml = await this.request('cloudfront', 'cloudfront.amazonaws.com', 'GET', '/2020-05-31/distribution');
    const dists = [];
    
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

  // Create Response Headers Policy
  async createResponseHeadersPolicy(policyName, headersConfig) {
    const path = `/2020-05-31/response-headers-policy`;
    
    let securityHeadersXml = '';
    if (headersConfig.ContentSecurityPolicy) {
      securityHeadersXml += `<ContentSecurityPolicy>
        <Override>true</Override>
        <ContentSecurityPolicy>${headersConfig.ContentSecurityPolicy}</ContentSecurityPolicy>
      </ContentSecurityPolicy>`;
    }
    if (headersConfig.StrictTransportSecurity) {
      securityHeadersXml += `<StrictTransportSecurity>
        <Override>true</Override>
        <AccessControlMaxAgeSec>${headersConfig.StrictTransportSecurity.maxAge || 31536000}</AccessControlMaxAgeSec>
        <IncludeSubdomains>${headersConfig.StrictTransportSecurity.includeSubdomains || 'true'}</IncludeSubdomains>
        <Preload>${headersConfig.StrictTransportSecurity.preload || 'true'}</Preload>
      </StrictTransportSecurity>`;
    }
    if (headersConfig.FrameOptions) {
      securityHeadersXml += `<FrameOptions>
        <Override>true</Override>
        <FrameOption>${headersConfig.FrameOptions}</FrameOption>
      </FrameOptions>`;
    }
    if (headersConfig.ContentTypeOptions) {
      securityHeadersXml += `<ContentTypeOptions>
        <Override>true</Override>
      </ContentTypeOptions>`;
    }

    const xmlBody = `<?xml version="1.0" encoding="UTF-8"?>
<ResponseHeadersPolicyConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Name>${policyName}</Name>
  <Comment>AutoRemediate Security Headers Policy</Comment>
  <SecurityHeadersConfig>
    ${securityHeadersXml}
  </SecurityHeadersConfig>
</ResponseHeadersPolicyConfig>`;

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

module.exports = AWSConnector;
