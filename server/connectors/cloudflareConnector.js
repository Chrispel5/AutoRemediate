const fetch = require('node-fetch');

class CloudflareConnector {
  constructor(apiToken) {
    this.token = apiToken;
    this.baseUrl = 'https://api.cloudflare.com/client/v4';
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      ...options.headers
    };

    const response = await fetch(url, {
      ...options,
      headers
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
      const errorMsg = data.errors && data.errors.length > 0 
        ? data.errors.map(e => `${e.message} (Code: ${e.code})`).join(', ')
        : `HTTP Error ${response.status}`;
      throw new Error(errorMsg);
    }
    return data.result;
  }

  async verifyToken() {
    try {
      await this.request('/user/tokens/verify');
      return true;
    } catch (err) {
      return false;
    }
  }

  async getZoneId(domain) {
    const zones = await this.request(`/zones?name=${domain}`);
    if (!zones || zones.length === 0) {
      throw new Error(`Zone for domain ${domain} not found in this Cloudflare account.`);
    }
    return zones[0].id;
  }

  async listDnsRecords(zoneId, type = '') {
    const typeParam = type ? `?type=${type}` : '';
    return await this.request(`/zones/${zoneId}/dns_records${typeParam}`);
  }

  async createDnsRecord(zoneId, record) {
    // record should look like: { type: 'TXT', name: '_dmarc.example.com', content: '...', ttl: 3600 }
    return await this.request(`/zones/${zoneId}/dns_records`, {
      method: 'POST',
      body: JSON.stringify(record)
    });
  }

  async updateDnsRecord(zoneId, recordId, record) {
    return await this.request(`/zones/${zoneId}/dns_records/${recordId}`, {
      method: 'PUT',
      body: JSON.stringify(record)
    });
  }

  async deleteDnsRecord(zoneId, recordId) {
    return await this.request(`/zones/${zoneId}/dns_records/${recordId}`, {
      method: 'DELETE'
    });
  }

  async createTransformRule(zoneId, rule) {
    // rule should represent the transformation rule JSON
    // POST /zones/{zoneId}/rulesets for response header modifications
    // In CF API v4, response headers are configured under rulesets matching 'zone' and phase 'http_response_headers_transform'
    
    // First retrieve rulesets to find phase http_response_headers_transform
    const rulesets = await this.request(`/zones/${zoneId}/rulesets`);
    let targetRuleset = rulesets.find(r => r.phase === 'http_response_headers_transform');

    if (!targetRuleset) {
      // If it does not exist, create the entry ruleset first
      targetRuleset = await this.request(`/zones/${zoneId}/rulesets`, {
        method: 'POST',
        body: JSON.stringify({
          name: 'Response Headers Ruleset',
          kind: 'zone',
          phase: 'http_response_headers_transform',
          rules: []
        })
      });
    }

    // Append rule to the ruleset
    return await this.request(`/zones/${zoneId}/rulesets/${targetRuleset.id}/rules`, {
      method: 'POST',
      body: JSON.stringify(rule)
    });
  }
}

module.exports = CloudflareConnector;
