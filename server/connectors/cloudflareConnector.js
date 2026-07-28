const fetch = require('node-fetch');

class CloudflareConnector {
  constructor(apiToken) {
    this.token = apiToken;
    this.baseUrl = 'https://api.cloudflare.com/client/v4';
  }

  // Returns the full API envelope ({ success, errors, result, result_info })
  async requestFull(endpoint, options = {}) {
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
    return data;
  }

  async request(endpoint, options = {}) {
    const data = await this.requestFull(endpoint, options);
    return data.result;
  }

  // Zone-scoped tokens cannot call /user/tokens/verify, so accept the token
  // if either that endpoint or a zones listing confirms validity.
  async verifyToken() {
    try {
      await this.request('/user/tokens/verify');
      return true;
    } catch (err) {
      // Fall through to zone-scoped check
    }
    try {
      await this.request('/zones?per_page=1');
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
    const typeParam = type ? `&type=${encodeURIComponent(type)}` : '';
    const all = [];
    let page = 1;

    while (true) {
      const data = await this.requestFull(`/zones/${zoneId}/dns_records?per_page=100&page=${page}${typeParam}`);
      all.push(...(data.result || []));
      const info = data.result_info;
      if (!info || !info.total_pages || page >= info.total_pages) break;
      page++;
    }

    return all;
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
    // Response header modifications live on the zone entrypoint ruleset for
    // the http_response_headers_transform phase.
    const rulesets = await this.request(`/zones/${zoneId}/rulesets`);
    const targetRuleset = rulesets.find(r => r.phase === 'http_response_headers_transform');

    if (!targetRuleset) {
      // Cloudflare rejects an entrypoint created with an empty rules array.
      // Create-or-update the phase entrypoint with the rule included.
      return await this.request(`/zones/${zoneId}/rulesets/phases/http_response_headers_transform/entrypoint`, {
        method: 'PUT',
        body: JSON.stringify({ rules: [rule] })
      });
    }

    // Dedup: drop any existing rule that already sets the same header(s)
    const newHeaders = Object.keys((rule.action_parameters && rule.action_parameters.headers) || {})
      .map(h => h.toLowerCase());
    if (newHeaders.length > 0) {
      const existing = await this.request(`/zones/${zoneId}/rulesets/${targetRuleset.id}`);
      const existingRules = (existing && existing.rules) || [];
      for (const r of existingRules) {
        const ruleHeaders = Object.keys((r.action_parameters && r.action_parameters.headers) || {})
          .map(h => h.toLowerCase());
        if (ruleHeaders.some(h => newHeaders.includes(h))) {
          await this.request(`/zones/${zoneId}/rulesets/${targetRuleset.id}/rules/${r.id}`, {
            method: 'DELETE'
          });
        }
      }
    }

    // Append rule to the ruleset
    return await this.request(`/zones/${zoneId}/rulesets/${targetRuleset.id}/rules`, {
      method: 'POST',
      body: JSON.stringify(rule)
    });
  }
}

module.exports = CloudflareConnector;
