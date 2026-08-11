const { fetchWithinOrigin } = require('../utils/httpTarget');

async function fingerprint(domain) {
  const url = `https://${domain}`;
  const pathChecks = ['/README.md', '/CHANGELOG.md', '/changelog.txt'];
  let detectedInfo = [];
  // Version leaks owned by THIS scanner (meta generator tags, changelogs).
  // Header-based version disclosure is reported by headerAnalyzer instead.
  let versionLeaks = [];

  try {
    // Check main response headers first
    const mainResult = await fetchWithinOrigin(url, { method: 'GET', timeout: 5000 });
    const mainResponse = mainResult.response;
    if (mainResult.externalRedirect) {
      return {
        id: 'software-fingerprint-auth-limited',
        name: 'Software Fingerprinting Limited by Authentication',
        severity: 'LOW',
        status: 'FAIL',
        evidence: `Target redirects to external authentication origin: ${mainResult.externalRedirect}`,
        description: 'The unauthenticated target response was inspected, but application HTML and version files behind authentication were not accessible.'
      };
    }
    const serverHeader = mainResponse.headers.get('server') || '';
    const xPoweredBy = mainResponse.headers.get('x-powered-by') || '';

    if (serverHeader) {
      detectedInfo.push(`Server Header: ${serverHeader}`);
    }
    if (xPoweredBy) {
      detectedInfo.push(`Powered-By: ${xPoweredBy}`);
    }

    // HTML analysis for meta generator tags (attributes in either order)
    const htmlText = await mainResponse.text();
    const generatorMatch = htmlText.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i)
      || htmlText.match(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']generator["']/i);
    if (generatorMatch && generatorMatch[1]) {
      detectedInfo.push(`Meta Generator: ${generatorMatch[1]}`);
      versionLeaks.push(`Meta Generator: ${generatorMatch[1]}`);
    }

    // Proactively check common paths
    for (const path of pathChecks) {
      try {
        const pathResult = await fetchWithinOrigin(url + path, { method: 'GET', timeout: 3000 });
        const pathResponse = pathResult.response;
        if (pathResult.externalRedirect) continue;
        if (pathResponse.status === 200) {
          const content = await pathResponse.text();
          // Check for version markers like "Version 1.2.3" or "v1.2.3" or framework version patterns
          const versionMatch = content.match(/version\s*(\d+\.\d+(\.\d+)?)/i);
          if (versionMatch) {
            detectedInfo.push(`Changelog Version: ${versionMatch[1]} (found in ${path})`);
            versionLeaks.push(`Changelog Version: ${versionMatch[1]} (found in ${path})`);
          }
        }
      } catch (err) {
        // Ignore single path failures
      }
    }

    // Determine findings based on what was detected
    const findingsExposed = versionLeaks.length > 0;

    if (findingsExposed) {
      return {
        id: 'software-fingerprint-ver',
        name: 'Outdated / Verifiable Software Stacks Exposed',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: versionLeaks.join('\n'),
        description: 'Metadata or files disclose specific framework, language, or system version details. This eases targeted exploit searches.',
        fix: {
          type: 'config',
          notes: 'Disable meta generator tags in application headers and remove public changelog/readme files with version markers.'
        }
      };
    }

    return {
      id: 'software-fingerprint',
      name: 'Software Stacks Anonymized',
      severity: 'PASS',
      status: 'PASS',
      evidence: detectedInfo.join('\n') || 'No headers or files disclosed technology versions.',
      description: 'System software name or application version tags are successfully hidden from scanning components.'
    };

  } catch (err) {
    return {
      id: 'software-fingerprint-failed',
      name: 'Software Fingerprinting Incomplete',
      severity: 'LOW',
      status: 'FAIL',
      evidence: err.message,
      description: 'Handshake timeout or network block halted software library analysis.'
    };
  }
}

module.exports = { fingerprint };
