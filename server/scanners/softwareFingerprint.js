const fetch = require('node-fetch');

async function fingerprint(domain) {
  const url = `https://${domain}`;
  const pathChecks = ['/README.md', '/CHANGELOG.md', '/changelog.txt'];
  let detectedInfo = [];
  // Version leaks owned by THIS scanner (meta generator tags, changelogs).
  // Header-based version disclosure is reported by headerAnalyzer instead.
  let versionLeaks = [];

  try {
    // Check main response headers first
    const mainResponse = await fetch(url, { method: 'GET', timeout: 5000 });
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
        const pathResponse = await fetch(url + path, { method: 'GET', timeout: 3000 });
        // SPA/framework catch-all routes answer 200 with index.html for every
        // path. Fingerprinting that app shell as "/CHANGELOG.md exists" is a
        // false positive, so only non-HTML bodies are inspected.
        const pathContentType = pathResponse.headers.get('content-type') || '';
        if (pathResponse.status === 200 && !pathContentType.includes('text/html')) {
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
      // Only report what this scanner actually cleared. Echoing a versioned
      // Server header here contradicted the PASS verdict; header-based
      // disclosure is owned by the header scan.
      evidence: 'No version markers found in meta generator tags or changelog files.',
      description: 'No application version tags were exposed via HTML metadata or public changelog files. (Header-based version disclosure is reported separately by the header scan.)'
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
