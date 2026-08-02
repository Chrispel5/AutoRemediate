const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const path = require('path');
const fetch = require('node-fetch');
const { normalizeDomain, isRecordNameAllowed } = require('./utils/domain');
const { createRateLimiter } = require('./utils/rateLimit');

// Import Scanners
const dnsAuditor = require('./scanners/dnsAuditor');
const headerAnalyzer = require('./scanners/headerAnalyzer');
const tlsInspector = require('./scanners/tlsInspector');
const softwareFingerprint = require('./scanners/softwareFingerprint');
const errorDisclosure = require('./scanners/errorDisclosure');
const cookieAnalyzer = require('./scanners/cookieAnalyzer');
const subdomainEnum = require('./scanners/subdomainEnum');

// Import Remediators & Connectors
const cloudflareConnector = require('./connectors/cloudflareConnector');
const dnsRemediator = require('./remediators/dnsRemediator');
const headerRemediator = require('./remediators/headerRemediator');
const reportBuilder = require('./utils/reportBuilder');

const AWSConnector = require('./connectors/awsConnector');
const cloudfrontRemediator = require('./remediators/cloudfrontRemediator');
const albRemediator = require('./remediators/albRemediator');
const route53Remediator = require('./remediators/route53Remediator');

// Upgrade Templates & Exporters
const { applyCompliance } = require('./templates/compliance');
const { applyRemediationMetadata } = require('./templates/remediation');
const { generateTerraform } = require('./templates/terraform');
const scanDb = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// The UI is served same-origin by this Express server, so cross-origin API
// calls are never legitimate. Lock CORS to localhost tool origins instead of
// the previous wildcard (which let any web page drive this server's cloud
// credentials).
const ALLOWED_ORIGINS = new Set([
  'http://localhost:3000', 'http://127.0.0.1:3000',
  'http://localhost:5500', 'http://127.0.0.1:5500',
  'http://localhost:8080', 'http://127.0.0.1:8080'
]);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'));
  }
}));
app.disable('x-powered-by');
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 30
});

app.use('/api', apiLimiter);

// In-memory databases
const scanCache = new Map();
const SCAN_CACHE_MAX = 100;

// Cap the cache by evicting the oldest entry (Map preserves insertion order).
// persist=false keeps demo data out of the SQLite scan history.
function cacheScan(scanId, scanResult, persist = true) {
  if (scanCache.size >= SCAN_CACHE_MAX && !scanCache.has(scanId)) {
    const oldestKey = scanCache.keys().next().value;
    scanCache.delete(oldestKey);
  }
  scanCache.set(scanId, scanResult);
  if (persist) {
    try { scanDb.saveScan(scanId, scanResult); } catch (e) { console.error('[DB] saveScan failed:', e.message); }
  }
}
let cfConnection = {
  connected: false,
  token: null,
  zoneMap: new Map() // domain -> zoneId
};
let awsConnection = {
  connected: false,
  roleArn: null,
  accessKeyId: null,
  secretAccessKey: null,
  sessionToken: null,
  region: 'us-east-1',
  expiresAt: null, // assumed-role temporary credentials expire after 1h
  distributionMap: new Map() // domain -> distributionId
};

// Route: Connect to Cloudflare API
app.post('/api/connect', async (req, res) => {
  const { apiToken } = req.body;
  console.log('[CONNECT] Received connect request, token length:', apiToken ? apiToken.length : 0);
  if (!apiToken) {
    return res.status(400).json({ error: 'API Token is required' });
  }

  try {
    const connector = new cloudflareConnector(apiToken);
    const isValid = await connector.verifyToken();
    console.log('[CONNECT] Token verification result:', isValid);
    if (!isValid) {
      console.log('[CONNECT] Token verification failed');
      return res.status(401).json({ error: 'Invalid API Token' });
    }

    cfConnection.connected = true;
    cfConnection.token = apiToken;
    cfConnection.zoneMap.clear();

    console.log('[CONNECT] SUCCESS — cfConnection.connected:', cfConnection.connected);
    return res.json({ success: true, message: 'Connected to Cloudflare successfully' });
  } catch (err) {
    console.log('[CONNECT] ERROR:', err.message);
    return res.status(500).json({ error: `Connection failed: ${err.message}` });
  }
});

// Debug: Connection status check
app.get('/api/status', (req, res) => {
  res.json({
    cloudflareConnected: cfConnection.connected,
    awsConnected: awsConnection.connected,
    hasToken: !!cfConnection.token,
    hasAwsKey: !!(awsConnection.accessKeyId || awsConnection.roleArn),
    roleArn: awsConnection.roleArn ? '***' : null, // never leak the ARN to clients
    cachedScans: scanCache.size,
    cachedZones: cfConnection.zoneMap.size
  });
});

// Route: Disconnect providers and wipe stored credentials from memory
app.post('/api/disconnect', (req, res) => {
  cfConnection.connected = false;
  cfConnection.token = null;
  cfConnection.zoneMap.clear();
  awsConnection.connected = false;
  awsConnection.roleArn = null;
  awsConnection.accessKeyId = null;
  awsConnection.secretAccessKey = null;
  awsConnection.sessionToken = null;
  awsConnection.region = 'us-east-1';
  awsConnection.expiresAt = null;
  awsConnection.distributionMap.clear();
  return res.json({ success: true, message: 'Disconnected providers and cleared credentials' });
});

function getLocalAwsCredentials() {
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: process.env.AWS_SESSION_TOKEN || null
    };
  }

  try {
    const credPath = path.join(os.homedir(), '.aws', 'credentials');
    if (fs.existsSync(credPath)) {
      const content = fs.readFileSync(credPath, 'utf8');
      // Only read the [default] profile so keys from different profiles are
      // never cross-paired into one credential set.
      const defaultSection = content.match(/^\[default\]([\s\S]*?)(?=^\s*\[|\s*$)/m);
      const section = defaultSection ? defaultSection[1] : content;
      const keyMatch = section.match(/aws_access_key_id\s*=\s*([^\s]+)/i);
      const secMatch = section.match(/aws_secret_access_key\s*=\s*([^\s]+)/i);
      const tokenMatch = section.match(/aws_session_token\s*=\s*([^\s]+)/i);
      if (keyMatch && secMatch) {
        return {
          accessKeyId: keyMatch[1],
          secretAccessKey: secMatch[1],
          sessionToken: tokenMatch ? tokenMatch[1] : null
        };
      }
    }
  } catch (e) {
    console.error('[AWS] Failed to read local AWS credentials:', e.message);
  }

  return null;
}

// Route: Connect to AWS API (Supports IAM Role ARN AssumeRole or Access Keys)
app.post('/api/connect-aws', async (req, res) => {
  const { roleArn, accessKeyId, secretAccessKey, region, sessionToken } = req.body;
  const awsRegion = region || 'us-east-1';

  const localCreds = getLocalAwsCredentials() || {};

  if (!roleArn && (!accessKeyId || !secretAccessKey) && !localCreds.accessKeyId) {
    return res.status(400).json({ error: 'Provide either an IAM Role ARN or Access Key ID & Secret Access Key.' });
  }

  try {
    let keyId = accessKeyId || localCreds.accessKeyId;
    let secKey = secretAccessKey || localCreds.secretAccessKey;
    let sToken = sessionToken || localCreds.sessionToken || null;

    if (roleArn) {
      if (!keyId || !secKey) {
        return res.status(400).json({
          error: 'Assuming an IAM Role requires base credentials to sign the AssumeRole request. Please enter your AWS Access Key ID & Secret Access Key in the fields below, or configure them in your local AWS CLI (~/.aws/credentials).'
        });
      }

      const baseConnector = new AWSConnector(keyId, secKey, awsRegion, sToken);
      const assumedCreds = await baseConnector.assumeRole(roleArn);
      keyId = assumedCreds.accessKeyId;
      secKey = assumedCreds.secretAccessKey;
      sToken = assumedCreds.sessionToken;
    }

    const connector = new AWSConnector(keyId, secKey, awsRegion, sToken);
    const isValid = await connector.verifyCredentials();
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid AWS Credentials or Role Assumption failed.' });
    }

    awsConnection.connected = true;
    awsConnection.roleArn = roleArn || null;
    awsConnection.accessKeyId = keyId;
    awsConnection.secretAccessKey = secKey;
    awsConnection.sessionToken = sToken;
    awsConnection.region = awsRegion;
    awsConnection.expiresAt = roleArn ? Date.now() + 3600 * 1000 : null;
    awsConnection.distributionMap.clear();

    const message = roleArn
      ? `Successfully assumed IAM Role (${roleArn}) and connected to AWS!`
      : 'Connected to AWS successfully!';

    return res.json({ success: true, message });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// Route: Trigger scan
app.post('/api/scan', async (req, res) => {
  const { target } = req.body;

  let domain;
  try {
    domain = normalizeDomain(target);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const scanId = 'scan_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  const startTime = new Date();

  // Run all scanners in parallel using Promise.allSettled
  try {
    const results = await Promise.allSettled([
      dnsAuditor.checkSPF(domain),
      dnsAuditor.checkDMARC(domain),
      dnsAuditor.checkMX(domain),
      dnsAuditor.checkDKIM(domain),
      dnsAuditor.checkStaleTXT(domain),
      headerAnalyzer.analyze(domain),
      tlsInspector.inspect(domain),
      softwareFingerprint.fingerprint(domain),
      errorDisclosure.check(domain),
      cookieAnalyzer.analyze(domain),
      subdomainEnum.enumerate(domain)
    ]);

    const findings = [];
    let infraType = 'unknown';

    results.forEach((res) => {
      if (res.status === 'fulfilled') {
        if (Array.isArray(res.value)) {
          findings.push(...res.value);
        } else if (res.value && res.value.findings) {
          findings.push(...res.value.findings);
          if (res.value.infraType) {
            infraType = res.value.infraType;
          }
        } else if (res.value) {
          findings.push(res.value);
        }
      } else {
        console.error('Scanner error:', res.reason);
      }
    });

    // If AWS is connected and scanning a CloudFront distribution, check live distribution config for attached ResponseHeadersPolicyId
    if (awsConnection.connected && awsConnection.accessKeyId) {
      try {
        const awsConn = new AWSConnector(awsConnection.accessKeyId, awsConnection.secretAccessKey, awsConnection.region, awsConnection.sessionToken);
        const dists = await awsConn.listDistributions();
        const targetDomain = domain.toLowerCase();
        const targetDist = dists.find(d => d.domainName.toLowerCase() === targetDomain || d.aliases.includes(targetDomain));
        if (targetDist) {
          const { xml } = await awsConn.getDistributionConfig(targetDist.id);
          const policyMatch = xml.match(/<ResponseHeadersPolicyId>([^<]+)<\/ResponseHeadersPolicyId>/);
          if (policyMatch && policyMatch[1]) {
            const policyId = policyMatch[1];
            // Don't blanket-PASS on an attached policy ID: re-fetch the live
            // site and only flip findings whose header is actually served.
            const headerForFinding = {
              'csp-missing': 'content-security-policy',
              'hsts-missing': 'strict-transport-security',
              'xframe-missing': 'x-frame-options',
              'xcto-missing': 'x-content-type-options',
              'referrer-missing': 'referrer-policy',
              'permissions-missing': 'permissions-policy'
            };
            const liveResp = await fetch(`https://${domain}`, {
              method: 'GET',
              timeout: 10000,
              headers: { 'User-Agent': 'AutoRemediate-Scanner/1.0' }
            });
            findings.forEach(f => {
              const headerName = headerForFinding[f.id];
              if (headerName && liveResp.headers.get(headerName)) {
                f.status = 'PASS';
                f.severity = 'PASS';
                f.evidence = `CloudFront Response Headers Policy Active (Policy ID: ${policyId}) — ${headerName} present in live response`;
                f.name = f.name.replace('Missing / Weak', 'Configured').replace('Missing', 'Active');
              }
            });
          }
        }
      } catch (cfErr) {
        console.log('[SCAN] CloudFront Policy check note:', cfErr.message);
      }
    }

    const enriched = applyRemediationMetadata(applyCompliance(findings), domain);

    const scanResult = {
      scanId,
      target: domain,
      scanTime: startTime.toISOString(),
      infraType,
      findings: enriched
    };

    cacheScan(scanId, scanResult);
    return res.json(scanResult);
  } catch (err) {
    return res.status(500).json({ error: `Scan execution failed: ${err.message}` });
  }
});

// Route: Export Terraform configuration
app.post('/api/terraform/export', (req, res) => {
  const { scanId, findingId, provider } = req.body;
  if (!scanId || !findingId || !provider) {
    return res.status(400).json({ error: 'scanId, findingId, and provider are required' });
  }

  if (provider !== 'cloudflare' && provider !== 'aws') {
    return res.status(400).json({ error: "Unsupported provider. Choose 'cloudflare' or 'aws'." });
  }

  const scan = scanCache.get(scanId) || scanDb.getScan(scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan session not found' });
  }

  const finding = scan.findings.find(f => f.id === findingId);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found in this scan session' });
  }

  if (!finding.fix && finding.status !== 'PASS') {
    return res.status(400).json({ error: 'No Terraform export available for this finding.' });
  }

  try {
    const tfCode = generateTerraform(finding, scan.target, provider);
    const filename = `autoremediate-${finding.id}-${provider}.tf`;
    return res.json({
      success: true,
      filename,
      terraform: tfCode
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// Route: Apply remediation fix
app.post('/api/remediate', async (req, res) => {
  const { scanId, findingId, provider } = req.body;
  if (!scanId || !findingId) {
    return res.status(400).json({ error: 'scanId and findingId are required' });
  }

  const scan = scanCache.get(scanId) || scanDb.getScan(scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan session not found' });
  }

  const findingIndex = scan.findings.findIndex(f => f.id === findingId);
  if (findingIndex === -1) {
    return res.status(404).json({ error: 'Finding not found in this scan session' });
  }

  const finding = scan.findings[findingIndex];
  if (!finding.fix) {
    return res.status(400).json({ error: 'No automatic fix available for this finding' });
  }

  if (finding.fix.record && !isRecordNameAllowed(finding.fix.record.name, scan.target)) {
    return res.status(400).json({ error: 'Refusing to remediate DNS records outside the scanned domain.' });
  }

  console.log('[REMEDIATE] cfConnected:', cfConnection.connected, '| awsConnected:', awsConnection.connected, '| requestedProvider:', provider);
  if ((!cfConnection.connected || !cfConnection.token) && (!awsConnection.connected || !awsConnection.accessKeyId)) {
    return res.status(400).json({ error: 'Cloud provider connection required to apply fixes. Connect Cloudflare or AWS.' });
  }

  try {
    let remediationResult;
    // An explicitly requested provider ('cloudflare' or 'aws') is honored
    // strictly; only fall through to the other provider when none was
    // requested (or 'both' was requested).
    const explicitProvider = provider && provider !== 'both' ? provider : null;
    const targetProvider = provider || (awsConnection.connected && !cfConnection.connected ? 'aws' : 'cloudflare');

    // Fail fast with a clear message when the requested provider is not
    // connected, instead of silently returning "Unknown error".
    if (explicitProvider === 'cloudflare' && !cfConnection.connected) {
      return res.status(400).json({ error: 'Cloudflare is not connected. Connect Cloudflare first, or request provider "aws".' });
    }
    if (explicitProvider === 'aws' && !awsConnection.connected) {
      return res.status(400).json({ error: 'AWS is not connected. Connect AWS first, or request provider "cloudflare".' });
    }
    // Assumed-role session tokens expire after 1 hour; refuse to act on stale creds.
    if (awsConnection.connected && awsConnection.expiresAt && Date.now() > awsConnection.expiresAt) {
      awsConnection.connected = false;
      return res.status(400).json({ error: 'AWS session credentials have expired. Reconnect to AWS (or re-assume the IAM role) before remediating.' });
    }

    if (finding.fix.type === 'dns' || finding.fix.type === 'dns-update' || finding.fix.type === 'dns-delete') {
      if ((targetProvider === 'cloudflare' || targetProvider === 'both') && cfConnection.connected) {
        try {
          const connector = new cloudflareConnector(cfConnection.token);
          let zoneId = cfConnection.zoneMap.get(scan.target);
          if (!zoneId) {
            zoneId = await connector.getZoneId(scan.target);
            cfConnection.zoneMap.set(scan.target, zoneId);
          }
          remediationResult = await dnsRemediator.applyFix(connector, zoneId, scan.target, finding);
        } catch (cfErr) {
          remediationResult = { success: false, error: cfErr.message };
        }
      }
      
      if ((targetProvider === 'aws' || targetProvider === 'both' || (!explicitProvider && (!remediationResult || !remediationResult.success))) && awsConnection.connected) {
        const awsConn = new AWSConnector(awsConnection.accessKeyId, awsConnection.secretAccessKey, awsConnection.region, awsConnection.sessionToken);
        const awsResult = await route53Remediator.applyFix(awsConn, scan.target, finding);
        if (remediationResult && remediationResult.success && awsResult.success) {
          // Both providers applied the fix — append the AWS verification
          remediationResult.verification += ` | ${awsResult.verification}`;
        } else if (!remediationResult || !remediationResult.success) {
          // Never overwrite a success with a failure
          remediationResult = awsResult;
        }
      }
    } else if (finding.fix.type === 'cloudflare-rule') {
      if ((targetProvider === 'cloudflare' || targetProvider === 'both') && cfConnection.connected) {
        try {
          const connector = new cloudflareConnector(cfConnection.token);
          let zoneId = cfConnection.zoneMap.get(scan.target);
          if (!zoneId) {
            zoneId = await connector.getZoneId(scan.target);
            cfConnection.zoneMap.set(scan.target, zoneId);
          }
          remediationResult = await headerRemediator.applyFix(connector, zoneId, scan.target, finding);
        } catch (cfErr) {
          remediationResult = { success: false, error: cfErr.message };
        }
      }

      if ((targetProvider === 'aws' || targetProvider === 'both' || (!explicitProvider && (!remediationResult || !remediationResult.success))) && awsConnection.connected) {
        const awsConn = new AWSConnector(awsConnection.accessKeyId, awsConnection.secretAccessKey, awsConnection.region, awsConnection.sessionToken);
        // Prefer ALB listener header injection when the site fronts an ALB;
        // fall back to CloudFront Response Headers Policy otherwise.
        let awsResult = await albRemediator.applyFix(awsConn, scan.target, finding);
        if (awsResult && awsResult.notApplicable) {
          awsResult = await cloudfrontRemediator.applyFix(awsConn, scan.target, finding);
        }
        if (remediationResult && remediationResult.success && awsResult.success) {
          remediationResult.verification += ` | ${awsResult.verification}`;
        } else if (!remediationResult || !remediationResult.success) {
          remediationResult = awsResult;
        }
      }
    } else {
      return res.status(400).json({ error: `Fix type '${finding.fix.type}' is not auto-remediable.` });
    }

    if (remediationResult && remediationResult.success) {
      // Only a genuinely verified result flips the finding to PASS. An applied
      // but unconfirmed fix (e.g. DNS propagation still pending) stays FAIL so
      // the UI can never claim "verified" for an unverified change.
      const verificationText = remediationResult.verification || '';
      const actuallyVerified = /verified/i.test(verificationText) && !/pending/i.test(verificationText);
      scan.findings[findingIndex].status = actuallyVerified ? 'PASS' : 'FAIL';
      scan.findings[findingIndex].severity = actuallyVerified ? 'PASS' : scan.findings[findingIndex].severity;
      scan.findings[findingIndex].remediationDetails = { ...remediationResult, verified: actuallyVerified };
      
      // Update scanCache
      cacheScan(scanId, scan);
      try { scanDb.recordRemediation(scanId, findingId, provider, remediationResult.verification); } catch (e) { console.error('[DB] recordRemediation failed:', e.message); }
      return res.json({ success: true, finding: scan.findings[findingIndex] });
    } else {
      let errText = remediationResult ? remediationResult.error : 'Unknown error during remediation';
      if (errText.includes('Route 53 hosted zone not found') && scan.target.includes('cloudfront.net')) {
        errText = `DNS records (SPF/DMARC) are managed on custom domain registrars, not raw *.cloudfront.net hostnames. To test AWS CloudFront Auto-Fix, click Auto-Fix on a Security Header finding (such as Content-Security-Policy or HSTS).`;
      }
      return res.status(400).json({ error: errText });
    }
  } catch (err) {
    let msg = err.message;
    if (msg.includes('Route 53 hosted zone not found') && scan.target.includes('cloudfront.net')) {
      msg = `DNS records (SPF/DMARC) are managed on custom domain registrars, not raw *.cloudfront.net hostnames. To test AWS CloudFront Auto-Fix, click Auto-Fix on a Security Header finding (such as Content-Security-Policy or HSTS).`;
    }
    return res.status(400).json({ error: `Remediation failed: ${msg}` });
  }
});

// Route: Generate HTML Report (falls back to SQLite so reports survive restarts)
app.get('/api/report/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = scanCache.get(scanId) || scanDb.getScan(scanId);
  if (!scan) {
    return res.status(404).send('<h1>Report Not Found</h1><p>Please run a scan first.</p>');
  }

  const html = reportBuilder.generateReport(scan);
  res.setHeader('Content-Type', 'text/html');
  return res.send(html);
});

// Route: Scan history (list + detail)
app.get('/api/history', (req, res) => {
  return res.json({ scans: scanDb.listScans() });
});

app.get('/api/history/:scanId', (req, res) => {
  const scan = scanDb.getScan(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  return res.json({ scan, remediations: scanDb.listRemediations(req.params.scanId) });
});

// Route: Portfolio/Demo Mode data
app.get('/api/demo', (req, res) => {
  const scanId = 'scan_demo';
  const demoData = {
    scanId,
    target: 'demo.example.com',
    scanTime: new Date().toISOString(),
    infraType: 'apache',
    findings: [
      {
        id: 'dmarc-missing',
        name: 'No DMARC Record Found',
        severity: 'CRITICAL',
        status: 'FAIL',
        evidence: 'No DMARC TXT record found at _dmarc.demo.example.com',
        description: 'Anyone can spoof emails from this domain. Email providers have no policy instructions.',
        fix: {
          type: 'dns',
          record: { type: 'TXT', name: '_dmarc.demo.example.com', content: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@demo.example.com;' }
        }
      },
      {
        id: 'csp-missing',
        name: 'Content-Security-Policy (CSP) Header Missing',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: 'Content-Security-Policy: (Not present)',
        description: 'The Content-Security-Policy header restricts resources that can load on your pages, protecting against Cross-Site Scripting (XSS).',
        fix: {
          type: 'cloudflare-rule',
          header: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self' https://www.googletagmanager.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;"
        }
      },
      {
        id: 'server-version-exposed',
        name: 'Web Server Version Disclosed',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: 'Server: Apache/2.4.41 (Ubuntu)',
        description: 'Exposing specific server version numbers makes it easier for attackers to identify matches for known vulnerabilities (CVEs).',
        fix: {
          type: 'config',
          notes: 'Apache configuration needs ServerTokens set to Prod'
        }
      },
      {
        id: 'spf-softfail',
        name: 'SPF Soft Fail Configured (~all)',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: 'TXT Record: v=spf1 include:_spf.google.com ~all',
        description: 'SPF soft fail (~all) tells receiving servers to accept spoofed emails and flag them, rather than reject them outright (-all).',
        fix: {
          type: 'dns-update',
          record: { type: 'TXT', name: 'demo.example.com', content: 'v=spf1 include:_spf.google.com -all' }
        }
      },
      {
        id: 'hsts-missing',
        name: 'HTTP Strict Transport Security (HSTS) Missing',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: 'Strict-Transport-Security: (Not present)',
        description: 'HSTS instructs browsers to only connect to your site over secure HTTPS connections, preventing SSL stripping attacks.',
        fix: {
          type: 'cloudflare-rule',
          header: 'Strict-Transport-Security',
          value: 'max-age=31536000; includeSubDomains; preload'
        }
      },
      {
        id: 'error-disclosure',
        name: 'Stack Trace Leak on Database Exception',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: 'PHP Fatal Error: Call to undefined function mysqli_connect() in /var/www/html/lib.php on line 53\nStack trace:\n#0 /var/www/html/index.php(10): db_connect()',
        description: 'Exceptions and stack traces disclose backend filenames, function calls, and database driver details, easing attacker payload writing.',
        fix: {
          type: 'config',
          notes: 'Configure error_reporting, display_errors = Off in php.ini'
        }
      },
      {
        id: 'cookie-insecure',
        name: 'Sensitive Session Cookie Lacks HttpOnly/Secure Flags',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: 'Set-Cookie: PHPSESSID=abc123xyz; path=/',
        description: 'Without HttpOnly, scripts can read the session cookie (XSS session hijacking). Without Secure, cookies can be transmitted over unencrypted HTTP.',
        fix: {
          type: 'config',
          notes: 'Set session.cookie_secure = On and session.cookie_httponly = On in php.ini'
        }
      },
      {
        id: 'stale-txt-token',
        name: 'Legacy DNS Verification Token Present',
        severity: 'LOW',
        status: 'FAIL',
        evidence: 'TXT record: google-site-verification=abcdef1234567890',
        description: 'Legacy search console or domain verification tokens create metadata noise and leak historic security providers used.',
        fix: {
          type: 'dns-delete',
          record: { type: 'TXT', name: 'demo.example.com', content: 'google-site-verification=abcdef1234567890' }
        }
      },
      {
        id: 'xframe',
        name: 'Clickjacking Protection Active',
        severity: 'PASS',
        status: 'PASS',
        evidence: 'X-Frame-Options: SAMEORIGIN',
        description: 'Prevents the site from being framed inside malicious sites, mitigating clickjacking.'
      },
      {
        id: 'tls-valid',
        name: 'TLS Certificate Valid',
        severity: 'PASS',
        status: 'PASS',
        evidence: 'Issuer: Let\'s Encrypt, Valid until: 2027-06-15 (347 days remaining), Protocol: TLSv1.3',
        description: 'The site encrypts web transit using valid TLS protocols and certificate properties.'
      }
    ]
  };

  demoData.findings = applyRemediationMetadata(applyCompliance(demoData.findings), demoData.target);

  // Demo data is kept out of the SQLite scan history so it never pollutes
  // real assessment listings.
  cacheScan(scanId, demoData, false);
  return res.json(demoData);
});

app.listen(PORT, () => {
  console.log(`AutoRemediate API server running at http://localhost:${PORT}`);
});
