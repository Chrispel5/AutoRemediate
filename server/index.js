const express = require('express');
const cors = require('cors');
const path = require('path');
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
const route53Remediator = require('./remediators/route53Remediator');

// Upgrade Templates & Exporters
const { applyCompliance } = require('./templates/compliance');
const { applyRemediationMetadata } = require('./templates/remediation');
const { generateTerraform } = require('./templates/terraform');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 30
});

app.use('/api', apiLimiter);

// In-memory databases
const scanCache = new Map();
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
    roleArn: awsConnection.roleArn,
    cachedScans: scanCache.size,
    cachedZones: cfConnection.zoneMap.size
  });
});

// Route: Connect to AWS API (Supports IAM Role ARN AssumeRole or Access Keys)
app.post('/api/connect-aws', async (req, res) => {
  const { roleArn, accessKeyId, secretAccessKey, region, sessionToken } = req.body;
  const awsRegion = region || 'us-east-1';

  if (!roleArn && (!accessKeyId || !secretAccessKey)) {
    return res.status(400).json({ error: 'Provide either an IAM Role ARN or Access Key ID & Secret Access Key.' });
  }

  try {
    let keyId = accessKeyId;
    let secKey = secretAccessKey;
    let sToken = sessionToken || null;

    if (roleArn) {
      const baseConnector = new AWSConnector(keyId || 'dummyKey', secKey || 'dummySecret', awsRegion, sToken);
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
    awsConnection.distributionMap.clear();

    const message = roleArn
      ? `Successfully assumed IAM Role (${roleArn}) and connected to AWS!`
      : 'Connected to AWS successfully!';

    return res.json({ success: true, message });
  } catch (err) {
    return res.status(500).json({ error: `Connection failed: ${err.message}` });
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

  const scanId = 'scan_' + Date.now();
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

    const enriched = applyRemediationMetadata(applyCompliance(findings), domain);

    const scanResult = {
      scanId,
      target: domain,
      scanTime: startTime.toISOString(),
      infraType,
      findings: enriched
    };

    scanCache.set(scanId, scanResult);
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

  const scan = scanCache.get(scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan session not found' });
  }

  const finding = scan.findings.find(f => f.id === findingId);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found in this scan session' });
  }

  if (!finding.fix) {
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

  const scan = scanCache.get(scanId);
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
    const targetProvider = provider || (awsConnection.connected && !cfConnection.connected ? 'aws' : 'cloudflare');

    if (finding.fix.type === 'dns' || finding.fix.type === 'dns-update' || finding.fix.type === 'dns-delete') {
      if ((targetProvider === 'cloudflare' || targetProvider === 'both') && cfConnection.connected) {
        const connector = new cloudflareConnector(cfConnection.token);
        let zoneId = cfConnection.zoneMap.get(scan.target);
        if (!zoneId) {
          zoneId = await connector.getZoneId(scan.target);
          cfConnection.zoneMap.set(scan.target, zoneId);
        }
        remediationResult = await dnsRemediator.applyFix(connector, zoneId, scan.target, finding);
      }
      
      if ((targetProvider === 'aws' || targetProvider === 'both' || !remediationResult) && awsConnection.connected) {
        const awsConn = new AWSConnector(awsConnection.accessKeyId, awsConnection.secretAccessKey, awsConnection.region, awsConnection.sessionToken);
        const awsResult = await route53Remediator.applyFix(awsConn, scan.target, finding);
        if (remediationResult && awsResult.success) {
          remediationResult.verification += ` | AWS Route 53 DNS record updated.`;
        } else {
          remediationResult = awsResult;
        }
      }
    } else if (finding.fix.type === 'cloudflare-rule') {
      if ((targetProvider === 'cloudflare' || targetProvider === 'both') && cfConnection.connected) {
        const connector = new cloudflareConnector(cfConnection.token);
        let zoneId = cfConnection.zoneMap.get(scan.target);
        if (!zoneId) {
          zoneId = await connector.getZoneId(scan.target);
          cfConnection.zoneMap.set(scan.target, zoneId);
        }
        remediationResult = await headerRemediator.applyFix(connector, zoneId, scan.target, finding);
      }

      if ((targetProvider === 'aws' || targetProvider === 'both' || !remediationResult) && awsConnection.connected) {
        const awsConn = new AWSConnector(awsConnection.accessKeyId, awsConnection.secretAccessKey, awsConnection.region, awsConnection.sessionToken);
        const awsResult = await cloudfrontRemediator.applyFix(awsConn, scan.target, finding);
        if (remediationResult && awsResult.success) {
          remediationResult.verification += ` | ${awsResult.verification}`;
        } else {
          remediationResult = awsResult;
        }
      }
    } else {
      return res.status(400).json({ error: `Fix type '${finding.fix.type}' is not auto-remediable.` });
    }

    if (remediationResult && remediationResult.success) {
      // Update finding status to PASS
      scan.findings[findingIndex].status = 'PASS';
      scan.findings[findingIndex].severity = 'PASS';
      scan.findings[findingIndex].remediationDetails = remediationResult;
      
      // Update scanCache
      scanCache.set(scanId, scan);
      return res.json({ success: true, finding: scan.findings[findingIndex] });
    } else {
      return res.status(500).json({ error: remediationResult ? remediationResult.error : 'Unknown error during remediation' });
    }
  } catch (err) {
    return res.status(500).json({ error: `Remediation execution failed: ${err.message}` });
  }
});

// Route: Generate HTML Report
app.get('/api/report/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = scanCache.get(scanId);
  if (!scan) {
    return res.status(404).send('<h1>Report Not Found</h1><p>Please run a scan first.</p>');
  }

  const html = reportBuilder.generateReport(scan);
  res.setHeader('Content-Type', 'text/html');
  return res.send(html);
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
        id: 'xframe-present',
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

  scanCache.set(scanId, demoData);
  return res.json(demoData);
});

app.listen(PORT, () => {
  console.log(`AutoRemediate API server running at http://localhost:${PORT}`);
});
