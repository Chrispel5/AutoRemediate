const tls = require('tls');

function inspect(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false, // Avoid throwing on self-signed during scan
      timeout: 8000
    }, () => {
      const cert = socket.getPeerCertificate();
      
      if (!cert || Object.keys(cert).length === 0) {
        resolve({
          id: 'tls-missing',
          name: 'TLS Certificate Inspection Failure',
          severity: 'HIGH',
          status: 'FAIL',
          evidence: 'No peer certificate returned',
          description: 'Could not fetch a valid TLS certificate from this endpoint. Traffic may be unencrypted or blocked.'
        });
        socket.destroy();
        return;
      }

      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const timeDiff = validTo - now;
      const daysRemaining = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
      
      const protocol = socket.getProtocol();

      // We connect with rejectUnauthorized:false so bad certificates can be
      // classified instead of throwing — which means hostname and validity
      // window must be checked manually before anything is reported as PASS.
      const apex = domain.replace(/^www\./, '');
      const altNames = (cert.subjectaltname || '')
        .split(',')
        .map(s => s.trim().replace(/^DNS:/i, '').toLowerCase())
        .filter(Boolean);
      const certCN = (cert.subject && cert.subject.CN ? cert.subject.CN : '').toLowerCase();
      const target = domain.toLowerCase();
      const wildcardCovers = (name) => name.startsWith('*.') && target.endsWith(name.slice(1)) &&
        target.split('.').length === name.split('.').length;
      const hostnameValid = altNames.some(n => n === target || wildcardCovers(n)) ||
        certCN === target || (certCN.startsWith('*.') && wildcardCovers(certCN)) ||
        altNames.includes(apex);
      const notYetValid = new Date(cert.valid_from) > now;

      if (daysRemaining <= 0) {
        resolve({
          id: 'tls-expired',
          name: 'TLS Certificate Expired',
          severity: 'CRITICAL',
          status: 'FAIL',
          evidence: `Expired on: ${cert.valid_to} (${Math.abs(daysRemaining)} days ago)`,
          description: 'The SSL/TLS certificate has expired, displaying standard security warning pages to web visitors.'
        });
      } else if (!hostnameValid) {
        resolve({
          id: 'tls-hostname-mismatch',
          name: 'TLS Certificate Not Valid for This Hostname',
          severity: 'HIGH',
          status: 'FAIL',
          evidence: `Certificate covers: ${altNames.join(', ') || certCN || 'unknown'} — requested hostname: ${domain}`,
          description: 'The presented certificate does not cover this hostname (subjectAltName mismatch), so browsers will reject it with a security warning.'
        });
      } else if (notYetValid) {
        resolve({
          id: 'tls-not-yet-valid',
          name: 'TLS Certificate Not Yet Valid',
          severity: 'HIGH',
          status: 'FAIL',
          evidence: `Certificate valid from: ${cert.valid_from}`,
          description: 'The certificate start date is in the future, so browsers will treat it as invalid.'
        });
      } else if (socket.authorized === false) {
        resolve({
          id: 'tls-untrusted',
          name: 'TLS Certificate Not Trusted',
          severity: 'HIGH',
          status: 'FAIL',
          evidence: `Chain validation failed: ${socket.authorizationError || 'unknown error'}`,
          description: 'The certificate is self-signed or issued by an untrusted CA. Browsers will show a full-page certificate warning.'
        });
      } else if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        resolve({
          id: 'tls-old-protocol',
          name: 'Deprecated TLS Protocol Negotiated',
          severity: 'MODERATE',
          status: 'FAIL',
          evidence: `Negotiated protocol: ${protocol}`,
          description: 'TLS 1.0/1.1 are deprecated and rejected by modern browsers and PCI DSS. Enable TLS 1.2 and 1.3 only.'
        });
      } else if (daysRemaining < 30) {
        resolve({
          id: 'tls-warn',
          name: 'TLS Certificate Near Expiry',
          severity: 'MODERATE',
          status: 'FAIL',
          evidence: `Expires on: ${cert.valid_to} (${daysRemaining} days remaining)`,
          description: 'The certificate expires in less than 30 days. Renew immediately to prevent visitor service warnings.'
        });
      } else {
        resolve({
          id: 'tls-valid',
          name: 'TLS Certificate Valid',
          severity: 'PASS',
          status: 'PASS',
          evidence: `Issuer: ${cert.issuer.CN || cert.issuer.O || 'Unknown'}, Expires: ${cert.valid_to} (${daysRemaining} days remaining), Protocol: ${protocol}`,
          description: 'Valid, active SSL/TLS configuration encrypting web traffic.'
        });
      }

      socket.destroy();
    });

    socket.on('error', (err) => {
      resolve({
        id: 'tls-missing',
        name: 'TLS Certificate Inspection Failure',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: `Connection error: ${err.message}`,
        description: 'Failed to establish a TLS handshake. Port 443 might be closed or blocked by firewall security.'
      });
      socket.destroy();
    });

    socket.on('timeout', () => {
      resolve({
        id: 'tls-missing',
        name: 'TLS Certificate Inspection Timeout',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: 'Handshake timed out after 8 seconds',
        description: 'Connection timed out trying to fetch TLS handshake parameters.'
      });
      socket.destroy();
    });
  });
}

module.exports = { inspect };
