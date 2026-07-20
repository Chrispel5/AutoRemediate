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
      const cipher = socket.getCipher();

      if (daysRemaining <= 0) {
        resolve({
          id: 'tls-expired',
          name: 'TLS Certificate Expired',
          severity: 'CRITICAL',
          status: 'FAIL',
          evidence: `Expired on: ${cert.valid_to} (${Math.abs(daysRemaining)} days ago)`,
          description: 'The SSL/TLS certificate has expired, displaying standard security warning pages to web visitors.'
        });
      } else if (daysRemaining < 30) {
        resolve({
          id: 'tls-warn',
          name: 'TLS Certificate Near Expiry',
          severity: 'WARN',
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
