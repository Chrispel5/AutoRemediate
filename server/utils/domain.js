const net = require('net');

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function normalizeDomain(input) {
  if (typeof input !== 'string') {
    throw new Error('Target domain is required');
  }

  let value = input.trim().toLowerCase();
  if (!value) {
    throw new Error('Target domain is required');
  }

  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  value = value.split(/[/?#]/)[0];
  value = value.replace(/\.$/, '');

  if (value.includes('@')) {
    throw new Error('Enter a domain name without credentials or user info');
  }

  if (value.startsWith('[') && value.endsWith(']')) {
    throw new Error('IP addresses are not supported as scan targets');
  }

  let host = value.split(':')[0];
  if (host.startsWith('www.')) {
    host = host.slice(4);
  }

  if (!isValidDomain(host)) {
    throw new Error('Enter a valid domain name, for example example.com');
  }

  return host;
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253 || net.isIP(domain)) {
    return false;
  }

  const labels = domain.split('.');
  if (labels.length < 2) {
    return false;
  }

  return labels.every(label => DOMAIN_LABEL.test(label));
}

function isRecordNameAllowed(recordName, baseDomain) {
  if (typeof recordName !== 'string') {
    return false;
  }

  const normalizedRecord = recordName.trim().toLowerCase().replace(/\.$/, '');
  const normalizedBase = baseDomain.trim().toLowerCase().replace(/\.$/, '');
  return normalizedRecord === normalizedBase || normalizedRecord.endsWith(`.${normalizedBase}`);
}

module.exports = {
  normalizeDomain,
  isRecordNameAllowed
};
