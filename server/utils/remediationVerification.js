function isRemediationVerified(result) {
  if (!result || result.success !== true) return false;
  if (typeof result.verified === 'boolean') return result.verified;

  const verification = String(result.verification || '').trim();
  return /^verified\b/i.test(verification) && !/\bpending\b/i.test(verification);
}

module.exports = { isRemediationVerified };
