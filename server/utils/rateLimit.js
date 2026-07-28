function createRateLimiter({ windowMs, maxRequests }) {
  const clients = new Map();
  let lastSweep = Date.now();

  return function rateLimit(req, res, next) {
    const now = Date.now();

    // Periodically purge expired entries so the Map cannot grow unbounded
    if (now - lastSweep >= windowMs) {
      lastSweep = now;
      for (const [key, entry] of clients) {
        if (entry.resetAt <= now) {
          clients.delete(key);
        }
      }
    }

    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const current = clients.get(key);

    if (!current || current.resetAt <= now) {
      clients.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    current.count += 1;
    if (current.count > maxRequests) {
      const retryAfter = Math.ceil((current.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter.toString());
      return res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
    }

    return next();
  };
}

module.exports = { createRateLimiter };
