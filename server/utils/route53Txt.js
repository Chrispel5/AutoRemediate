// Route 53 TXT values must be enclosed in literal double quotes, and any
// chunk longer than 255 characters must be split into multiple quoted chunks.
function quoteRoute53Txt(value) {
  const chunks = [];
  for (let i = 0; i < value.length; i += 255) {
    chunks.push(value.slice(i, i + 255));
  }
  return chunks.map(c => `"${c}"`).join(' ');
}

// Strip the Route 53 quoting from a stored TXT value to get the plain content.
// e.g. `"v=spf1 a" "bc"` -> `v=spf1 abc`
function unquoteRoute53Txt(raw) {
  return raw.replace(/"\s*"/g, '').replace(/^"|"$/g, '').trim();
}

module.exports = { quoteRoute53Txt, unquoteRoute53Txt };
