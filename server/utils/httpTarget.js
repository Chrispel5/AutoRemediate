const fetch = require('node-fetch');

async function fetchWithinOrigin(url, options = {}, maxRedirects = 3) {
  const initialOrigin = new URL(url).origin;
  let currentUrl = url;

  for (let redirects = 0; redirects <= maxRedirects; redirects++) {
    const response = await fetch(currentUrl, {
      ...options,
      redirect: 'manual'
    });
    const location = response.headers.get('location');
    const isRedirect = response.status >= 300 && response.status < 400 && location;

    if (!isRedirect) {
      return { response, url: currentUrl, externalRedirect: null };
    }

    const nextUrl = new URL(location, currentUrl);
    if (nextUrl.origin !== initialOrigin) {
      return {
        response,
        url: currentUrl,
        externalRedirect: nextUrl.origin
      };
    }

    currentUrl = nextUrl.toString();
  }

  throw new Error(`Too many same-origin redirects while requesting ${initialOrigin}`);
}

module.exports = { fetchWithinOrigin };
