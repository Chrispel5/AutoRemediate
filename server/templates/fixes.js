module.exports = {
  'csp-missing': {
    apache: {
      description: 'Add Content-Security-Policy header via Apache config site file.',
      file: '/etc/apache2/sites-enabled/your-site.conf',
      code: `<LocationMatch "^/">
    Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
</LocationMatch>`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: {
      description: 'Add Content-Security-Policy header inside server block of Nginx site block.',
      file: '/etc/nginx/sites-enabled/your-site',
      code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;`,
      postAction: 'sudo systemctl restart nginx'
    },
    cloudflare: {
      description: 'Inject Content-Security-Policy header using Cloudflare Transform Rules.',
      method: 'API / Transform Rules',
      code: 'Cloudflare Transform Rule → Modify Response Header → Set Content-Security-Policy'
    },
    s3: {
      description: 'Set Content-Security-Policy via S3 metadata values or CloudFront custom headers policy.',
      method: 'AWS CloudFront CLI / Console',
      code: 'aws cloudfront create-response-headers-policy --response-headers-policy-config ...'
    }
  },
  'server-version-exposed': {
    apache: {
      description: 'Disable detailed server tokens and signatures in Apache global conf.',
      file: '/etc/apache2/conf-enabled/security.conf',
      code: `ServerTokens Prod\nServerSignature Off`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: {
      description: 'Set server_tokens option to off in Nginx global settings.',
      file: '/etc/nginx/nginx.conf',
      code: `server_tokens off;`,
      postAction: 'sudo systemctl restart nginx'
    },
    s3: { description: 'N/A — Amazon S3 does not disclose detailed operating system or server build numbers.', skip: true },
    cloudflare: { description: 'N/A — Cloudflare handles edge traffic hiding internal server structures.', skip: true }
  },
  'dmarc-missing': {
    all: {
      description: 'Publish DMARC record to prevent email spoofing attacks.',
      record: '_dmarc.{domain} TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain};"'
    }
  },
  'spf-softfail': {
    all: {
      description: 'Transition SPF mechanism from soft fail (~all) to hard fail (-all) to reject unauthorized mail.',
      note: 'Edit the published SPF TXT record and replace "~all" with "-all"'
    }
  },
  'error-disclosure': {
    apache: {
      description: 'Anonymize PHP logs and disable display of backend runtime errors.',
      file: 'php.ini',
      code: `display_errors = Off\nlog_errors = On\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT`
    },
    nginx: {
      description: 'Turn off display_errors option in php-fpm pool parameters.',
      file: 'php-fpm.conf',
      code: `php_flag[display_errors] = off`
    },
    s3: { description: 'N/A — Static websites run without server-side application engines.', skip: true }
  },
  'hsts-missing': {
    apache: {
      description: 'Add Strict-Transport-Security header for domain HTTPS security.',
      file: '/etc/apache2/sites-enabled/your-site.conf',
      code: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: {
      description: 'Add HTTP Strict-Transport-Security header in Nginx configurations.',
      file: '/etc/nginx/sites-enabled/your-site',
      code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
      postAction: 'sudo systemctl restart nginx'
    },
    cloudflare: { description: 'Enable HSTS in Cloudflare under SSL/TLS → Edge Certificates → HTTP Strict Transport Security.', method: 'Cloudflare Dashboard' }
  },
  'xframe-missing': {
    apache: { 
      description: 'Set X-Frame-Options to deny framing layout rendering.',
      code: `Header always set X-Frame-Options "DENY"`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: { 
      description: 'Add X-Frame-Options DENY rule inside site block.',
      code: `add_header X-Frame-Options "DENY" always;`,
      postAction: 'sudo systemctl restart nginx'
    },
    cloudflare: { description: 'Add custom response header transform rule to set X-Frame-Options: DENY.', method: 'Cloudflare Rules API' }
  },
  'xcto-missing': {
    apache: { 
      description: 'Enforce X-Content-Type-Options nosniff header values.',
      code: `Header always set X-Content-Type-Options "nosniff"`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: { 
      description: 'Configure nosniff content headers in Nginx configuration.',
      code: `add_header X-Content-Type-Options "nosniff" always;`,
      postAction: 'sudo systemctl restart nginx'
    },
    cloudflare: { description: 'Define X-Content-Type-Options: nosniff via Response Headers Rules.', method: 'Cloudflare Rules API' }
  },
  'cookie-insecure': {
    apache: {
      description: 'Inject security attributes HttpOnly, Secure, and SameSite on cookie transmissions.',
      code: `Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: {
      description: 'Enable secure cookie rewrite mapping in proxy modules.',
      code: `proxy_cookie_flags ~ secure httponly samesite=strict;`
    }
  },
  'xpoweredby-exposed': {
    apache: {
      description: 'Turn off expose_php in PHP configurations to hide compilation flags.',
      file: '/etc/php/8.x/apache2/php.ini',
      code: `expose_php = Off`,
      postAction: 'sudo systemctl restart apache2'
    },
    nginx: {
      description: 'Add hide headers directive inside Nginx configuration files.',
      code: `proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;`,
      postAction: 'sudo systemctl restart nginx'
    }
  }
};
