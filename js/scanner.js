// Scan Grid manager
window.scanner = (() => {
  const MODULES = [
    { key: 'dns', name: 'DNS Records Audit' },
    { key: 'headers', name: 'HTTP Header Analyzer' },
    { key: 'tls', name: 'TLS/SSL cert check' },
    { key: 'software', name: 'Software Fingerprinting' },
    { key: 'errors', name: 'Error Disclosure probe' },
    { key: 'cookies', name: 'Cookie Security flags' },
    { key: 'subdomains', name: 'Subdomain Takeover audit' }
  ];

  const sleep = ms => new Promise(res => setTimeout(res, ms));

  function initGrid() {
    const grid = document.getElementById('scanner-grid');
    grid.innerHTML = '';

    MODULES.forEach(mod => {
      const card = document.createElement('div');
      card.className = 'scanner-card idle';
      card.id = `scanner-${mod.key}`;
      card.innerHTML = `
        <div class="scanner-card-name">${mod.name}</div>
        <div class="scanner-card-status">Waiting</div>
      `;
      grid.appendChild(card);
    });
  }

  async function runVisualPipeline() {
    for (const mod of MODULES) {
      const card = document.getElementById(`scanner-${mod.key}`);
      if (card) {
        card.className = 'scanner-card scanning';
        card.querySelector('.scanner-card-status').textContent = 'Analyzing...';
        // Add a small visual stagger delay for cybersecurity feeling
        await sleep(350);
      }
    }
  }

  function finishGrid() {
    // Sweep cards whose scanner produced no finding out of the scanning state
    document.querySelectorAll('.scanner-card.scanning').forEach(card => {
      card.className = 'scanner-card idle';
      card.querySelector('.scanner-card-status').textContent = 'No Data';
    });
  }

  return {
    initGrid,
    runVisualPipeline,
    finishGrid
  };
})();
