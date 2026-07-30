// Scan history panel — lists past scans from SQLite and links to their reports.
(function () {
  const btn = document.getElementById('btn-history');
  if (!btn) return;

  let modal = null;

  function buildModal() {
    modal = document.createElement('div');
    modal.className = 'modal hidden';
    modal.id = 'history-modal';
    const content = document.createElement('div');
    content.className = 'modal-content glass-card';
    content.style.width = '550px';

    const h2 = document.createElement('h2');
    h2.textContent = 'Scan History';
    const list = document.createElement('div');
    list.id = 'history-list';
    list.style.maxHeight = '400px';
    list.style.overflowY = 'auto';
    const actions = document.createElement('div');
    actions.className = 'modal-actions';
    const close = document.createElement('button');
    close.className = 'btn-ghost';
    close.textContent = 'Close';
    close.addEventListener('click', () => modal.classList.add('hidden'));

    actions.appendChild(close);
    content.appendChild(h2);
    content.appendChild(list);
    content.appendChild(actions);
    modal.appendChild(content);
    document.body.appendChild(modal);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.add('hidden');
    });
  }

  function renderRow(list, scan) {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:12px 4px;border-bottom:1px solid var(--border-color);gap:10px;';

    const info = document.createElement('div');
    const target = document.createElement('div');
    target.style.fontWeight = '700';
    target.textContent = scan.target;
    const meta = document.createElement('div');
    meta.style.cssText = 'font-size:12px;color:var(--text-muted);';
    const c = scan.counts || {};
    meta.textContent = `${new Date(scan.at).toLocaleString()} — ${scan.infra || 'unknown'} — ` +
      `${c.critical || 0} critical, ${c.high || 0} high, ${c.moderate || 0} moderate, ${c.pass || 0} pass`;
    info.appendChild(target);
    info.appendChild(meta);

    const link = document.createElement('a');
    link.className = 'btn-action btn-view-fix';
    link.style.textDecoration = 'none';
    link.textContent = 'View Report';
    link.href = `/api/report/${encodeURIComponent(scan.id)}`;
    link.target = '_blank';

    row.appendChild(info);
    row.appendChild(link);
    list.appendChild(row);
  }

  btn.addEventListener('click', async () => {
    if (!modal) buildModal();
    const list = modal.querySelector('#history-list');
    list.textContent = 'Loading...';
    modal.classList.remove('hidden');
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      list.textContent = '';
      if (!data.scans || data.scans.length === 0) {
        list.textContent = 'No scans recorded yet.';
        return;
      }
      data.scans.forEach(scan => renderRow(list, scan));
    } catch (err) {
      list.textContent = 'Could not load history (server running an older version?).';
    }
  });
})();
