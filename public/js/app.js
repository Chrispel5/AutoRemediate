// Main Controller
document.addEventListener('DOMContentLoaded', () => {
  const btnSettings = document.getElementById('btn-settings');
  const btnCloseSettings = document.getElementById('btn-close-settings');
  const settingsModal = document.getElementById('settings-modal');
  const btnConnect = document.getElementById('btn-connect');
  const cfTokenInput = document.getElementById('cf-token');
  const cloudflareStatus = document.getElementById('cloudflare-status');
  
  const btnScan = document.getElementById('btn-scan');
  const targetInput = document.getElementById('target-input');
  
  const btnDemo = document.getElementById('btn-demo');
  const btnExport = document.getElementById('btn-export');

  let currentScanData = null;
  let isCloudflareConnected = false;

  // Set default targets
  targetInput.value = 'topnotchguides.com.ng';

  // Toggle Settings Modal
  btnSettings.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
  });

  btnCloseSettings.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
  });

  // Handle Cloudflare connection verification
  btnConnect.addEventListener('click', async () => {
    const token = cfTokenInput.value.trim();
    if (!token) {
      alert('Please enter a Cloudflare API token.');
      return;
    }

    btnConnect.disabled = true;
    btnConnect.textContent = 'Connecting...';

    try {
      const response = await fetch('/api/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiToken: token })
      });

      const data = await response.json();
      if (response.ok && data.success) {
        isCloudflareConnected = true;
        cloudflareStatus.textContent = 'Cloudflare: Connected';
        cloudflareStatus.classList.remove('disconnected');
        cloudflareStatus.classList.add('connected');
        settingsModal.classList.add('hidden');
        alert('Connected to Cloudflare successfully!');
        
        // Notify dashboard and remediation components
        window.isCloudflareConnected = true;
        if (currentScanData) {
          window.dashboard.renderFindings(currentScanData.findings, currentScanData.scanId);
        }
      } else {
        alert(`Connection Failed: ${data.error}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    } finally {
      btnConnect.disabled = false;
      btnConnect.textContent = 'Connect';
    }
  });

  // Handle Scanning Target
  btnScan.addEventListener('click', async () => {
    const target = targetInput.value.trim();
    if (!target) {
      alert('Please enter a target domain.');
      return;
    }

    btnScan.disabled = true;
    btnScan.textContent = 'Scanning...';
    
    // Reset view panels
    document.getElementById('scan-progress').classList.remove('hidden');
    document.getElementById('infra-panel').classList.add('hidden');
    document.getElementById('findings-section').classList.add('hidden');
    document.getElementById('report-section').classList.add('hidden');

    window.scanner.initGrid();

    try {
      // Simulate real scanning phase transitions
      await window.scanner.runVisualPipeline();

      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Scan failed');
      }

      currentScanData = await response.json();
      
      // Update UI panels
      document.getElementById('scan-progress').classList.add('hidden');
      document.getElementById('infra-panel').classList.remove('hidden');
      document.getElementById('findings-section').classList.remove('hidden');
      document.getElementById('report-section').classList.remove('hidden');

      // Populate dashboard details
      window.dashboard.renderInfra(currentScanData.infraType, currentScanData.target);
      window.dashboard.renderFindings(currentScanData.findings, currentScanData.scanId);

    } catch (err) {
      alert(`Scan failed: ${err.message}`);
      document.getElementById('scan-progress').classList.add('hidden');
    } finally {
      btnScan.disabled = false;
      btnScan.innerHTML = '<span class="btn-scan-text">Scan Target</span><span class="btn-scan-icon">→</span>';
    }
  });

  // Handle Demo Mode data
  btnDemo.addEventListener('click', async () => {
    // Reset views
    document.getElementById('scan-progress').classList.remove('hidden');
    document.getElementById('infra-panel').classList.add('hidden');
    document.getElementById('findings-section').classList.add('hidden');
    document.getElementById('report-section').classList.add('hidden');

    window.scanner.initGrid();
    btnDemo.disabled = true;

    try {
      await window.scanner.runVisualPipeline();

      const response = await fetch('/api/demo');
      currentScanData = await response.json();

      document.getElementById('scan-progress').classList.add('hidden');
      document.getElementById('infra-panel').classList.remove('hidden');
      document.getElementById('findings-section').classList.remove('hidden');
      document.getElementById('report-section').classList.remove('hidden');

      // Populate details
      window.dashboard.renderInfra(currentScanData.infraType, currentScanData.target);
      window.dashboard.renderFindings(currentScanData.findings, currentScanData.scanId);

    } catch (err) {
      alert(`Failed to load demo: ${err.message}`);
    } finally {
      btnDemo.disabled = false;
    }
  });

  // Handle Export HTML Report
  btnExport.addEventListener('click', () => {
    if (!currentScanData) return;
    window.report.export(currentScanData.scanId);
  });
});
