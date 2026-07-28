// Report exporter module
window.report = (() => {
  function exportReport(scanId, scanData) {
    if (!scanId) {
      alert('Please run a target scan or toggle demo mode first.');
      return;
    }

    const isStaticEnv = window.location.hostname.includes('github.io') || window.location.protocol === 'file:';
    const isLocalScan = window.scanIsLocal || (typeof scanId === 'string' && scanId.indexOf('scan_local_') === 0);

    if ((isStaticEnv || isLocalScan) && scanData) {
      // Generate the report client-side for static hosting or backend-unknown local scans
      const reportHtml = generateClientReport(scanData);
      const reportWindow = window.open('', '_blank');
      if (reportWindow) {
        reportWindow.document.write(reportHtml);
        reportWindow.document.close();
      } else {
        alert('Pop-up blocked! Please allow pop-ups to view the report.');
      }
    } else if (!isStaticEnv && !isLocalScan) {
      // Open the backend report print window in a new tab
      window.open(`/api/report/${scanId}`, '_blank');
    } else {
      alert('Report data unavailable for this scan. Please run the scan again.');
    }
  }

  function generateClientReport(scan) {
    const { target, scanTime, infraType, findings } = scan;
    
    let criticalCount = 0;
    let highCount = 0;
    let moderateCount = 0;
    let lowCount = 0;
    let passCount = 0;

    findings.forEach(f => {
      if (f.status === 'PASS') {
        passCount++;
      } else {
        switch (f.severity) {
          case 'CRITICAL': criticalCount++; break;
          case 'HIGH': highCount++; break;
          case 'MODERATE': moderateCount++; break;
          case 'LOW': lowCount++; break;
        }
      }
    });

    const findingsRows = findings.map(f => {
      let severityClass = f.severity.toLowerCase();
      if (f.status === 'PASS') severityClass = 'pass';

      const statusBadge = f.status === 'PASS' 
        ? '<span class="status-badge pass">FIXED / PASS</span>' 
        : '<span class="status-badge fail">VULNERABLE</span>';

      const remediationText = f.remediationDetails 
        ? `<div class="remediation-proof"><strong>Auto-Fixed:</strong> ${escapeHtml(f.remediationDetails.verification)}</div>`
        : '';

      return `
        <tr class="finding-row ${severityClass}">
          <td><span class="severity-tag ${severityClass}">${f.status === 'PASS' ? 'PASS' : f.severity}</span></td>
          <td>
            <div class="finding-name">${escapeHtml(f.name)}</div>
            <div class="finding-desc">${escapeHtml(f.description || '')}</div>
            ${remediationText}
          </td>
          <td>
            <pre class="evidence-block"><code>${escapeHtml(f.evidence)}</code></pre>
          </td>
          <td>${statusBadge}</td>
        </tr>
      `;
    }).join('');

    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AutoRemediate Report — ${escapeHtml(target)}</title>
        <style>
          body {
            background-color: #0a0e1a;
            color: #f1f5f9;
            font-family: 'Inter', -apple-system, sans-serif;
            margin: 0;
            padding: 40px 20px;
          }
          .container {
            max-width: 1100px;
            margin: 0 auto;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
          }
          header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 20px;
            margin-bottom: 30px;
          }
          h1 {
            margin: 0;
            font-size: 28px;
            color: #00d4ff;
          }
          .meta-info {
            font-size: 14px;
            color: #94a3b8;
            line-height: 1.6;
          }
          .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 40px;
          }
          .stat-card {
            background: rgba(30, 41, 59, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
          }
          .stat-value {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 5px;
          }
          .stat-label {
            font-size: 12px;
            color: #94a3b8;
            text-transform: uppercase;
          }
          .critical .stat-value { color: #ff4757; text-shadow: 0 0 10px rgba(255, 71, 87, 0.2); }
          .high .stat-value { color: #ff6b35; }
          .moderate .stat-value { color: #ffa502; }
          .low .stat-value { color: #5f9cf7; }
          .pass .stat-value { color: #2ed573; }
          
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
          }
          th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          }
          th {
            background-color: rgba(30, 41, 59, 0.6);
            color: #e2e8f0;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
          }
          .finding-name {
            font-weight: 600;
            font-size: 15px;
            margin-bottom: 6px;
          }
          .finding-desc {
            font-size: 13px;
            color: #94a3b8;
            line-height: 1.4;
          }
          .evidence-block {
            background: #0d1117;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 6px;
            padding: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            max-height: 120px;
            overflow-y: auto;
            white-space: pre-wrap;
            margin: 0;
            color: #c9d1d9;
          }
          .status-badge {
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 4px;
            text-transform: uppercase;
          }
          .status-badge.pass {
            background: rgba(46, 213, 115, 0.15);
            color: #2ed573;
            border: 1px solid rgba(46, 213, 115, 0.3);
          }
          .status-badge.fail {
            background: rgba(255, 71, 87, 0.15);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
          }
          .severity-tag {
            font-size: 11px;
            font-weight: 700;
            padding: 3px 6px;
            border-radius: 3px;
            text-transform: uppercase;
          }
          .severity-tag.critical { background: #ff4757; color: white; }
          .severity-tag.high { background: #ff6b35; color: white; }
          .severity-tag.moderate { background: #ffa502; color: black; }
          .severity-tag.low { background: #5f9cf7; color: white; }
          .severity-tag.pass { background: #2ed573; color: white; }

          .remediation-proof {
            margin-top: 10px;
            padding: 8px;
            background: rgba(46, 213, 115, 0.08);
            border-left: 3px solid #2ed573;
            border-radius: 0 4px 4px 0;
            font-size: 12px;
            color: #a8e6cf;
          }
          
          .print-btn {
            background-color: #00d4ff;
            color: #0a0e1a;
            border: none;
            padding: 12px 24px;
            font-weight: 700;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
          }
          .print-btn:hover {
            background-color: #00b0d9;
          }

          @media print {
            body {
              background-color: #ffffff;
              color: #000000;
              padding: 0;
            }
            .container {
              border: none;
              box-shadow: none;
              padding: 0;
              max-width: 100%;
            }
            .print-btn { display: none; }
            .stat-card {
              border: 1px solid #ddd;
            }
            th {
              background-color: #f1f5f9;
              color: #000;
            }
            .evidence-block {
              background: #f8fafc;
              color: #000;
              border: 1px solid #ddd;
            }
            h1 { color: #000; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <header>
            <div>
              <h1>AutoRemediate Security Assessment</h1>
              <div class="meta-info">
                Target Host: <strong>${escapeHtml(target)}</strong><br>
                Generated On: ${new Date(scanTime).toLocaleString()}<br>
                Detected Environment: <span style="text-transform: uppercase;">${escapeHtml(infraType)}</span>
              </div>
            </div>
            <div>
              <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
            </div>
          </header>

          <div class="stats-grid">
            <div class="stat-card critical">
              <div class="stat-value">${criticalCount}</div>
              <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
              <div class="stat-value">${highCount}</div>
              <div class="stat-label">High</div>
            </div>
            <div class="stat-card moderate">
              <div class="stat-value">${moderateCount}</div>
              <div class="stat-label">Moderate</div>
            </div>
            <div class="stat-card low">
              <div class="stat-value">${lowCount}</div>
              <div class="stat-label">Low</div>
            </div>
            <div class="stat-card pass">
              <div class="stat-value">${passCount}</div>
              <div class="stat-label">Passed / Fixed</div>
            </div>
          </div>

          <h2>Audit Findings</h2>
          <table>
            <thead>
              <tr>
                <th style="width: 10%">Severity</th>
                <th style="width: 45%">Vulnerability Description</th>
                <th style="width: 35%">Evidence</th>
                <th style="width: 10%">Status</th>
              </tr>
            </thead>
            <tbody>
              ${findingsRows}
            </tbody>
          </table>
        </div>
      </body>
      </html>
    `;
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  return {
    export: exportReport
  };
})();
