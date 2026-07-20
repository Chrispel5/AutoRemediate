// Report exporter module
window.report = (() => {
  function exportReport(scanId) {
    if (!scanId) {
      alert('Please run a target scan or toggle demo mode first.');
      return;
    }
    
    // Open the report print window in a new tab
    window.open(`/api/report/${scanId}`, '_blank');
  }

  return {
    export: exportReport
  };
})();
