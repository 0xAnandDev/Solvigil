import { renderResults } from './results.js';
export function initAnalyzer() {
  const btnAnalyze = document.getElementById('btn-analyze');
  const uploadSection = document.getElementById('upload-section');
  const processingSection = document.getElementById('processing-section');
  const resultsSection = document.getElementById('results-section');
  
  const progressFill = document.getElementById('progress-fill');
  const processingSteps = document.getElementById('processing-steps');
  
  const stepsText = [
    'Parsing code structure',
    'Generating Abstract Syntax Tree',
    'Running vulnerability detection rules',
    'Simulating execution paths',
    'Generating security insights'
  ];
  
  btnAnalyze.addEventListener('click', async () => {
    if (window.hasAcceptedTerms && !window.hasAcceptedTerms()) {
      if (window.showToast) window.showToast('Please accept terms & conditions first', 'error');
      else alert('Please accept terms & conditions first');
      return;
    }

    if (!window.currentUploadedFileContent) {
      if (window.showToast) window.showToast('Please select a file first', 'error');
      else alert('Please select a file first');
      return;
    }

    btnAnalyze.disabled = true;

    // Show loading section
    uploadSection.style.display = 'none';
    processingSection.style.display = 'flex';
    resultsSection.style.display = 'none';

    try {
      let result;
      try {
        // ALWAYS use the real backend
        const formData = new FormData();
        if (window.currentUploadedFile) {
          formData.append('file', window.currentUploadedFile);
        } else {
          const blob = new Blob([window.currentUploadedFileContent], { type: 'text/plain' });
          formData.append('file', blob, 'contract.sol');
        }

        const response = await fetch('http://localhost:5000/api/analyze', {
          method: 'POST',
          body: formData
        });

        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${await response.text()}`);
        }

        const responseJson = await response.json();
        const analysisData = responseJson.analysis ? responseJson.analysis : responseJson;
        result = { success: true, data: analysisData };
      } catch (err) {
        console.error('Backend failed:', err);
        result = { success: false, error: err.message || 'Server error' };
      }

      if (!result.success) {
        if (window.showToast) window.showToast('Analysis failed: ' + result.error, 'error');
        processingSection.style.display = 'none';
        uploadSection.style.display = 'block';
        btnAnalyze.disabled = false;
        return;
      }

      console.log('Raw API Response Data:', result.data);

      // Store analysis data globally for download function
      window.currentAnalysis = result.data;
      
      const fileNameEl = document.getElementById('file-name');
      const fileSizeEl = document.getElementById('file-size');
      window.currentFileName = fileNameEl ? fileNameEl.textContent : 'Contract.sol';
      window.currentFileSize = fileSizeEl ? fileSizeEl.textContent : 'Unknown';

      // Ensure the correct data structure is set for the new results page
      const reportData = result.data.summary ? result.data : {
        ...result.data,
        summary: result.data.details?.severityBreakdown || { critical: 0, high: 0, medium: 0, low: 0 }
      };

      // Add file info into the report so the new page displays it correctly
      reportData.contractInfo = {
        ...(reportData.contractInfo || {}),
        name: window.currentFileName,
        size: window.currentFileSize
      };

      // Store in sessionStorage to pass it securely to the next page
      sessionStorage.setItem('solvigil_analysis_result', JSON.stringify(reportData));
      sessionStorage.setItem('solvigil_contract_code', window.currentUploadedFileContent || '');
      
      // Navigate to the beautiful premium results interface
      window.location.href = '/analysis-results.html';

    } catch (error) {
      console.error('Analysis error:', error);
      if (window.showToast) window.showToast('❌ ' + error.message, 'error');
      processingSection.style.display = 'none';
      uploadSection.style.display = 'block';
      btnAnalyze.disabled = false;
    } finally {
      btnAnalyze.disabled = false;
    }
  });
  
  // Setup "Analyze Another" button using resetScanner logic
  document.getElementById('btn-analyze-another').addEventListener('click', () => {
    // Clear selected file
    const fileInput = document.getElementById('file-input');
    if (fileInput) fileInput.value = '';
    
    const fileDisplay = document.getElementById('file-display');
    if (fileDisplay) fileDisplay.style.display = 'none';
    
    btnAnalyze.disabled = true;
    window.currentUploadedFileContent = null;
    
    // Hide results, show upload
    resultsSection.style.display = 'none';
    uploadSection.style.display = 'block';
    
    // Reset analysis data
    window.currentAnalysis = null;
    window.currentFileName = null;
    window.currentFileSize = null;
    
    // Scroll to upload
    uploadSection.scrollIntoView({ behavior: 'smooth' });
    
    if (window.showToast) window.showToast('Ready for next analysis', 'info');
  });

  // Setup Code Review Modal
  const btnReviewCode = document.getElementById('btn-review-code');
  if (btnReviewCode) {
    btnReviewCode.addEventListener('click', () => {
      const modal = document.getElementById('code-review-modal');
      const container = document.getElementById('code-review-container');
      
      const code = window.currentUploadedFileContent || '';
      const lines = code.split('\n');
      
      // Get vulnerable lines
      const vulnerableLines = new Set();
      if (window.currentAnalysisResults && window.currentAnalysisResults.vulnerabilities) {
        window.currentAnalysisResults.vulnerabilities.forEach(v => {
          if (v.line) vulnerableLines.add(parseInt(v.line));
          if (v.location) vulnerableLines.add(parseInt(v.location));
        });
      }
      
      let html = '';
      lines.forEach((line, index) => {
        const lineNum = index + 1;
        const isVulnerable = vulnerableLines.has(lineNum);
        const bgStyle = isVulnerable ? 'background-color: rgba(239, 68, 68, 0.1);' : '';
        const numStyle = isVulnerable ? 'color: #ef4444; font-weight: bold;' : 'color: #999;';
        
        // Escape HTML in code line
        const escapedLine = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        
        html += `<div style="display: table-row; ${bgStyle}">
          <div style="display: table-cell; padding: 2px 12px; text-align: right; border-right: 1px solid #eee; user-select: none; width: 40px; ${numStyle}">${lineNum}</div>
          <div style="display: table-cell; padding: 2px 16px; white-space: pre-wrap; word-break: break-all;">${escapedLine || ' '}</div>
        </div>`;
      });
      
      container.innerHTML = html;
      modal.style.display = 'flex';
      setTimeout(() => {
        modal.style.opacity = '1';
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) modalContent.style.animation = 'modalAppear 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) forwards';
      }, 10);
    });
  }

  // Close Code Review Modal
  const btnCloseCodeReview = document.getElementById('btn-close-code-review');
  if (btnCloseCodeReview) {
    btnCloseCodeReview.addEventListener('click', () => {
      const modal = document.getElementById('code-review-modal');
      modal.style.opacity = '0';
      setTimeout(() => {
        modal.style.display = 'none';
      }, 300);
    });
  }

  // Setup Download Report
  const btnDownloadReport = document.getElementById('btn-download-report');
  if (btnDownloadReport) {
    btnDownloadReport.addEventListener('click', () => {
      if (typeof window.downloadReport === 'function') {
        window.downloadReport();
      } else {
        alert('Download function is not available.');
      }
    });
  }
}
