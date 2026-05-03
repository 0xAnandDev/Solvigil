export async function renderResults(detectorResults = null) {
  try {
    let vulnerabilities = [];
    let summary = {};
    let score = 100;

    if (detectorResults) {
      vulnerabilities = detectorResults.vulnerabilities;
      summary = detectorResults.summary;
      score = detectorResults.securityScore;
    } else {
      // Fetch mock vulnerability data fallback
      const response = await fetch('/data/sample-vulnerabilities.json');
      vulnerabilities = await response.json();
      
      summary.critical = 0;
      summary.high = 0;
      summary.medium = 0;
      summary.low = 0;
      
      vulnerabilities.forEach(v => {
        if (v.severity === 'CRITICAL') summary.critical++;
        else if (v.severity === 'HIGH') summary.high++;
        else if (v.severity === 'MEDIUM') summary.medium++;
        else if (v.severity === 'LOW' || v.severity === 'INFO') summary.low++;
      });
      score = 78;
    }
    
    // Construct analysis object for status display
    let securityStatus = 'Safe';
    if (score < 50) {
      securityStatus = 'Critical Risk';
    } else if (score < 70) {
      securityStatus = 'Vulnerable';
    } else if (score < 90) {
      securityStatus = 'Needs Review';
    } else if (score < 100) {
      securityStatus = 'Minor Issues';
    }

    const analysis = {
      securityScore: score,
      securityStatus: securityStatus,
      vulnerabilities: vulnerabilities,
      details: {
        confidence: detectorResults ? 'High' : 'Medium (Mock Data)',
        severityBreakdown: {
          critical: summary.critical || 0,
          high: summary.high || 0,
          medium: summary.medium || 0,
          low: summary.low || 0
        }
      }
    };
    
    // Call the main rendering function
    displayResults(analysis);

  } catch (error) {
    console.error('Error loading vulnerabilities:', error);
    const container = document.getElementById('vulnerabilities-container');
    if (container) {
      container.innerHTML = `
        <div class="error-message" style="display: flex;">
          Failed to load analysis results. Please try again.
        </div>
      `;
    }
  }
}

function renderAnalysisResults(analysis) {
  const container = document.getElementById('vulnerabilities-container');
  const safeMessage = document.getElementById('safe-message');
  const resultsSection = document.getElementById('results-section');
  const loadingSection = document.getElementById('processing-section'); // using our existing ID
  
  // Hide loading, show results
  if (loadingSection) loadingSection.style.display = 'none';
  if (resultsSection) resultsSection.style.display = 'block';
  
  // Display security status and score
  displaySecurityStatus(analysis);
  
  // Clear previous vulnerabilities
  if (container) container.innerHTML = '';
  
  // Check if contract is safe
  if (analysis.vulnerabilities.length === 0) {
    if (safeMessage) safeMessage.style.display = 'flex';
    if (container) container.style.display = 'none';
    return;
  }
  
  // Hide safe message, show vulnerabilities
  if (safeMessage) safeMessage.style.display = 'none';
  if (container) container.style.display = 'flex';
  
  // Sort vulnerabilities by severity
  const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
  const sorted = [...analysis.vulnerabilities].sort((a, b) =>
    (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );
  
  const formattedVulnerabilities = sorted.map(vuln => ({
    ...vuln,
    type: vuln.type || vuln.name || 'Vulnerability',
    code: vuln.code || vuln.vulnerableCode || 'No code provided',
    fix: vuln.fix || vuln.fixRecommendation || 'No fix provided',
    fixExplanation: vuln.fixExplanation || vuln.fixedCode || vuln.fixRecommendation || '',
    column: vuln.column || 0,
    simulation: vuln.simulation || ['Deploy malicious contract', 'Trigger vulnerable function', 'Exploit completes successfully'],
    impact: vuln.impact || 'System may behave unexpectedly.'
  }));

  // Create and append vulnerability cards
  formattedVulnerabilities.forEach((formattedVuln, index) => {
    const card = createVulnerabilityCard(formattedVuln, index);
    if (container) container.appendChild(card);
  });
  
  // Render Attack Simulation Tab
  renderAttackSimulationTab(formattedVulnerabilities);
  
  // Scroll to results
  setTimeout(() => {
    if (resultsSection) resultsSection.scrollIntoView({ behavior: 'smooth' });
  }, 100);
}

// Main function called from scanner-controller.js
export function displayResults(analysis) {
  window.currentAnalysis = analysis;
  renderAnalysisResults(analysis);
}

function getAttackIcon(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('reentrancy')) return '💣';
  if (t.includes('access control') || t.includes('authorization')) return '🔓';
  if (t.includes('overflow') || t.includes('underflow')) return '💥';
  if (t.includes('unchecked') || t.includes('return value')) return '⚠️';
  if (t.includes('dos') || t.includes('denial of service')) return '🧨';
  if (t.includes('version') || t.includes('compiler') || t.includes('pragma')) return '🧠';
  return '⚔️';
}

function renderAttackSimulationTab(vulnerabilities) {
  const simTab = document.getElementById('tab-simulation');
  if (!simTab) return; // Only execute if the tab exists

  simTab.innerHTML = ''; // Clear hardcoded content

  if (vulnerabilities.length === 0) {
    simTab.innerHTML = `
      <div class="sim-card" style="text-align: center; padding: 40px;">
        <div class="sim-icon" style="margin: 0 auto 16px;">✅</div>
        <h3 class="sim-title">No Vulnerabilities Found</h3>
        <p style="color: var(--text-muted);">Your contract is safe from known attack vectors.</p>
      </div>
    `;
    return;
  }

  vulnerabilities.forEach((vuln) => {
    const card = document.createElement('div');
    card.className = 'sim-card';

    const icon = getAttackIcon(vuln.type);
    const title = vuln.type;
    
    let html = `
      <div class="sim-header">
        <div class="sim-icon">${icon}</div>
        <div>
          <div class="sim-title">${title}</div>
          <div style="font-size: 14px; color: var(--text-muted);">Visualizing the flow of the vulnerability found on Line ${vuln.line || vuln.location || 'Unknown'}</div>
        </div>
      </div>
      <div class="sim-flow-vertical">
    `;

    const steps = vuln.simulation || [];
    steps.forEach((step, index) => {
      // Determine if step is an attacker action for styling
      const isAttacker = step.toLowerCase().includes('attacker') || step.toLowerCase().includes('malicious') || step.toLowerCase().includes('exploit');
      const pillClass = isAttacker ? 'sim-pill attacker' : 'sim-pill';
      
      html += `<div class="${pillClass}" style="animation-delay: ${index * 0.15}s">Step ${index + 1}: ${step}</div>`;
      
      if (index < steps.length - 1) {
        html += `<div class="sim-arrow" style="animation-delay: ${index * 0.15 + 0.05}s">↓</div>`;
      }
    });
    
    html += `</div>`;
    card.innerHTML = html;
    simTab.appendChild(card);
  });
}

function downloadReport() {
  // Get current analysis from window (set by scanner-controller)
  const analysis = window.currentAnalysis;
  
  if (!analysis) {
    showToast('❌ No analysis data available', 'error');
    return;
  }
  
  // Create detailed report object
  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      generatedAt: new Date().toLocaleString(),
      version: '1.0'
    },
    
    file: {
      name: window.currentFileName || 'Contract.sol',
      size: window.currentFileSize || 'Unknown'
    },
    
    analysis: {
      contractInfo: analysis.contractInfo || { name: 'Unknown', compiler: 'Unknown' },
      securityScore: analysis.securityScore,
      securityStatus: analysis.securityStatus,
      confidence: analysis.details.confidence,
      
      summary: {
        totalVulnerabilities: analysis.vulnerabilities.length,
        critical: analysis.details.severityBreakdown.critical,
        high: analysis.details.severityBreakdown.high,
        medium: analysis.details.severityBreakdown.medium,
        low: analysis.details.severityBreakdown.low
      },
      
      vulnerabilities: analysis.vulnerabilities.map(vuln => ({
        type: vuln.type,
        severity: vuln.severity,
        confidence: vuln.confidence,
        line: vuln.line,
        column: vuln.column,
        category: vuln.category,
        description: vuln.description,
        vulnerableCode: vuln.code,
        impact: vuln.impact,
        fix: vuln.fix,
        fixExplanation: vuln.fixExplanation,
        attackSimulation: vuln.simulation,
        references: vuln.references || []
      })),
      
      recommendations: generateRecommendations(analysis)
    }
  };
  
  // Convert to JSON with pretty formatting
  const jsonString = JSON.stringify(report, null, 2);
  
  // Create blob and download
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  
  link.href = url;
  link.download = `solvigil-analysis-${Date.now()}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  
  showToast('✅ Report downloaded successfully!', 'success');
}

function generateRecommendations(analysis) {
  const recommendations = [];
  
  if (analysis.details.severityBreakdown.critical > 0) {
    recommendations.push({
      priority: 'URGENT',
      message: 'Critical vulnerabilities found. DO NOT DEPLOY this contract. Fix immediately.',
      action: 'Review critical issues and apply fixes before any production deployment.'
    });
  }
  
  if (analysis.details.severityBreakdown.high > 0) {
    recommendations.push({
      priority: 'HIGH',
      message: 'High severity issues detected.',
      action: 'Fix high severity vulnerabilities before deploying to mainnet.'
    });
  }
  
  if (analysis.vulnerabilities.length === 0) {
    recommendations.push({
      priority: 'INFO',
      message: 'No vulnerabilities detected by automated analysis.',
      action: 'Consider a professional security audit for comprehensive coverage.'
    });
  } else {
    recommendations.push({
      priority: 'INFO',
      message: 'Professional audit recommended',
      action: 'Automated detection is not a substitute for professional security audits.'
    });
  }
  
  return recommendations;
}

// Expose to window so inline onclick or other scripts can call it
window.downloadReport = downloadReport;

function animateScore(targetScore, duration = 2000) {
  const scoreElement = document.getElementById('score-value');
  const circleProgress = document.querySelector('.circle-progress');
  
  if (!scoreElement || !circleProgress) return;
  
  let currentScore = 0;
  const startTime = Date.now();
  const radius = circleProgress.r.baseVal.value || 54;
  const circumference = 2 * Math.PI * radius;
  
  circleProgress.style.strokeDasharray = circumference;
  circleProgress.style.transition = 'none'; // Clear any CSS transitions
  
  function updateScore() {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Easing function for smooth animation
    const easeOutQuad = p => 1 - (1 - p) * (1 - p);
    const smoothProgress = easeOutQuad(progress);
    
    currentScore = Math.round(targetScore * smoothProgress);
    scoreElement.textContent = currentScore;
    
    // Animate circle progress proportional to score (out of 100)
    const offset = circumference - ((currentScore / 100) * circumference);
    circleProgress.style.strokeDashoffset = offset;
    
    if (progress < 1) {
      requestAnimationFrame(updateScore);
    } else {
      scoreElement.textContent = targetScore;
      circleProgress.style.strokeDashoffset = circumference - ((targetScore / 100) * circumference);
    }
  }
  
  requestAnimationFrame(updateScore);
}

function displaySecurityStatus(analysis) {
  console.log('Analysis data received:', analysis);

  if (!analysis) {
    console.error('No analysis data provided to displaySecurityStatus');
    return;
  }

  const { securityScore, securityStatus, details, summary } = analysis;
  
  // Safe defaults
  const confidence = details?.confidence || analysis.confidence || 'High';
  const breakdown = details?.severityBreakdown || summary || {
    critical: 0, high: 0, medium: 0, low: 0
  };
  
  // Animate score
  if (typeof animateScore === 'function') {
    animateScore(securityScore || 0);
  }
  
  // Set status title and description
  const statusTitle = document.getElementById('status-title');
  const statusDescription = document.getElementById('status-description');
  const confidenceLevel = document.getElementById('confidence-level');
  
  if (statusTitle) statusTitle.textContent = securityStatus || 'Unknown';
  if (confidenceLevel) confidenceLevel.textContent = confidence;
  
  // Set status colors
  const statusColors = {
    'Safe': '#10B981',
    'Minor Issues': '#3B82F6',
    'Needs Review': '#FBBF24',
    'Vulnerable': '#F59E0B',
    'Critical Risk': '#EF4444'
  };
  
  if (statusTitle && securityStatus) {
    statusTitle.style.color = statusColors[securityStatus] || '#666';
  }
  
  // Set description
  const descriptions = {
    'Safe': 'No vulnerabilities detected',
    'Minor Issues': 'Some low-severity issues found',
    'Needs Review': 'Medium severity vulnerabilities present',
    'Vulnerable': 'High severity vulnerabilities detected',
    'Critical Risk': 'Critical vulnerabilities found - DO NOT DEPLOY'
  };
  
  if (statusDescription && securityStatus) {
    statusDescription.textContent = descriptions[securityStatus] || 'Analysis complete';
  }
  
  // Update summary stats
  const statCrit = document.getElementById('stat-critical');
  if (statCrit) statCrit.textContent = breakdown.critical || 0;
  
  const statHigh = document.getElementById('stat-high');
  if (statHigh) statHigh.textContent = breakdown.high || 0;
  
  const statMed = document.getElementById('stat-medium');
  if (statMed) statMed.textContent = breakdown.medium || 0;
  
  const statLow = document.getElementById('stat-low');
  if (statLow) statLow.textContent = breakdown.low || 0;
}

function createVulnerabilityCard(vuln, index) {
  const severityColor = {
    'CRITICAL': '#EF4444',
    'HIGH': '#F59E0B',
    'MEDIUM': '#FBBF24',
    'LOW': '#3B82F6',
    'INFO': '#10B981'
  };
  
  const color = severityColor[vuln.severity] || '#666';
  const card = document.createElement('div');
  card.className = `vulnerability-card severity-${vuln.severity.toLowerCase()}`;
  card.style.animationDelay = `${index * 0.1}s`;
  
  card.innerHTML = `
<div class="card-header">
<div class="severity-badge" style="background-color: ${color}">
${vuln.severity}
</div>
<h3 class="vuln-title">${vuln.type}</h3>
<div class="confidence-tag">
Confidence: ${vuln.confidence}
</div>
</div>
<div class="card-location">
  <span class="line-number">📍 Line ${vuln.line || vuln.location || 'Unknown'}</span>
  <span class="column-number">Column ${vuln.column}</span>
</div>

<div class="card-description">
  <h4>What is this?</h4>
  <p>${vuln.description}</p>
</div>

<div class="card-vulnerable-code">
  <h4>🔴 Vulnerable Code:</h4>
  <div class="code-block">
    <code>${escapeHtml(vuln.code)}</code>
  </div>
</div>

<div class="card-attack-simulation">
  <h4>⚔️ Attack Simulation (How Attacker Exploits):</h4>
  <div class="simulation-steps">
    ${vuln.simulation.map((step, i) => `
      <div class="simulation-step">
        <div class="step-number">${i + 1}</div>
        <div class="step-text">${step}</div>
      </div>
    `).join('')}
  </div>
</div>

<div class="card-impact">
  <h4>⚠️ Impact:</h4>
  <p class="impact-text">${vuln.impact}</p>
</div>

<div class="card-fix">
  <h4>✅ How to Fix:</h4>
  <p class="fix-description">${vuln.fix}</p>
  <div class="fix-code-block">
    <pre><code>${escapeHtml(vuln.fixExplanation)}</code></pre>
  </div>
</div>

<div class="card-actions">
  <button class="btn-copy" onclick="copyToClipboard('${escapeJs(vuln.fixExplanation)}')">
    📋 Copy Fix
  </button>
</div>
`;
  return card;
}

// Helper function to escape HTML
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// Helper function to escape JavaScript strings
function escapeJs(text) {
  if (!text) return '';
  return text.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

// Copy to clipboard function
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('✅ Code copied to clipboard!', 'success');
  }).catch(() => {
    showToast('❌ Failed to copy', 'error');
  });
}

// Toast notification
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.classList.add('show');
  }, 10);
  
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function resetScanner() {
  const fileInput = document.getElementById('file-input');
  if (fileInput) fileInput.value = '';
  
  const fileDisplay = document.getElementById('file-display');
  if (fileDisplay) fileDisplay.style.display = 'none';
  
  const btnAnalyze = document.getElementById('btn-analyze');
  if (btnAnalyze) btnAnalyze.disabled = true;
  
  window.currentUploadedFileContent = null;
  
  const resultsSection = document.getElementById('results-section');
  const uploadSection = document.getElementById('upload-section');
  
  if (resultsSection) resultsSection.style.display = 'none';
  if (uploadSection) uploadSection.style.display = 'block';
  
  window.currentAnalysis = null;
  window.currentFileName = null;
  window.currentFileSize = null;
  
  if (uploadSection) uploadSection.scrollIntoView({ behavior: 'smooth' });
  showToast('Ready for next analysis', 'info');
}

function hideReviewModal() {
  const modal = document.getElementById('code-review-modal');
  if (modal) modal.style.display = 'none';
}

function showReviewModal() {
  let modal = document.getElementById('code-review-modal');
  
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'code-review-modal';
    modal.className = 'modal-overlay';
    modal.style.zIndex = '1010';
    modal.style.padding = '20px';
    modal.innerHTML = `
      <div class="modal-content" style="max-width: 800px; width: 100%; height: 80vh; display: flex; flex-direction: column; background: #ffffff; border-radius: 12px; overflow: hidden;">
        <div class="modal-header" style="flex-shrink: 0; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eaeaea; padding: 16px 24px; background: #fafafa;">
          <h3 class="modal-title" style="margin: 0; font-family: 'Inter', sans-serif; font-size: 18px; color: #111;">Contract Source Code</h3>
          <div style="display: flex; gap: 12px; align-items: center;">
            <button id="btn-copy-all-code" style="background: #00A19B; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">Copy All Code</button>
            <button id="btn-close-code-review" style="background: none; border: none; cursor: pointer; color: #666; padding: 4px; border-radius: 4px; transition: background 0.2s;">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <div class="modal-body" style="flex-grow: 1; overflow-y: auto; padding: 0; background: #ffffff; color: #333;">
          <div id="code-review-container" style="font-family: 'Fira Code', monospace; font-size: 14px; line-height: 1.6; display: table; width: 100%;"></div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('btn-close-code-review').addEventListener('click', hideReviewModal);
    document.getElementById('btn-copy-all-code').addEventListener('click', () => {
      const code = window.currentUploadedFileContent;
      if (code) {
        copyToClipboard(code);
      } else {
        showToast('❌ No code to copy', 'error');
      }
    });
  }
  
  const container = document.getElementById('code-review-container');
  if (!container) return;
  
  // Get the code
  const dummyCode = `pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}`;
  const code = window.currentUploadedFileContent || dummyCode;
  const lines = code.split('\n');
  
  // Map vulnerable lines
  const vulnerableLines = {};
  if (window.currentAnalysis && window.currentAnalysis.vulnerabilities) {
    window.currentAnalysis.vulnerabilities.forEach(vuln => {
      if (vuln.line) {
        // If multiple vulnerabilities on same line, keep the highest severity
        if (!vulnerableLines[vuln.line] || vuln.severity === 'CRITICAL') {
          vulnerableLines[vuln.line] = vuln;
        }
      }
    });
  } else if (!window.currentUploadedFileContent) {
    // Add mock vulnerability for the dummy code
    vulnerableLines[12] = { severity: 'CRITICAL', type: 'Reentrancy', description: 'State variables are updated after an external call' };
  }
  
  let html = '';
  lines.forEach((line, index) => {
    const lineNum = index + 1;
    const vuln = vulnerableLines[lineNum];
    
    if (vuln) {
      // Vulnerable line
      html += `
        <div class="code-line vulnerable" title="🔴 ${vuln.severity}: ${vuln.type} - ${vuln.description || 'Vulnerability detected'}">
          <div class="line-number-col">${lineNum}</div>
          <div class="line-indicator">🔴</div>
          <div class="line-content">${escapeHtml(line)}</div>
        </div>
      `;
    } else {
      // Normal line
      html += `
        <div class="code-line">
          <div class="line-number-col">${lineNum}</div>
          <div class="line-indicator"></div>
          <div class="line-content">${escapeHtml(line)}</div>
        </div>
      `;
    }
  });
  
  container.innerHTML = html;
  modal.style.display = 'flex';
}

// Initialize results renderer when page loads
document.addEventListener('DOMContentLoaded', () => {
// Add CSS link if not already present
if (!document.querySelector('link[href*="results.css"]')) {
const link = document.createElement('link');
link.rel = 'stylesheet';
link.href = 'css/results.css';
document.head.appendChild(link);
}
// Add event listeners for action buttons
const downloadBtn = document.querySelector('.btn-download');
const analyzeAgainBtn = document.querySelector('.btn-analyze-again');
const reviewCodeBtn = document.getElementById('btn-review-code');
const closeCodeReviewBtn = document.getElementById('btn-close-code-review');
const copyAllCodeBtn = document.getElementById('btn-copy-all-code');

if (downloadBtn) {
downloadBtn.addEventListener('click', downloadReport);
}
if (analyzeAgainBtn) {
analyzeAgainBtn.addEventListener('click', resetScanner);
}
if (reviewCodeBtn) {
reviewCodeBtn.addEventListener('click', showReviewModal);
}
if (closeCodeReviewBtn) {
closeCodeReviewBtn.addEventListener('click', hideReviewModal);
}
if (copyAllCodeBtn) {
copyAllCodeBtn.addEventListener('click', () => {
  const code = window.currentUploadedFileContent;
  if (code) {
    copyToClipboard(code);
  } else {
    showToast('❌ No code to copy', 'error');
  }
});
}

// Support for elements that might not have IDs but use the same classes/text
const otherReviewBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent.includes('Review Contract'));
otherReviewBtns.forEach(btn => {
  if (!btn.id) {
    btn.addEventListener('click', showReviewModal);
  }
});

});
// Export functions for global use
window.renderAnalysisResults = renderAnalysisResults;
window.displayResults = displayResults;
window.downloadReport = downloadReport;
window.resetScanner = resetScanner;
window.copyToClipboard = copyToClipboard;
window.showToast = showToast;
window.showReviewModal = showReviewModal;
window.hideReviewModal = hideReviewModal;
