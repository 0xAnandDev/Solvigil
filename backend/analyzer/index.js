const astBuilder = require('./ast-builder');
const vulnerabilityScanner = require('./vulnerability-scanner');
const scoreCalculator = require('./utils/score-calculator');

const fs = require('fs');
async function analyzeContract(code) {
  try {
    fs.writeFileSync('last_analyzed.sol', code);
    console.log('[ANALYZER] Starting analysis...');
    const ast = astBuilder.parse(code);
    console.log('[ANALYZER] AST created successfully');

    const contractInfo = astBuilder.extractInfo(ast, code);

    console.log('[ANALYZER] Running scanner...');
    const vulnerabilities = vulnerabilityScanner.scan(ast, code);
    console.log(`[ANALYZER] Scanner finished. Found ${vulnerabilities.length} vulnerabilities.`);

    const scoreResult = scoreCalculator.calculate(vulnerabilities);
    console.log(`[ANALYZER] Final report generated. Score: ${scoreResult.score}`);

    const summary = {
      totalFound: vulnerabilities.length,
      critical: scoreResult.details.severityBreakdown.critical,
      high: scoreResult.details.severityBreakdown.high,
      medium: scoreResult.details.severityBreakdown.medium,
      low: scoreResult.details.severityBreakdown.low
    };

    const finalReport = {
      contractInfo,
      DECISION: scoreResult.DECISION,
      securityScore: scoreResult.score,
      securityStatus: scoreResult.status,
      vulnerabilities,
      summary
    };

    // --- SANITY CHECKS ---
    let actualCritical = 0, actualHigh = 0, actualMedium = 0, actualLow = 0;
    
    finalReport.vulnerabilities.forEach(v => {
        if (v.isFalsePositive || v.status === 'false_positive' || v.status === 'dismissed' || v.isIgnored) return;
        const sev = (v.severity || 'INFO').toUpperCase();
        if (sev === 'CRITICAL') actualCritical++;
        if (sev === 'HIGH') actualHigh++;
        if (sev === 'MEDIUM') actualMedium++;
        if (sev === 'LOW') actualLow++;
    });

    // Check 4: Fix severity counts if they don't match
    finalReport.summary.critical = actualCritical;
    finalReport.summary.high = actualHigh;
    finalReport.summary.medium = actualMedium;
    finalReport.summary.low = actualLow;
    finalReport.DECISION.severityBreakdown = { critical: actualCritical, high: actualHigh, medium: actualMedium, low: actualLow };

    const hasVulns = actualCritical > 0 || actualHigh > 0 || actualMedium > 0 || actualLow > 0;

    // Check 1: If vulnerabilities exist but score > 90
    if (hasVulns && finalReport.securityScore > 90) {
        console.warn(`[SANITY CHECK] Vulnerabilities exist but score is ${finalReport.securityScore}. Adjusting to 85 max.`);
        finalReport.securityScore = Math.min(finalReport.securityScore, 85);
        finalReport.DECISION.securityScore = finalReport.securityScore;
    }

    // Check 2, 3, 5: Status MUST match highest severity
    let requiredStatus = 'Safe';
    if (actualCritical > 0) requiredStatus = 'Critical Risk';
    else if (actualHigh > 0) requiredStatus = 'High Risk';
    else if (actualMedium > 0) requiredStatus = 'Moderate Risk';
    else if (actualLow > 0) requiredStatus = 'Low Risk';

    if (finalReport.securityStatus !== requiredStatus) {
        console.warn(`[SANITY CHECK] Status mismatch. Adjusting from "${finalReport.securityStatus}" to "${requiredStatus}".`);
        finalReport.securityStatus = requiredStatus;
        finalReport.DECISION.securityStatus = requiredStatus;
    }

    // Enforce stricter score limits based on severity presence
    if (actualCritical > 0 && finalReport.securityScore >= 70) {
        finalReport.securityScore = Math.min(finalReport.securityScore, 69);
        finalReport.DECISION.securityScore = finalReport.securityScore;
    } else if (actualHigh > 0 && finalReport.securityScore >= 80) {
        finalReport.securityScore = Math.min(finalReport.securityScore, 79);
        finalReport.DECISION.securityScore = finalReport.securityScore;
    }

    return finalReport;
  } catch (error) {
    console.error('[ANALYZER] Error:', error);
    throw new Error(`Analysis failed: ${error.message}`);
  }
}

module.exports = {
  analyzeContract
};
