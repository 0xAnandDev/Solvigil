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

    // --- FINAL VALIDATION LAYER ---
    function validateAndFixReport(report) {
      let critCount = 0, highCount = 0, medCount = 0, lowCount = 0;
      
      // 7. Check each vulnerability
      report.vulnerabilities = report.vulnerabilities.map(v => {
        let validSev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(v.severity) ? v.severity : 'LOW';
        let validLine = (v.line && v.line > 0) ? v.line : 1;
        let validType = v.type || 'Unknown Vulnerability';
        let validDesc = v.description || 'No description provided';
        
        if (validSev !== v.severity || validLine !== v.line || validType !== v.type || validDesc !== v.description) {
          console.warn(`[VALIDATION] Fixing invalid vulnerability data:`, v);
        }
        
        v.severity = validSev;
        v.line = validLine;
        v.type = validType;
        v.description = validDesc;
        
        if (v.severity === 'CRITICAL') critCount++;
        else if (v.severity === 'HIGH') highCount++;
        else if (v.severity === 'MEDIUM') medCount++;
        else if (v.severity === 'LOW') lowCount++;
        
        return v;
      });

      const totalVulns = report.vulnerabilities.length;
      
      // Fix counts to add up exactly
      report.summary.totalFound = totalVulns;
      report.summary.critical = critCount;
      report.summary.high = highCount;
      report.summary.medium = medCount;
      report.summary.low = lowCount;
      report.DECISION.severityBreakdown = { critical: critCount, high: highCount, medium: medCount, low: lowCount };

      if (totalVulns === 0) {
        // 1. If vulnerabilities array is empty
        if (report.securityStatus !== 'Safe') {
           console.warn(`[VALIDATION] Fixing status: empty vulns but status was ${report.securityStatus}`);
           report.securityStatus = 'Safe';
        }
        if (report.securityScore < 95) {
           console.warn(`[VALIDATION] Fixing score: empty vulns but score was ${report.securityScore}`);
           report.securityScore = 100;
        }
      } else {
        // 2. If vulnerabilities array NOT empty
        if (report.securityStatus === 'Safe') {
           console.warn(`[VALIDATION] Fixing status: has vulns but status was Safe`);
           report.securityStatus = 'Low Risk'; // Temporary, will be overridden below
        }
        if (report.securityScore >= 90) {
           console.warn(`[VALIDATION] Fixing score: has vulns but score was ${report.securityScore}`);
           report.securityScore = 89;
        }

        // 3. If CRITICAL severity found
        if (critCount > 0) {
           if (report.securityStatus !== 'Critical Risk') report.securityStatus = 'Critical Risk';
           if (report.securityScore >= 70) report.securityScore = 69;
        } 
        // 4. If only HIGH severity found (no CRITICAL)
        else if (highCount > 0) {
           if (report.securityStatus !== 'High Risk') report.securityStatus = 'High Risk';
           if (report.securityScore < 60 || report.securityScore > 80) report.securityScore = Math.min(Math.max(report.securityScore, 60), 79);
        }
        // 5. If only MEDIUM found (no HIGH/CRITICAL)
        else if (medCount > 0) {
           if (report.securityStatus !== 'Moderate Risk') report.securityStatus = 'Moderate Risk';
           if (report.securityScore < 60 || report.securityScore > 80) report.securityScore = Math.min(Math.max(report.securityScore, 60), 79);
        }
        // 6. If only LOW found
        else if (lowCount > 0) {
           if (report.securityStatus !== 'Low Risk') report.securityStatus = 'Low Risk';
           if (report.securityScore < 80 || report.securityScore >= 95) report.securityScore = Math.min(Math.max(report.securityScore, 80), 94);
        }
      }
      
      report.DECISION.securityStatus = report.securityStatus;
      report.DECISION.securityScore = report.securityScore;
      
      return report;
    }

    return validateAndFixReport(finalReport);
  } catch (error) {
    console.error('[ANALYZER] Error:', error);
    throw new Error(`Analysis failed: ${error.message}`);
  }
}

module.exports = {
  analyzeContract
};
