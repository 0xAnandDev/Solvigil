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

      const STATUS_COLORS = {
        "Critical Risk": "#EF4444",
        "High Risk": "#F59E0B",
        "Needs Review": "#FBBF24",
        "Low Risk": "#3B82F6",
        "Safe": "#10B981"
      };

      if (totalVulns === 0) {
        // 1. If vulnerabilities array is empty
        if (report.securityStatus !== 'Safe') {
           console.warn(`[VALIDATION] Fixing status: empty vulns but status was ${report.securityStatus}`);
           report.securityStatus = 'Safe';
        }
        if (report.securityScore !== 100) {
           console.warn(`[VALIDATION] Fixing score: empty vulns but score was ${report.securityScore}`);
           report.securityScore = 100;
        }
      } else {
        // 2. If vulnerabilities array NOT empty
        if (report.securityStatus === 'Safe') {
           console.warn(`[VALIDATION] Fixing status: has vulns but status was Safe`);
           report.securityStatus = 'Low Risk'; // Will be overridden below
        }

        // 3. Status is ALWAYS determined by highest severity
        if (critCount > 0) {
           report.securityStatus = 'Critical Risk';
        } else if (highCount > 0) {
           report.securityStatus = 'High Risk';
        } else if (medCount > 0) {
           report.securityStatus = 'Needs Review';
        } else if (lowCount > 0) {
           report.securityStatus = 'Low Risk';
        }

        // 4. Score recalculation based on new weights
        const deductions = (critCount * 40) + (highCount * 25) + (medCount * 15) + (lowCount * 5);
        report.securityScore = Math.max(0, Math.min(100, 100 - deductions));

        // 5. Score Normalization Rules based on status
        if (report.securityStatus === 'Critical Risk' && report.securityScore > 40) {
           report.securityScore = 40;
        } else if (report.securityStatus === 'High Risk' && report.securityScore > 70) {
           report.securityScore = 70;
        } else if (report.securityStatus === 'Needs Review' && report.securityScore > 85) {
           report.securityScore = 85;
        } else if (report.securityStatus === 'Low Risk' && report.securityScore > 95) {
           report.securityScore = 95;
        }
      }
      
      report.DECISION.securityStatus = report.securityStatus;
      report.DECISION.securityScore = report.securityScore;
      report.DECISION.statusColor = STATUS_COLORS[report.securityStatus] || "#10B981";
      report.statusColor = report.DECISION.statusColor;
      
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
