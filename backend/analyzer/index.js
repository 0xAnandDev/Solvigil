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
      securityScore: scoreResult.score,
      securityStatus: scoreResult.status,
      vulnerabilities,
      summary
    };

    return finalReport;
  } catch (error) {
    console.error('[ANALYZER] Error:', error);
    throw new Error(`Analysis failed: ${error.message}`);
  }
}

module.exports = {
  analyzeContract
};
