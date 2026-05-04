const SEVERITY_TO_STATUS = {
  CRITICAL: "Critical Risk",
  HIGH: "High Risk",
  MEDIUM: "Moderate Risk",
  LOW: "Low Risk",
  NONE: "Safe"
};

const STATUS_COLORS = {
  "Critical Risk": "#EF4444",
  "High Risk": "#F59E0B",
  "Moderate Risk": "#FBBF24",
  "Low Risk": "#3B82F6",
  "Safe": "#10B981"
};

class ScoreCalculator {
    static calculate(vulnerabilities = []) {
        const baseScore = 100;
        let deductions = 0;
        
        const severityBreakdown = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };

        vulnerabilities.forEach(vuln => {
            // Ignore vulnerabilities explicitly marked as false positive or dismissed
            if (vuln.isFalsePositive || vuln.status === 'false_positive' || vuln.status === 'dismissed' || vuln.isIgnored) {
                return;
            }

            const severity = (vuln.severity || 'INFO').toUpperCase();
            const lowerSeverity = severity.toLowerCase();
            if (severityBreakdown[lowerSeverity] !== undefined) {
                severityBreakdown[lowerSeverity]++;
            }
        });

        if (severityBreakdown.critical > 0) {
            deductions += 35; // First CRITICAL
            if (severityBreakdown.critical > 1) {
                deductions += (severityBreakdown.critical - 1) * 20;
                deductions += (severityBreakdown.critical - 1) * 10; // Compound effect extra penalty
            }
        }
        
        if (severityBreakdown.high > 0) {
            deductions += 25; // First HIGH
            if (severityBreakdown.high > 1) {
                deductions += (severityBreakdown.high - 1) * 10;
                deductions += (severityBreakdown.high - 1) * 5; // Compound effect extra penalty
            }
        }
        
        if (severityBreakdown.medium > 0) {
            deductions += 15; // First MEDIUM
            if (severityBreakdown.medium > 1) {
                deductions += (severityBreakdown.medium - 1) * 15;
                deductions += (severityBreakdown.medium - 1) * 5; // Compound effect extra penalty
            }
        }
        
        if (severityBreakdown.low > 0) {
            deductions += 6; // First LOW
            if (severityBreakdown.low > 1) {
                deductions += (severityBreakdown.low - 1) * 6;
                deductions += (severityBreakdown.low - 1) * 2; // Compound effect extra penalty
            }
        }

        const finalScore = Math.max(0, baseScore - deductions);

        let highestSeverity = 'NONE';
        if (severityBreakdown.critical > 0) highestSeverity = 'CRITICAL';
        else if (severityBreakdown.high > 0) highestSeverity = 'HIGH';
        else if (severityBreakdown.medium > 0) highestSeverity = 'MEDIUM';
        else if (severityBreakdown.low > 0) highestSeverity = 'LOW';

        const status = SEVERITY_TO_STATUS[highestSeverity];
        
        let statusReasoning = 'No vulnerabilities detected.';
        if (highestSeverity === 'CRITICAL') statusReasoning = 'Critical vulnerabilities found. DO NOT DEPLOY.';
        else if (highestSeverity === 'HIGH') statusReasoning = 'High severity vulnerabilities detected. Fix before deployment.';
        else if (highestSeverity === 'MEDIUM') statusReasoning = 'Medium severity vulnerabilities present. Review required.';
        else if (highestSeverity === 'LOW') statusReasoning = 'Some low-severity issues found that should be addressed.';

        return {
            DECISION: {
                securityScore: finalScore,
                securityStatus: status,
                statusColor: STATUS_COLORS[status],
                statusReasoning: statusReasoning,
                severityBreakdown: {
                    critical: severityBreakdown.critical,
                    high: severityBreakdown.high,
                    medium: severityBreakdown.medium,
                    low: severityBreakdown.low
                }
            },
            score: finalScore, // Backward compatibility
            status, // Backward compatibility
            statusColor: STATUS_COLORS[status],
            confidence: 'HIGH',
            details: {
                baseScore,
                deductions,
                vulnerabilityCount: vulnerabilities.filter(v => !v.isFalsePositive && v.status !== 'false_positive' && v.status !== 'dismissed' && !v.isIgnored).length,
                severityBreakdown: {
                    critical: severityBreakdown.critical,
                    high: severityBreakdown.high,
                    medium: severityBreakdown.medium,
                    low: severityBreakdown.low
                }
            }
        };
    }
}

module.exports = ScoreCalculator;
