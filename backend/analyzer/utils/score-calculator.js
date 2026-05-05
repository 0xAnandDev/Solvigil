const STATUS_COLORS = {
  "Critical risk": "#EF4444",
  "Vulnerable": "#F59E0B",
  "Needs review": "#FBBF24",
  "Minor issues": "#3B82F6",
  "Safe": "#10B981"
};

class ScoreCalculator {
    static calculate(vulnerabilities = []) {
        const baseScore = 100;
        
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
            if (severity === 'INFO') return;

            const lowerSeverity = severity.toLowerCase();
            if (severityBreakdown[lowerSeverity] !== undefined) {
                severityBreakdown[lowerSeverity]++;
            }
        });

        const deductions = (severityBreakdown.critical * 30) + 
                           (severityBreakdown.high * 20) + 
                           (severityBreakdown.medium * 10) + 
                           (severityBreakdown.low * 5);

        const finalScore = Math.max(0, baseScore - deductions);

        let status = "Safe";
        if (finalScore <= 39) status = "Critical risk";
        else if (finalScore <= 59) status = "Vulnerable";
        else if (finalScore <= 79) status = "Needs review";
        else if (finalScore <= 94) status = "Minor issues";
        else status = "Safe";
        
        let statusReasoning = 'No vulnerabilities detected.';
        if (status === 'Critical risk') statusReasoning = 'Critical risk. DO NOT DEPLOY.';
        else if (status === 'Vulnerable') statusReasoning = 'Vulnerable. Fix before deployment.';
        else if (status === 'Needs review') statusReasoning = 'Needs review. Review required.';
        else if (status === 'Minor issues') statusReasoning = 'Minor issues found that should be addressed.';

        return {
            DECISION: {
                securityScore: finalScore,
                securityStatus: status,
                statusColor: STATUS_COLORS[status] || "#10B981",
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
            statusColor: STATUS_COLORS[status] || "#10B981",
            confidence: 'HIGH',
            details: {
                baseScore,
                deductions,
                vulnerabilityCount: severityBreakdown.critical + severityBreakdown.high + severityBreakdown.medium + severityBreakdown.low,
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
