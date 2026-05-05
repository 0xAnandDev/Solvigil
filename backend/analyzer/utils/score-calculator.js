const STATUS_COLORS = {
  "Critical Risk": "#EF4444",
  "High Risk": "#F59E0B",
  "Needs Review": "#FBBF24",
  "Low Risk": "#3B82F6",
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

        let finalScore = Math.max(0, baseScore - deductions);
        const activeVulnerabilities = severityBreakdown.critical + severityBreakdown.high + severityBreakdown.medium + severityBreakdown.low;

        // FINAL VALIDATION CHECK
        if (activeVulnerabilities > 0 && finalScore > 90) {
            finalScore = 90;
        }

        let status = "Safe";
        if (severityBreakdown.critical > 0) status = "Critical Risk";
        else if (severityBreakdown.high > 0) status = "High Risk";
        else if (severityBreakdown.medium > 0) status = "Needs Review";
        else if (severityBreakdown.low > 0) status = "Low Risk";
        else status = "Safe";
        
        let statusReasoning = 'No vulnerabilities detected.';
        if (status === 'Critical Risk') statusReasoning = 'Critical risk. DO NOT DEPLOY.';
        else if (status === 'High Risk') statusReasoning = 'High risk. Fix before deployment.';
        else if (status === 'Needs Review') statusReasoning = 'Needs review. Review required.';
        else if (status === 'Low Risk') statusReasoning = 'Low risk. Minor issues found that should be addressed.';

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
                vulnerabilityCount: activeVulnerabilities,
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
