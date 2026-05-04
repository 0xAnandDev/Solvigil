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

        let status = 'Safe';
        let statusReasoning = 'No vulnerabilities detected.';
        
        if (severityBreakdown.critical > 0) {
            status = 'Critical Risk';
            statusReasoning = 'Critical vulnerabilities found. DO NOT DEPLOY.';
        } else if (severityBreakdown.high > 0) {
            status = 'High Risk';
            statusReasoning = 'High severity vulnerabilities detected. Fix before deployment.';
        } else if (severityBreakdown.medium > 0) {
            status = 'Moderate Risk';
            statusReasoning = 'Medium severity vulnerabilities present. Review required.';
        } else if (severityBreakdown.low > 0) {
            status = 'Low Risk';
            statusReasoning = 'Some low-severity issues found that should be addressed.';
        } else {
            status = 'Safe';
            statusReasoning = 'The contract is generally secure.';
        }

        return {
            DECISION: {
                securityScore: finalScore,
                securityStatus: status,
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
