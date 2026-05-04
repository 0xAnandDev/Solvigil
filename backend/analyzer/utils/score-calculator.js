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

        const weights = {
            CRITICAL: 30,
            HIGH: 20,
            MEDIUM: 10,
            LOW: 5,
            INFO: 1
        };

        vulnerabilities.forEach(vuln => {
            // Ignore vulnerabilities explicitly marked as false positive or dismissed
            if (vuln.isFalsePositive || vuln.status === 'false_positive' || vuln.status === 'dismissed' || vuln.isIgnored) {
                return;
            }

            const severity = (vuln.severity || 'INFO').toUpperCase();
            
            if (weights[severity]) {
                deductions += weights[severity];
            }
            
            const lowerSeverity = severity.toLowerCase();
            if (severityBreakdown[lowerSeverity] !== undefined) {
                severityBreakdown[lowerSeverity]++;
            }
        });

        const finalScore = Math.max(0, baseScore - deductions);

        let status = 'Safe';
        let statusReasoning = 'No vulnerabilities detected.';
        if (finalScore >= 95) {
            status = 'Safe';
            statusReasoning = 'The contract is generally secure.';
        } else if (finalScore >= 80) {
            status = 'Minor Issues';
            statusReasoning = 'Some low-severity issues found that should be addressed.';
        } else if (finalScore >= 60) {
            status = 'Needs Review';
            statusReasoning = 'Medium severity vulnerabilities present. Review required.';
        } else if (finalScore >= 40) {
            status = 'Vulnerable';
            statusReasoning = 'High severity vulnerabilities detected. Fix before deployment.';
        } else {
            status = 'Critical Risk';
            statusReasoning = 'Critical vulnerabilities found. DO NOT DEPLOY.';
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
