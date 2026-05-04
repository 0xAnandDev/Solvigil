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
        if (finalScore >= 95) {
            status = 'Safe';
        } else if (finalScore >= 80) {
            status = 'Minor Issues';
        } else if (finalScore >= 60) {
            status = 'Needs Review';
        } else if (finalScore >= 40) {
            status = 'Vulnerable';
        } else {
            status = 'Critical Risk';
        }

        return {
            score: finalScore,
            status,
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
