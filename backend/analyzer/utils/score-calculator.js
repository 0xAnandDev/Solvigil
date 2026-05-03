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
        if (severityBreakdown.critical > 0) {
            status = 'Critical Risk';
        } else if (severityBreakdown.high > 0) {
            status = 'Vulnerable';
        } else if (severityBreakdown.medium > 0) {
            status = 'Needs Review';
        } else if (severityBreakdown.low > 0) {
            status = 'Minor Issues';
        }

        return {
            score: finalScore,
            status,
            confidence: 'HIGH',
            details: {
                baseScore,
                deductions,
                vulnerabilityCount: vulnerabilities.length,
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
