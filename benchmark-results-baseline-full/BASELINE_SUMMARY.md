# Baseline Results - Full OWASP Benchmark (2740 test cases)
Date: Sat Aug 16 19:04:39 EEST 2025
Confidence Threshold: 0.3
Max Files: 10000
Scan Duration: 65m 28s

## Performance Metrics:
- Precision: 18.2%
- Recall: 40.3%  
- F1-Score: 25.0%
- Accuracy: 29.3%
- False Positive Rate: 75.3%

## Confusion Matrix:
- Vulnerabilities Found: 3137
- True Positives: ~1054
- False Positives: ~2083
- Total Test Cases: 2740

## Category Performance:
- cmdi: F1=59.9% (best)
- sqli: F1=67.0% (best)  
- ldapi: F1=30.0%
- pathtraver: F1=24.6%
- xss: F1=16.4%
- Others: F1=0.0% (hash, trustbound, crypto, weakrand, securecookie, xpathi)

## Key Insights:
- High recall (40.3%) shows good vulnerability detection capability
- Low precision (18.2%) indicates many false positives
- Best performance on SQL Injection (67.0% F1) and Command Injection (59.9% F1)
- Poor performance on cryptographic and configuration issues
- 2083 unmatched vulnerabilities suggest over-detection

## Next Steps:
- Increase confidence threshold to reduce false positives
- Analyze confidence distribution of true vs false positives
- Focus detection rules on better-performing categories

