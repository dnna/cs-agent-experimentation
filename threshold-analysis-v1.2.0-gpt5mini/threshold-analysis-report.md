# Confidence Threshold Analysis Report

*Generated: 2025-08-16T21:41:25.728Z*  
*Scanner Version: AI-Powered Agentic Scanner v1.2.0 (GPT-5-mini)*

## Executive Summary

This analysis evaluates the impact of different confidence thresholds on vulnerability detection performance, using the OWASP Benchmark v1.2 evaluation framework.

## Threshold Performance Comparison

| Threshold | Vulnerabilities | Precision | Recall | F1-Score | Accuracy | FPR |
|-----------|----------------|-----------|--------|----------|----------|-----|
| 0.4 | 8583 | 8.8% | 53.6% | 15.2% | 14.8% | 91.7% |
| 0.5 | 8582 | 8.8% | 53.6% | 15.2% | 14.8% | 91.7% |
| 0.6 | 7943 | 9.5% | 53.6% | 16.2% | 15.8% | 91.0% |
| 0.7 | 4169 | 18.1% | 53.4% | 27.0% | 26.8% | 82.3% |
| 0.75 | 348 | 58.3% | 14.3% | 23.0% | 50.6% | 10.9% |
| 0.78 | 11 | 81.8% | 0.6% | 1.3% | 48.6% | 0.2% |

## Key Insights

### Optimal Threshold Selection

- **Best F1-Score**: Threshold 0.7 (27.0%)
- **Best Precision**: Threshold 0.78 (81.8%)
- **Above Commercial Average**: 0.75 (58.3%), 0.78 (81.8%)


### Precision-Recall Trade-off

As confidence threshold increases:
- **Precision trend**: Generally increases (fewer false positives)
- **Recall trend**: Generally decreases (more true positives filtered out)
- **Optimal balance**: Threshold 0.7 provides best F1-Score


### Commercial Tool Comparison

- **Commercial Average**: 45% precision, 73% recall, 56% F1-Score
- **Best Achievement**: 81.8% precision (+36.8 points vs commercial)
- **Competitive Position**: Above commercial average precision


## Detailed Analysis


### Threshold 0.4
- **Vulnerabilities Reported**: 8583 (filtered out: 0)
- **Precision**: 8.8% 
- **Recall**: 53.6%
- **F1-Score**: 15.2%
- **False Positive Rate**: 91.7%
- **Gap to Commercial Average (45% precision)**: -36.2 points


### Threshold 0.5
- **Vulnerabilities Reported**: 8582 (filtered out: 1)
- **Precision**: 8.8% 
- **Recall**: 53.6%
- **F1-Score**: 15.2%
- **False Positive Rate**: 91.7%
- **Gap to Commercial Average (45% precision)**: -36.2 points


### Threshold 0.6
- **Vulnerabilities Reported**: 7943 (filtered out: 640)
- **Precision**: 9.5% 
- **Recall**: 53.6%
- **F1-Score**: 16.2%
- **False Positive Rate**: 91.0%
- **Gap to Commercial Average (45% precision)**: -35.5 points


### Threshold 0.7
- **Vulnerabilities Reported**: 4169 (filtered out: 4414)
- **Precision**: 18.1% 
- **Recall**: 53.4%
- **F1-Score**: 27.0%
- **False Positive Rate**: 82.3%
- **Gap to Commercial Average (45% precision)**: -26.9 points


### Threshold 0.75
- **Vulnerabilities Reported**: 348 (filtered out: 8235)
- **Precision**: 58.3% 
- **Recall**: 14.3%
- **F1-Score**: 23.0%
- **False Positive Rate**: 10.9%
- **Gap to Commercial Average (45% precision)**: 13.3 points


### Threshold 0.78
- **Vulnerabilities Reported**: 11 (filtered out: 8572)
- **Precision**: 81.8% 
- **Recall**: 0.6%
- **F1-Score**: 1.3%
- **False Positive Rate**: 0.2%
- **Gap to Commercial Average (45% precision)**: 36.8 points


## Recommendations


1. **For Balanced Performance**: Use threshold 0.7 (best F1-Score: 27.0%)
2. **For High Precision**: Use highest viable threshold while maintaining reasonable recall
3. **For Production Deployment**: Consider threshold 0.7 as optimal balance
4. **For Further Optimization**: Explore category-specific thresholds or hybrid approaches


---
*Analysis based on OWASP Benchmark v1.2 (2740 test cases)*
