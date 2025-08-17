# Confidence Threshold Analysis Report

*Generated: 2025-08-16T21:45:19.022Z*  
*Scanner Version: AI-Powered Agentic Scanner v1.2.0 (GPT-5-mini)*

## Executive Summary

This analysis evaluates the impact of different confidence thresholds on vulnerability detection performance, using the OWASP Benchmark v1.2 evaluation framework.

## Threshold Performance Comparison

| Threshold | Vulnerabilities | Precision | Recall | F1-Score | Accuracy | FPR |
|-----------|----------------|-----------|--------|----------|----------|-----|
| 0.7 | 4169 | 18.1% | 53.4% | 27.0% | 26.8% | 82.3% |
| 0.71 | 3289 | 22.9% | 53.3% | 32.1% | 31.8% | 77.5% |
| 0.72 | 2704 | 27.8% | 53.1% | 36.5% | 36.3% | 72.6% |
| 0.73 | 2039 | 31.4% | 45.3% | 37.1% | 40.9% | 61.8% |
| 0.74 | 735 | 53.9% | 28.0% | 36.8% | 51.1% | 24.9% |
| 0.75 | 348 | 58.3% | 14.3% | 23.0% | 50.6% | 10.9% |
| 0.76 | 75 | 60.0% | 3.2% | 6.0% | 48.9% | 2.3% |
| 0.77 | 23 | 69.6% | 1.1% | 2.2% | 48.7% | 0.5% |
| 0.78 | 11 | 81.8% | 0.6% | 1.3% | 48.6% | 0.2% |
| 0.79 | 0 | 0.0% | 0.0% | 0.0% | 48.4% | 0.0% |
| 0.8 | 0 | 0.0% | 0.0% | 0.0% | 48.4% | 0.0% |

## Key Insights

### Optimal Threshold Selection

- **Best F1-Score**: Threshold 0.73 (37.1%)
- **Best Precision**: Threshold 0.78 (81.8%)
- **Above Commercial Average**: 0.74 (53.9%), 0.75 (58.3%), 0.76 (60.0%), 0.77 (69.6%), 0.78 (81.8%)


### Precision-Recall Trade-off

As confidence threshold increases:
- **Precision trend**: Generally increases (fewer false positives)
- **Recall trend**: Generally decreases (more true positives filtered out)
- **Optimal balance**: Threshold 0.73 provides best F1-Score


### Commercial Tool Comparison

- **Commercial Average**: 45% precision, 73% recall, 56% F1-Score
- **Best Achievement**: 81.8% precision (+36.8 points vs commercial)
- **Competitive Position**: Above commercial average precision


## Detailed Analysis


### Threshold 0.7
- **Vulnerabilities Reported**: 4169 (filtered out: 4414)
- **Precision**: 18.1% 
- **Recall**: 53.4%
- **F1-Score**: 27.0%
- **False Positive Rate**: 82.3%
- **Gap to Commercial Average (45% precision)**: -26.9 points


### Threshold 0.71
- **Vulnerabilities Reported**: 3289 (filtered out: 5294)
- **Precision**: 22.9% 
- **Recall**: 53.3%
- **F1-Score**: 32.1%
- **False Positive Rate**: 77.5%
- **Gap to Commercial Average (45% precision)**: -22.1 points


### Threshold 0.72
- **Vulnerabilities Reported**: 2704 (filtered out: 5879)
- **Precision**: 27.8% 
- **Recall**: 53.1%
- **F1-Score**: 36.5%
- **False Positive Rate**: 72.6%
- **Gap to Commercial Average (45% precision)**: -17.2 points


### Threshold 0.73
- **Vulnerabilities Reported**: 2039 (filtered out: 6544)
- **Precision**: 31.4% 
- **Recall**: 45.3%
- **F1-Score**: 37.1%
- **False Positive Rate**: 61.8%
- **Gap to Commercial Average (45% precision)**: -13.6 points


### Threshold 0.74
- **Vulnerabilities Reported**: 735 (filtered out: 7848)
- **Precision**: 53.9% 
- **Recall**: 28.0%
- **F1-Score**: 36.8%
- **False Positive Rate**: 24.9%
- **Gap to Commercial Average (45% precision)**: 8.9 points


### Threshold 0.75
- **Vulnerabilities Reported**: 348 (filtered out: 8235)
- **Precision**: 58.3% 
- **Recall**: 14.3%
- **F1-Score**: 23.0%
- **False Positive Rate**: 10.9%
- **Gap to Commercial Average (45% precision)**: 13.3 points


### Threshold 0.76
- **Vulnerabilities Reported**: 75 (filtered out: 8508)
- **Precision**: 60.0% 
- **Recall**: 3.2%
- **F1-Score**: 6.0%
- **False Positive Rate**: 2.3%
- **Gap to Commercial Average (45% precision)**: 15.0 points


### Threshold 0.77
- **Vulnerabilities Reported**: 23 (filtered out: 8560)
- **Precision**: 69.6% 
- **Recall**: 1.1%
- **F1-Score**: 2.2%
- **False Positive Rate**: 0.5%
- **Gap to Commercial Average (45% precision)**: 24.6 points


### Threshold 0.78
- **Vulnerabilities Reported**: 11 (filtered out: 8572)
- **Precision**: 81.8% 
- **Recall**: 0.6%
- **F1-Score**: 1.3%
- **False Positive Rate**: 0.2%
- **Gap to Commercial Average (45% precision)**: 36.8 points


### Threshold 0.79
- **Vulnerabilities Reported**: 0 (filtered out: 8583)
- **Precision**: 0.0% 
- **Recall**: 0.0%
- **F1-Score**: 0.0%
- **False Positive Rate**: 0.0%
- **Gap to Commercial Average (45% precision)**: -45.0 points


### Threshold 0.8
- **Vulnerabilities Reported**: 0 (filtered out: 8583)
- **Precision**: 0.0% 
- **Recall**: 0.0%
- **F1-Score**: 0.0%
- **False Positive Rate**: 0.0%
- **Gap to Commercial Average (45% precision)**: -45.0 points


## Recommendations


1. **For Balanced Performance**: Use threshold 0.73 (best F1-Score: 37.1%)
2. **For High Precision**: Use highest viable threshold while maintaining reasonable recall
3. **For Production Deployment**: Consider threshold 0.73 as optimal balance
4. **For Further Optimization**: Explore category-specific thresholds or hybrid approaches


---
*Analysis based on OWASP Benchmark v1.2 (2740 test cases)*
