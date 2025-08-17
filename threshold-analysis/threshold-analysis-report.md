# Confidence Threshold Analysis Report

*Generated: 2025-08-16T16:19:02.012Z*  
*Scanner Version: AI-Powered Agentic Scanner v1.1.0*

## Executive Summary

This analysis evaluates the impact of different confidence thresholds on vulnerability detection performance, using the OWASP Benchmark v1.2 evaluation framework.

## Threshold Performance Comparison

| Threshold | Vulnerabilities | Precision | Recall | F1-Score | Accuracy | FPR |
|-----------|----------------|-----------|--------|----------|----------|-----|
| 0.4 | 3128 | 18.2% | 40.3% | 25.1% | 29.3% | 75.3% |
| 0.5 | 3083 | 18.5% | 40.3% | 25.3% | 29.6% | 74.9% |
| 0.6 | 2503 | 22.8% | 40.3% | 29.1% | 33.7% | 69.6% |
| 0.7 | 1431 | 39.6% | 40.0% | 39.8% | 45.2% | 50.5% |
| 0.75 | 284 | 56.3% | 11.3% | 18.8% | 49.7% | 9.4% |
| 0.78 | 15 | 60.0% | 0.6% | 1.3% | 48.5% | 0.5% |

## Key Insights

### Optimal Threshold Selection

- **Best F1-Score**: Threshold 0.7 (39.8%)
- **Best Precision**: Threshold 0.78 (60.0%)
- **Above Commercial Average**: 0.75 (56.3%), 0.78 (60.0%)


### Precision-Recall Trade-off

As confidence threshold increases:
- **Precision trend**: Generally increases (fewer false positives)
- **Recall trend**: Generally decreases (more true positives filtered out)
- **Optimal balance**: Threshold 0.7 provides best F1-Score


### Commercial Tool Comparison

- **Commercial Average**: 45% precision, 73% recall, 56% F1-Score
- **Best Achievement**: 60.0% precision (+15.0 points vs commercial)
- **Competitive Position**: Above commercial average precision


## Detailed Analysis


### Threshold 0.4
- **Vulnerabilities Reported**: 3128 (filtered out: 9)
- **Precision**: 18.2% 
- **Recall**: 40.3%
- **F1-Score**: 25.1%
- **False Positive Rate**: 75.3%
- **Gap to Commercial Average (45% precision)**: -26.8 points


### Threshold 0.5
- **Vulnerabilities Reported**: 3083 (filtered out: 54)
- **Precision**: 18.5% 
- **Recall**: 40.3%
- **F1-Score**: 25.3%
- **False Positive Rate**: 74.9%
- **Gap to Commercial Average (45% precision)**: -26.5 points


### Threshold 0.6
- **Vulnerabilities Reported**: 2503 (filtered out: 634)
- **Precision**: 22.8% 
- **Recall**: 40.3%
- **F1-Score**: 29.1%
- **False Positive Rate**: 69.6%
- **Gap to Commercial Average (45% precision)**: -22.2 points


### Threshold 0.7
- **Vulnerabilities Reported**: 1431 (filtered out: 1706)
- **Precision**: 39.6% 
- **Recall**: 40.0%
- **F1-Score**: 39.8%
- **False Positive Rate**: 50.5%
- **Gap to Commercial Average (45% precision)**: -5.4 points


### Threshold 0.75
- **Vulnerabilities Reported**: 284 (filtered out: 2853)
- **Precision**: 56.3% 
- **Recall**: 11.3%
- **F1-Score**: 18.8%
- **False Positive Rate**: 9.4%
- **Gap to Commercial Average (45% precision)**: 11.3 points


### Threshold 0.78
- **Vulnerabilities Reported**: 15 (filtered out: 3122)
- **Precision**: 60.0% 
- **Recall**: 0.6%
- **F1-Score**: 1.3%
- **False Positive Rate**: 0.5%
- **Gap to Commercial Average (45% precision)**: 15.0 points


## Recommendations


1. **For Balanced Performance**: Use threshold 0.7 (best F1-Score: 39.8%)
2. **For High Precision**: Use highest viable threshold while maintaining reasonable recall
3. **For Production Deployment**: Consider threshold 0.7 as optimal balance
4. **For Further Optimization**: Explore category-specific thresholds or hybrid approaches


---
*Analysis based on OWASP Benchmark v1.2 (2740 test cases)*
