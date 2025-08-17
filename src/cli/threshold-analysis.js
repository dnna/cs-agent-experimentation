#!/usr/bin/env node

import { promises as fs } from 'fs';
import path from 'path';
import { OwaspBenchmarkEvaluator } from '../evaluation/owasp-benchmark.js';

/**
 * Test multiple confidence thresholds and generate comparative analysis
 */
async function runThresholdAnalysis() {
  const thresholds = [0.70, 0.71, 0.72, 0.73, 0.74, 0.75, 0.76, 0.77, 0.78, 0.79, 0.80];
  const baselineResultsPath = path.join(process.cwd(), 'benchmark-results-v1.2.0-gpt5mini/raw-scan-results.json');
  const outputBaseDir = path.join(process.cwd(), 'threshold-analysis-v1.2.0-gpt5mini-granular');
  
  console.log('🔍 Running comprehensive threshold analysis...\n');
  console.log(`🎯 Testing thresholds: ${thresholds.join(', ')}`);
  console.log(`📁 Results will be saved to: ${outputBaseDir}`);
  
  // Load baseline results
  const rawData = await fs.readFile(baselineResultsPath, 'utf8');
  const originalResults = JSON.parse(rawData);
  console.log(`📊 Loaded ${originalResults.vulnerabilities.length} original vulnerabilities\n`);
  
  const results = [];
  
  for (const threshold of thresholds) {
    console.log(`\n📊 Testing threshold ${threshold}...`);
    
    // Filter vulnerabilities
    const filteredVulnerabilities = originalResults.vulnerabilities.filter(vuln => 
      vuln.confidence >= threshold
    );
    
    console.log(`  ✅ Filtered: ${originalResults.vulnerabilities.length} → ${filteredVulnerabilities.length} vulnerabilities`);
    
    // Create output directory for this threshold
    const thresholdDir = path.join(outputBaseDir, `threshold-${threshold}`);
    await fs.mkdir(thresholdDir, { recursive: true });
    
    // Evaluate against OWASP benchmark
    const evaluator = new OwaspBenchmarkEvaluator();
    await evaluator.loadBenchmark('/Users/dnna/Projects/vulnerabilitydetect');
    const metrics = await evaluator.evaluateResults(filteredVulnerabilities);
    
    // Save results for this threshold
    const thresholdResults = {
      threshold,
      vulnerabilitiesFound: filteredVulnerabilities.length,
      vulnerabilitiesFiltered: originalResults.vulnerabilities.length - filteredVulnerabilities.length,
      metrics,
      timestamp: new Date().toISOString()
    };
    
    await fs.writeFile(
      path.join(thresholdDir, 'results.json'), 
      JSON.stringify(thresholdResults, null, 2)
    );
    
    results.push(thresholdResults);
    
    console.log(`  📈 Precision: ${(metrics.precision * 100).toFixed(1)}%, Recall: ${(metrics.recall * 100).toFixed(1)}%, F1: ${(metrics.f1Score * 100).toFixed(1)}%`);
  }
  
  // Generate comparative analysis
  console.log('\n📊 Generating comparative analysis...');
  await generateComparativeAnalysis(results, outputBaseDir);
  
  // Print summary table
  printSummaryTable(results);
  
  console.log(`\n✅ Threshold analysis complete! Results saved to: ${outputBaseDir}`);
}

/**
 * Generate comparative analysis report
 */
async function generateComparativeAnalysis(results, outputDir) {
  const report = `# Confidence Threshold Analysis Report

*Generated: ${new Date().toISOString()}*  
*Scanner Version: AI-Powered Agentic Scanner v1.2.0 (GPT-5-mini)*

## Executive Summary

This analysis evaluates the impact of different confidence thresholds on vulnerability detection performance, using the OWASP Benchmark v1.2 evaluation framework.

## Threshold Performance Comparison

| Threshold | Vulnerabilities | Precision | Recall | F1-Score | Accuracy | FPR |
|-----------|----------------|-----------|--------|----------|----------|-----|
${results.map(r => 
  `| ${r.threshold} | ${r.vulnerabilitiesFound} | ${(r.metrics.precision * 100).toFixed(1)}% | ${(r.metrics.recall * 100).toFixed(1)}% | ${(r.metrics.f1Score * 100).toFixed(1)}% | ${(r.metrics.accuracy * 100).toFixed(1)}% | ${(r.metrics.falsePositiveRate * 100).toFixed(1)}% |`
).join('\n')}

## Key Insights

### Optimal Threshold Selection
${generateOptimalThresholdInsights(results)}

### Precision-Recall Trade-off
${generatePrecisionRecallInsights(results)}

### Commercial Tool Comparison
${generateCommercialComparison(results)}

## Detailed Analysis

${results.map(r => `
### Threshold ${r.threshold}
- **Vulnerabilities Reported**: ${r.vulnerabilitiesFound} (filtered out: ${r.vulnerabilitiesFiltered})
- **Precision**: ${(r.metrics.precision * 100).toFixed(1)}% 
- **Recall**: ${(r.metrics.recall * 100).toFixed(1)}%
- **F1-Score**: ${(r.metrics.f1Score * 100).toFixed(1)}%
- **False Positive Rate**: ${(r.metrics.falsePositiveRate * 100).toFixed(1)}%
- **Gap to Commercial Average (45% precision)**: ${((r.metrics.precision * 100) - 45).toFixed(1)} points
`).join('\n')}

## Recommendations

${generateRecommendations(results)}

---
*Analysis based on OWASP Benchmark v1.2 (2740 test cases)*
`;

  await fs.writeFile(path.join(outputDir, 'threshold-analysis-report.md'), report);
}

/**
 * Generate optimal threshold insights
 */
function generateOptimalThresholdInsights(results) {
  const bestF1 = results.reduce((best, current) => 
    current.metrics.f1Score > best.metrics.f1Score ? current : best
  );
  
  const bestPrecision = results.reduce((best, current) => 
    current.metrics.precision > best.metrics.precision ? current : best
  );
  
  const aboveCommercial = results.filter(r => r.metrics.precision >= 0.45);
  
  return `
- **Best F1-Score**: Threshold ${bestF1.threshold} (${(bestF1.metrics.f1Score * 100).toFixed(1)}%)
- **Best Precision**: Threshold ${bestPrecision.threshold} (${(bestPrecision.metrics.precision * 100).toFixed(1)}%)
- **Above Commercial Average**: ${aboveCommercial.length > 0 ? 
    aboveCommercial.map(r => `${r.threshold} (${(r.metrics.precision * 100).toFixed(1)}%)`).join(', ') :
    'None - highest was ' + results[results.length-1].threshold + ' at ' + (results[results.length-1].metrics.precision * 100).toFixed(1) + '%'}
`;
}

/**
 * Generate precision-recall insights
 */
function generatePrecisionRecallInsights(results) {
  const sorted = [...results].sort((a, b) => a.threshold - b.threshold);
  
  return `
As confidence threshold increases:
- **Precision trend**: Generally increases (fewer false positives)
- **Recall trend**: Generally decreases (more true positives filtered out)
- **Optimal balance**: Threshold ${sorted.find(r => r.metrics.f1Score === Math.max(...sorted.map(s => s.metrics.f1Score)))?.threshold} provides best F1-Score
`;
}

/**
 * Generate commercial comparison
 */
function generateCommercialComparison(results) {
  const commercialAvg = 0.45;
  const bestPrecision = Math.max(...results.map(r => r.metrics.precision));
  const gap = (bestPrecision * 100) - (commercialAvg * 100);
  
  return `
- **Commercial Average**: 45% precision, 73% recall, 56% F1-Score
- **Best Achievement**: ${(bestPrecision * 100).toFixed(1)}% precision (${gap >= 0 ? '+' : ''}${gap.toFixed(1)} points vs commercial)
- **Competitive Position**: ${gap >= 0 ? 'Above' : 'Below'} commercial average precision
`;
}

/**
 * Generate recommendations
 */
function generateRecommendations(results) {
  const bestF1 = results.reduce((best, current) => 
    current.metrics.f1Score > best.metrics.f1Score ? current : best
  );
  
  return `
1. **For Balanced Performance**: Use threshold ${bestF1.threshold} (best F1-Score: ${(bestF1.metrics.f1Score * 100).toFixed(1)}%)
2. **For High Precision**: Use highest viable threshold while maintaining reasonable recall
3. **For Production Deployment**: Consider threshold ${bestF1.threshold} as optimal balance
4. **For Further Optimization**: Explore category-specific thresholds or hybrid approaches
`;
}

/**
 * Print summary table to console
 */
function printSummaryTable(results) {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('                    THRESHOLD ANALYSIS SUMMARY                 ');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('┌───────────┬──────────────┬───────────┬────────┬──────────┐');
  console.log('│ Threshold │ Vulns Found  │ Precision │ Recall │ F1-Score │');
  console.log('├───────────┼──────────────┼───────────┼────────┼──────────┤');
  
  results.forEach(r => {
    console.log(`│ ${r.threshold.toString().padEnd(9)} │ ${r.vulnerabilitiesFound.toString().padStart(12)} │ ${(r.metrics.precision * 100).toFixed(1).padStart(8)}% │ ${(r.metrics.recall * 100).toFixed(1).padStart(5)}% │ ${(r.metrics.f1Score * 100).toFixed(1).padStart(7)}% │`);
  });
  
  console.log('└───────────┴──────────────┴───────────┴────────┴──────────┘');
  
  // Find best performers
  const bestF1 = results.reduce((best, current) => 
    current.metrics.f1Score > best.metrics.f1Score ? current : best
  );
  const bestPrecision = results.reduce((best, current) => 
    current.metrics.precision > best.metrics.precision ? current : best
  );
  
  console.log('\n🏆 Best Performers:');
  console.log(`   Best F1-Score: ${bestF1.threshold} (${(bestF1.metrics.f1Score * 100).toFixed(1)}%)`);
  console.log(`   Best Precision: ${bestPrecision.threshold} (${(bestPrecision.metrics.precision * 100).toFixed(1)}%)`);
  
  // Commercial comparison
  const aboveCommercial = results.filter(r => r.metrics.precision >= 0.45);
  if (aboveCommercial.length > 0) {
    console.log(`   Above Commercial Avg (45%): ${aboveCommercial.map(r => r.threshold).join(', ')}`);
  } else {
    console.log(`   Closest to Commercial Avg: ${bestPrecision.threshold} (${((bestPrecision.metrics.precision * 100) - 45).toFixed(1)} points gap)`);
  }
}

// Run analysis
runThresholdAnalysis().catch(console.error);