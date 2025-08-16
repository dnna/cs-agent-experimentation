#!/usr/bin/env node

import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { promisify } from 'util';
import { VulnerabilityCoordinator } from '../core/coordinator.js';
import { OwaspBenchmarkEvaluator } from '../evaluation/owasp-benchmark.js';
import { OwaspXmlGenerator } from '../evaluation/owasp-xml-generator.js';

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Run scanner against OWASP Benchmark and generate scorecard
 */
async function runBenchmark() {
  const benchmarkPath = '/Users/dnna/Projects/vulnerabilitydetect';
  const outputDir = path.join(process.cwd(), 'benchmark-results');
  
  console.log('🚀 Starting OWASP Benchmark evaluation...\n');
  
  try {
    // Step 1: Run the scanner
    console.log('📊 Step 1: Running vulnerability scanner on OWASP Benchmark...');
    console.log(`   Path: ${benchmarkPath}`);
    
    const coordinator = new VulnerabilityCoordinator();
    await coordinator.initialize();
    
    const scanResults = await coordinator.scanRepository(benchmarkPath, {
      language: 'java',
      maxFiles: 10000, // Full benchmark evaluation
      confidenceThreshold: 0.3,
      includeTests: true,
      excludePatterns: [
        // Default excludes
        'node_modules/**',
        '.git/**',
        '**/target/**',
        '**/build/**',
        '**/dist/**',
        '**/*.class',
        '**/*.jar',
        '**/*.war',
        '**/*.ear',
        '**/coverage/**',
        '**/.nyc_output/**',
        // OWASP Benchmark specific excludes - only analyze testcode
        '**/helpers/**',
        '**/utils/**',
        '**/support/**',
        '**/resources/**',
        '**/report/**',
        '**/service/**',
        '**/pojo/**',
        '**/dto/**',
        '**/sonarqube/**',
        '**/*.xml',
        '**/*.properties',
        '**/*.html',
        '**/*.css',
        '**/*.js'
      ]
    });
    
    console.log(`✅ Scan complete: Found ${scanResults.vulnerabilities.length} vulnerabilities\n`);
    
    // Step 2: Save raw results
    console.log('📊 Step 2: Saving raw scan results...');
    await fs.mkdir(outputDir, { recursive: true });
    const rawResultsPath = path.join(outputDir, 'raw-scan-results.json');
    await fs.writeFile(rawResultsPath, JSON.stringify(scanResults, null, 2));
    console.log(`✅ Saved to: ${rawResultsPath}\n`);
    
    // Step 3: Generate OWASP XML format
    console.log('📊 Step 3: Generating OWASP Benchmark XML format...');
    const xmlGenerator = new OwaspXmlGenerator();
    const xmlFilename = xmlGenerator.generateFilename('1.2');
    const xmlPath = path.join(benchmarkPath, 'results', xmlFilename);
    await xmlGenerator.saveXmlResults(scanResults, benchmarkPath, xmlPath);
    console.log(`✅ Generated: ${xmlPath}\n`);
    
    // Step 4: Evaluate against expected results
    console.log('📊 Step 4: Evaluating against expected results...');
    const evaluator = new OwaspBenchmarkEvaluator();
    await evaluator.loadBenchmark(benchmarkPath);
    const metrics = await evaluator.evaluateResults(scanResults.vulnerabilities);
    
    // Save evaluation metrics
    const metricsPath = path.join(outputDir, 'evaluation-metrics.json');
    await fs.writeFile(metricsPath, JSON.stringify(metrics, null, 2));
    console.log(`✅ Saved metrics to: ${metricsPath}\n`);
    
    // Step 5: Generate scorecard using OWASP tools
    console.log('📊 Step 5: Generating OWASP Scorecard...');
    console.log('   Running OWASP scorecard generator...');
    
    try {
      process.chdir(benchmarkPath);
      const { stdout, stderr } = await execAsync('./createScorecards.sh', {
        cwd: benchmarkPath,
        maxBuffer: 10 * 1024 * 1024 // 10MB buffer
      });
      
      if (stderr) {
        console.log('   Warning:', stderr);
      }
      
      console.log('✅ Scorecard generated successfully!\n');
      
      // Find the generated scorecard
      const scorecardPattern = `Benchmark_*${xmlFilename.replace('.xml', '')}.html`;
      const scorecardFiles = await fs.readdir(path.join(benchmarkPath, 'scorecard'));
      const scorecardFile = scorecardFiles.find(f => f.includes(xmlFilename.replace('.xml', '')));
      
      if (scorecardFile) {
        console.log(`📊 Scorecard available at: ${path.join(benchmarkPath, 'scorecard', scorecardFile)}`);
      }
      
    } catch (error) {
      console.log('⚠️  Could not run OWASP scorecard generator (Maven required)');
      console.log('   You can manually run: cd ' + benchmarkPath + ' && ./createScorecards.sh');
    }
    
    // Step 6: Generate comparison report
    console.log('\n📊 Step 6: Generating comparison report...');
    const comparisonReport = generateComparisonReport(metrics);
    const reportPath = path.join(outputDir, 'comparison-report.md');
    await fs.writeFile(reportPath, comparisonReport);
    console.log(`✅ Report saved to: ${reportPath}\n`);
    
    // Print summary
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('                    BENCHMARK RESULTS SUMMARY                  ');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`Tool: AI-Powered Agentic Scanner v1.0.0`);
    console.log(`Total Test Cases: ${metrics.totalTestCases}`);
    console.log(`Vulnerabilities Found: ${scanResults.vulnerabilities.length}`);
    console.log('');
    console.log('Performance Metrics:');
    console.log(`  • Precision: ${(metrics.precision * 100).toFixed(1)}%`);
    console.log(`  • Recall: ${(metrics.recall * 100).toFixed(1)}%`);
    console.log(`  • F1-Score: ${(metrics.f1Score * 100).toFixed(1)}%`);
    console.log(`  • Accuracy: ${(metrics.accuracy * 100).toFixed(1)}%`);
    console.log(`  • False Positive Rate: ${(metrics.falsePositiveRate * 100).toFixed(1)}%`);
    console.log('');
    console.log('Category Performance:');
    for (const [category, catMetrics] of Object.entries(metrics.categoryMetrics || {})) {
      console.log(`  • ${category}: F1=${(catMetrics.f1Score * 100).toFixed(1)}%`);
    }
    console.log('═══════════════════════════════════════════════════════════════');
    
    // Compare with commercial tools
    console.log('\n📊 Comparison with Commercial Tools (from OWASP Benchmark):');
    console.log('┌─────────────────────┬──────────┬──────────┬──────────┐');
    console.log('│ Tool                │ Precision│ Recall   │ F1-Score │');
    console.log('├─────────────────────┼──────────┼──────────┼──────────┤');
    console.log(`│ Your Tool           │ ${(metrics.precision * 100).toFixed(1).padStart(7)}% │ ${(metrics.recall * 100).toFixed(1).padStart(7)}% │ ${(metrics.f1Score * 100).toFixed(1).padStart(7)}% │`);
    console.log('│ Commercial Average  │   45.0% │   73.0% │   56.0% │');
    console.log('│ Best Commercial     │   95.0% │   85.0% │   90.0% │');
    console.log('└─────────────────────┴──────────┴──────────┴──────────┘');
    
    console.log('\n✅ Benchmark evaluation complete!');
    console.log(`   Results saved to: ${outputDir}`);
    console.log(`   XML results at: ${xmlPath}`);
    console.log(`   View scorecard at: ${benchmarkPath}/scorecard/`);
    
  } catch (error) {
    console.error('❌ Error running benchmark:', error);
    process.exit(1);
  }
}

/**
 * Generate markdown comparison report
 */
function generateComparisonReport(metrics) {
  const report = `# OWASP Benchmark Evaluation Report

## Tool Information
- **Name**: AI-Powered Agentic Scanner
- **Version**: 1.0.0
- **Date**: ${new Date().toISOString()}

## Overall Performance

| Metric | Value | Description |
|--------|-------|-------------|
| **Precision** | ${(metrics.precision * 100).toFixed(1)}% | True Positives / (True Positives + False Positives) |
| **Recall** | ${(metrics.recall * 100).toFixed(1)}% | True Positives / (True Positives + False Negatives) |
| **F1-Score** | ${(metrics.f1Score * 100).toFixed(1)}% | Harmonic mean of Precision and Recall |
| **Accuracy** | ${(metrics.accuracy * 100).toFixed(1)}% | (TP + TN) / Total |
| **FPR** | ${(metrics.falsePositiveRate * 100).toFixed(1)}% | False Positive Rate |

## Confusion Matrix

| | Predicted Positive | Predicted Negative |
|---|---|---|
| **Actual Positive** | ${metrics.confusionMatrix.truePositives} (TP) | ${metrics.confusionMatrix.falseNegatives} (FN) |
| **Actual Negative** | ${metrics.confusionMatrix.falsePositives} (FP) | ${metrics.confusionMatrix.trueNegatives} (TN) |

## Category-Specific Performance

| Category | Precision | Recall | F1-Score | Test Cases |
|----------|-----------|--------|----------|------------|
${Object.entries(metrics.categoryMetrics || {}).map(([cat, m]) => 
  `| ${cat} | ${(m.precision * 100).toFixed(1)}% | ${(m.recall * 100).toFixed(1)}% | ${(m.f1Score * 100).toFixed(1)}% | ${m.testCases} |`
).join('\n')}

## Comparison with Commercial Tools

Based on OWASP Benchmark v1.2 published results:

| Tool | Precision | Recall | F1-Score |
|------|-----------|--------|----------|
| **AI-Powered Scanner** | **${(metrics.precision * 100).toFixed(1)}%** | **${(metrics.recall * 100).toFixed(1)}%** | **${(metrics.f1Score * 100).toFixed(1)}%** |
| Commercial Average | 45% | 73% | 56% |
| Best Commercial Tool | 95% | 85% | 90% |
| SAST-01 | 46% | 73% | 56% |
| SAST-02 | 31% | 65% | 42% |
| SAST-03 | 86% | 77% | 81% |
| SAST-04 | 26% | 75% | 39% |
| SAST-05 | 52% | 69% | 59% |
| SAST-06 | 23% | 79% | 36% |

## Key Findings

### Strengths
${metrics.precision > 0.7 ? '- High precision indicates low false positive rate' : ''}
${metrics.recall > 0.7 ? '- High recall indicates good vulnerability detection coverage' : ''}
${metrics.f1Score > 0.6 ? '- Balanced F1-Score shows good overall performance' : ''}

### Areas for Improvement
${metrics.precision < 0.5 ? '- Precision needs improvement to reduce false positives' : ''}
${metrics.recall < 0.5 ? '- Recall needs improvement to detect more vulnerabilities' : ''}
${metrics.f1Score < 0.5 ? '- Overall performance needs enhancement' : ''}

## Recommendations

${metrics.recommendations?.map(r => `- **${r.type}**: ${r.message}`).join('\n') || '- Continue refining detection algorithms'}

---
*Generated by AI-Powered Agentic Vulnerability Scanner*
`;

  return report;
}

// Run if executed directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runBenchmark().catch(console.error);
}