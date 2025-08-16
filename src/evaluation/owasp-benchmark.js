import { promises as fs } from 'fs';
import path from 'path';
import { parse } from 'fast-csv';

/**
 * OWASP Benchmark evaluator for measuring tool performance
 */
export class OwaspBenchmarkEvaluator {
  constructor() {
    this.benchmarkPath = null;
    this.expectedResults = null;
    this.testCases = null;
    this.vulnerabilityMappings = new Map();
    this.initialized = false;
  }

  /**
   * Load OWASP Benchmark data
   * @param {string} benchmarkPath - Path to OWASP Benchmark
   */
  async loadBenchmark(benchmarkPath) {
    this.benchmarkPath = benchmarkPath;
    
    try {
      // Load expected results
      this.expectedResults = await this.parseExpectedResults();
      
      // Load test case mappings
      this.testCases = await this.parseTestCases();
      
      // Initialize vulnerability mappings
      this.initializeVulnerabilityMappings();
      
      this.initialized = true;
      console.log(`📊 Loaded OWASP Benchmark with ${this.expectedResults.length} test cases`);
      
    } catch (error) {
      throw new Error(`Failed to load OWASP Benchmark: ${error.message}`);
    }
  }

  /**
   * Parse expected results from CSV file
   * @returns {Array} Expected results
   */
  async parseExpectedResults() {
    const csvPath = path.join(this.benchmarkPath, 'expectedresults-1.2.csv');
    
    try {
      const csvContent = await fs.readFile(csvPath, 'utf8');
      const results = [];
      
      // Parse CSV manually for better control
      const lines = csvContent.trim().split('\n');
      const headers = lines[0].split(',');
      
      for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        
        if (values.length >= 4) {
          const testcase = values[0].trim();
          const category = values[1].trim();
          const realVulnerability = values[2].trim().toLowerCase() === 'true';
          const cwe = parseInt(values[3].trim()) || 0;
          
          results.push({
            testcase,
            category,
            isVulnerable: realVulnerability,
            cwe,
            fileName: this.extractFileName(testcase)
          });
        }
      }
      
      return results;
      
    } catch (error) {
      throw new Error(`Failed to parse expected results: ${error.message}`);
    }
  }

  /**
   * Parse test cases from benchmark structure
   * @returns {Array} Test cases
   */
  async parseTestCases() {
    const srcPath = path.join(this.benchmarkPath, 'src/main/java/org/owasp/benchmark/testcode');
    
    try {
      const testCases = [];
      const files = await fs.readdir(srcPath);
      
      for (const file of files) {
        if (file.endsWith('.java')) {
          const filePath = path.join(srcPath, file);
          const content = await fs.readFile(filePath, 'utf8');
          
          // Extract test case info from file
          const testCaseInfo = this.extractTestCaseInfo(file, content);
          if (testCaseInfo) {
            testCases.push(testCaseInfo);
          }
        }
      }
      
      return testCases;
      
    } catch (error) {
      throw new Error(`Failed to parse test cases: ${error.message}`);
    }
  }

  /**
   * Initialize vulnerability type mappings
   */
  initializeVulnerabilityMappings() {
    this.vulnerabilityMappings.set('cmdi', 'COMMAND_INJECTION');
    this.vulnerabilityMappings.set('crypto', 'CRYPTO_WEAKNESS');
    this.vulnerabilityMappings.set('hash', 'CRYPTO_WEAKNESS');
    this.vulnerabilityMappings.set('ldapi', 'LDAP_INJECTION');
    this.vulnerabilityMappings.set('pathtraver', 'PATH_TRAVERSAL');
    this.vulnerabilityMappings.set('securecookie', 'INSECURE_COOKIE');
    this.vulnerabilityMappings.set('sqli', 'SQL_INJECTION');
    this.vulnerabilityMappings.set('trustbound', 'TRUST_BOUNDARY');
    this.vulnerabilityMappings.set('weakrand', 'WEAK_RANDOMNESS');
    this.vulnerabilityMappings.set('xpathi', 'XPATH_INJECTION');
    this.vulnerabilityMappings.set('xss', 'XSS');
  }

  /**
   * Evaluate scan results against expected outcomes
   * @param {Array} scanResults - Results from vulnerability scanner
   * @returns {object} Evaluation metrics
   */
  async evaluateResults(scanResults) {
    if (!this.initialized) {
      throw new Error('Benchmark not loaded. Call loadBenchmark() first.');
    }

    console.log(`📊 Evaluating ${scanResults.length} scan results against ${this.expectedResults.length} test cases`);

    const metrics = {
      truePositives: 0,
      falsePositives: 0,
      trueNegatives: 0,
      falseNegatives: 0,
      byCategory: {},
      details: []
    };

    // Track which scan results have been matched to avoid double counting
    const matchedVulnerabilityIds = new Set();

    // Process each expected result
    for (const expected of this.expectedResults) {
      const prediction = this.findPrediction(scanResults, expected);
      const predicted = prediction !== null;

      // Mark this vulnerability as matched if found
      if (prediction && prediction.id) {
        matchedVulnerabilityIds.add(prediction.id);
      }

      // Calculate confusion matrix
      if (expected.isVulnerable && predicted) {
        metrics.truePositives++;
        this.updateCategoryMetrics(metrics.byCategory, expected.category, 'tp');
      } else if (!expected.isVulnerable && !predicted) {
        metrics.trueNegatives++;
        this.updateCategoryMetrics(metrics.byCategory, expected.category, 'tn');
      } else if (!expected.isVulnerable && predicted) {
        metrics.falsePositives++;
        this.updateCategoryMetrics(metrics.byCategory, expected.category, 'fp');
      } else if (expected.isVulnerable && !predicted) {
        metrics.falseNegatives++;
        this.updateCategoryMetrics(metrics.byCategory, expected.category, 'fn');
      }

      // Store detailed result
      metrics.details.push({
        testcase: expected.testcase,
        category: expected.category,
        expected: expected.isVulnerable,
        predicted: predicted,
        correct: (expected.isVulnerable === predicted),
        cwe: expected.cwe,
        confidence: prediction?.confidence || 0
      });
    }

    // Count unmatched scan results as false positives
    let unmatchedCount = 0;
    for (const result of scanResults) {
      if (!matchedVulnerabilityIds.has(result.id)) {
        unmatchedCount++;
        metrics.falsePositives++;
        
        // Try to categorize this false positive
        const category = this.mapVulnerabilityTypeToCategory(result.type) || 'unknown';
        this.updateCategoryMetrics(metrics.byCategory, category, 'fp');
      }
    }

    console.log(`📊 Found ${unmatchedCount} unmatched scan results counted as false positives`);

    // Calculate final metrics
    const finalMetrics = this.calculateFinalMetrics(metrics);
    
    // Generate category-specific metrics
    finalMetrics.categoryMetrics = this.calculateCategoryMetrics(metrics.byCategory);
    
    console.log(`📊 Evaluation completed:`);
    console.log(`   Precision: ${(finalMetrics.precision * 100).toFixed(1)}%`);
    console.log(`   Recall: ${(finalMetrics.recall * 100).toFixed(1)}%`);
    console.log(`   F1-Score: ${(finalMetrics.f1Score * 100).toFixed(1)}%`);
    console.log(`   Accuracy: ${(finalMetrics.accuracy * 100).toFixed(1)}%`);

    return finalMetrics;
  }

  /**
   * Find prediction for a test case
   * @param {Array} scanResults - Scan results
   * @param {object} expected - Expected result
   * @returns {object|null} Prediction or null if not found
   */
  findPrediction(scanResults, expected) {
    // Try to match by file name
    const fileName = expected.fileName;
    
    for (const result of scanResults) {
      const resultFile = result.file || result.relativePath || '';
      
      if (resultFile.includes(fileName)) {
        // Check if vulnerability type matches
        const expectedType = this.mapCategoryToVulnerabilityType(expected.category);
        
        if (expectedType === result.type) {
          return result;
        }
      }
    }
    
    return null;
  }

  /**
   * Map benchmark category to vulnerability type
   * @param {string} category - Benchmark category
   * @returns {string} Vulnerability type
   */
  mapCategoryToVulnerabilityType(category) {
    const lowerCategory = category.toLowerCase();
    
    for (const [key, value] of this.vulnerabilityMappings.entries()) {
      if (lowerCategory.includes(key)) {
        return value;
      }
    }
    
    return 'UNKNOWN';
  }

  /**
   * Map vulnerability type back to benchmark category (reverse mapping)
   * @param {string} vulnType - Vulnerability type
   * @returns {string} Benchmark category
   */
  mapVulnerabilityTypeToCategory(vulnType) {
    for (const [category, mappedType] of this.vulnerabilityMappings.entries()) {
      if (mappedType === vulnType) {
        return category;
      }
    }
    
    // Handle common types not in mapping
    const typeMap = {
      'XSS': 'xss',
      'SECURITY_MISCONFIGURATION': 'unknown',
      'CRYPTOGRAPHIC_ISSUE': 'crypto',
      'SENSITIVE_DATA_EXPOSURE': 'unknown',
      'INSECURE_DESERIALIZATION': 'unknown',
      'XML_EXTERNAL_ENTITY': 'unknown',
      'BROKEN_AUTHENTICATION': 'unknown',
      'BROKEN_ACCESS_CONTROL': 'unknown'
    };
    
    return typeMap[vulnType] || 'unknown';
  }

  /**
   * Extract file name from test case name
   * @param {string} testcase - Test case name
   * @returns {string} File name
   */
  extractFileName(testcase) {
    // Extract file name from test case (e.g., "BenchmarkTest00001" -> "BenchmarkTest00001")
    const match = testcase.match(/BenchmarkTest\d+/);
    return match ? match[0] : testcase;
  }

  /**
   * Extract test case information from file
   * @param {string} fileName - File name
   * @param {string} content - File content
   * @returns {object} Test case info
   */
  extractTestCaseInfo(fileName, content) {
    const testCaseName = fileName.replace('.java', '');
    
    // Extract vulnerability category from file content
    const categoryMatch = content.match(/\/\*\s*OWASP.*?category:\s*(\w+)/i);
    const category = categoryMatch ? categoryMatch[1] : 'unknown';
    
    // Extract CWE from file content
    const cweMatch = content.match(/CWE-(\d+)/);
    const cwe = cweMatch ? parseInt(cweMatch[1]) : 0;
    
    return {
      testcase: testCaseName,
      fileName: testCaseName,
      category,
      cwe,
      filePath: fileName
    };
  }

  /**
   * Update category metrics
   * @param {object} categoryMetrics - Category metrics object
   * @param {string} category - Category name
   * @param {string} type - Metric type (tp, fp, tn, fn)
   */
  updateCategoryMetrics(categoryMetrics, category, type) {
    if (!categoryMetrics[category]) {
      categoryMetrics[category] = { tp: 0, fp: 0, tn: 0, fn: 0 };
    }
    categoryMetrics[category][type]++;
  }

  /**
   * Calculate final metrics
   * @param {object} metrics - Raw metrics
   * @returns {object} Calculated metrics
   */
  calculateFinalMetrics(metrics) {
    const { truePositives, falsePositives, trueNegatives, falseNegatives } = metrics;
    
    const precision = truePositives / (truePositives + falsePositives) || 0;
    const recall = truePositives / (truePositives + falseNegatives) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;
    const accuracy = (truePositives + trueNegatives) / 
                    (truePositives + trueNegatives + falsePositives + falseNegatives) || 0;
    
    const falsePositiveRate = falsePositives / (falsePositives + trueNegatives) || 0;
    const falseNegativeRate = falseNegatives / (falseNegatives + truePositives) || 0;

    return {
      precision,
      recall,
      f1Score,
      accuracy,
      falsePositiveRate,
      falseNegativeRate,
      confusionMatrix: {
        truePositives,
        falsePositives,
        trueNegatives,
        falseNegatives
      },
      totalTestCases: this.expectedResults.length,
      details: metrics.details
    };
  }

  /**
   * Calculate category-specific metrics
   * @param {object} categoryMetrics - Category metrics
   * @returns {object} Calculated category metrics
   */
  calculateCategoryMetrics(categoryMetrics) {
    const categoryResults = {};
    
    for (const [category, metrics] of Object.entries(categoryMetrics)) {
      const { tp, fp, tn, fn } = metrics;
      
      const precision = tp / (tp + fp) || 0;
      const recall = tp / (tp + fn) || 0;
      const f1Score = 2 * (precision * recall) / (precision + recall) || 0;
      const accuracy = (tp + tn) / (tp + tn + fp + fn) || 0;
      
      categoryResults[category] = {
        precision,
        recall,
        f1Score,
        accuracy,
        testCases: tp + fp + tn + fn,
        vulnerabilities: tp + fn,
        confusionMatrix: { tp, fp, tn, fn }
      };
    }
    
    return categoryResults;
  }

  /**
   * Generate benchmark report
   * @param {object} metrics - Evaluation metrics
   * @returns {object} Benchmark report
   */
  generateBenchmarkReport(metrics) {
    const report = {
      metadata: {
        title: 'OWASP Benchmark Evaluation Report',
        benchmarkPath: this.benchmarkPath,
        generatedAt: new Date().toISOString(),
        version: '1.2'
      },
      summary: {
        totalTestCases: metrics.totalTestCases,
        precision: metrics.precision,
        recall: metrics.recall,
        f1Score: metrics.f1Score,
        accuracy: metrics.accuracy,
        falsePositiveRate: metrics.falsePositiveRate,
        falseNegativeRate: metrics.falseNegativeRate
      },
      confusionMatrix: metrics.confusionMatrix,
      categoryMetrics: metrics.categoryMetrics,
      recommendations: this.generateRecommendations(metrics),
      details: metrics.details
    };

    return report;
  }

  /**
   * Generate recommendations based on results
   * @param {object} metrics - Evaluation metrics
   * @returns {Array} Recommendations
   */
  generateRecommendations(metrics) {
    const recommendations = [];
    
    if (metrics.precision < 0.7) {
      recommendations.push({
        type: 'precision',
        message: 'Consider improving precision by reducing false positives through better validation',
        priority: 'high'
      });
    }
    
    if (metrics.recall < 0.7) {
      recommendations.push({
        type: 'recall',
        message: 'Consider improving recall by enhancing detection capabilities',
        priority: 'high'
      });
    }
    
    if (metrics.f1Score < 0.6) {
      recommendations.push({
        type: 'overall',
        message: 'Overall performance needs improvement in both precision and recall',
        priority: 'critical'
      });
    }
    
    // Category-specific recommendations
    for (const [category, categoryMetrics] of Object.entries(metrics.categoryMetrics)) {
      if (categoryMetrics.f1Score < 0.5) {
        recommendations.push({
          type: 'category',
          category,
          message: `Poor performance in ${category} category. Consider specialized detection rules`,
          priority: 'medium'
        });
      }
    }
    
    return recommendations;
  }

  /**
   * Export results to CSV format
   * @param {object} metrics - Evaluation metrics
   * @returns {string} CSV content
   */
  exportToCSV(metrics) {
    const headers = ['testcase', 'category', 'expected', 'predicted', 'correct', 'cwe', 'confidence'];
    const rows = [headers.join(',')];
    
    for (const detail of metrics.details) {
      const row = [
        detail.testcase,
        detail.category,
        detail.expected,
        detail.predicted,
        detail.correct,
        detail.cwe,
        detail.confidence
      ];
      rows.push(row.join(','));
    }
    
    return rows.join('\n');
  }

  /**
   * Get benchmark statistics
   * @returns {object} Benchmark statistics
   */
  getBenchmarkStats() {
    if (!this.initialized) {
      return null;
    }
    
    const stats = {
      totalTestCases: this.expectedResults.length,
      vulnerableTestCases: this.expectedResults.filter(r => r.isVulnerable).length,
      safeTestCases: this.expectedResults.filter(r => !r.isVulnerable).length,
      categories: {},
      cwes: {}
    };
    
    // Count by category
    for (const result of this.expectedResults) {
      stats.categories[result.category] = (stats.categories[result.category] || 0) + 1;
      stats.cwes[result.cwe] = (stats.cwes[result.cwe] || 0) + 1;
    }
    
    return stats;
  }
}

export default OwaspBenchmarkEvaluator;