import { BaseAgent } from './base-agent.js';

/**
 * Analyzer agent for detecting vulnerabilities in parsed code
 */
export class AnalyzerAgent extends BaseAgent {
  constructor(id, config = {}, sessionId = null) {
    super(id, config, sessionId);
    this.plugin = config.plugin;
    this.concurrency = config.concurrency || 3;
    this.enableAI = config.enableAI || false;
    this.confidenceThreshold = config.confidenceThreshold || 0.5;
    this.mode = config.mode || 'vulnerability_analysis';
  }

  /**
   * Initialize the analyzer agent
   */
  async initialize() {
    if (this.initialized) return;

    if (!this.plugin) {
      throw new Error('Analyzer agent requires a language plugin');
    }

    // Initialize the plugin if not already done
    if (!this.plugin.initialized) {
      await this.plugin.initialize();
    }

    await super.initialize();
    this.log('info', 'Analyzer agent initialized', { 
      plugin: this.plugin.name,
      mode: this.mode,
      enableAI: this.enableAI,
      confidenceThreshold: this.confidenceThreshold
    });
  }

  /**
   * Execute vulnerability analysis
   * @param {object} input - Input data
   * @returns {object} Analysis results
   */
  async execute(input) {
    return await this.executeTask(async (input) => {
      if (this.mode === 'dependency_analysis') {
        return await this.analyzeDependencies(input);
      } else {
        return await this.analyzeVulnerabilities(input);
      }
    }, input);
  }

  /**
   * Analyze vulnerabilities in parsed files
   * @param {object} input - Input containing parsedFiles
   * @returns {object} Vulnerability analysis results
   */
  async analyzeVulnerabilities(input) {
    this.validateInput(input, ['parsedFiles']);
    
    const { parsedFiles } = input;
    
    if (!Array.isArray(parsedFiles)) {
      throw new Error('parsedFiles must be an array');
    }

    this.log('info', `Starting vulnerability analysis on ${parsedFiles.length} files`);
    
    // Filter to successfully parsed files
    const validFiles = parsedFiles.filter(file => file.parseSuccess && file.parsed);
    
    this.log('info', `Analyzing ${validFiles.length} valid files`);
    
    // Analyze files for vulnerabilities
    const vulnerabilities = await this.analyzeFiles(validFiles);
    
    // Post-process vulnerabilities
    const processedVulnerabilities = await this.postProcessVulnerabilities(vulnerabilities);
    
    // Generate analysis statistics
    const stats = this.generateAnalysisStats(processedVulnerabilities, validFiles);
    
    return {
      vulnerabilities: processedVulnerabilities,
      stats,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Analyze dependencies for vulnerabilities
   * @param {object} input - Input containing repositoryPath
   * @returns {object} Dependency analysis results
   */
  async analyzeDependencies(input) {
    this.validateInput(input, ['repositoryPath']);
    
    const { repositoryPath } = input;
    
    this.log('info', `Starting dependency analysis for ${repositoryPath}`);
    
    // Use plugin to analyze dependencies
    const dependencyVulnerabilities = await this.plugin.analyzeDependencies(repositoryPath);
    
    // Generate dependency statistics
    const stats = this.generateDependencyStats(dependencyVulnerabilities);
    
    return {
      vulnerabilities: dependencyVulnerabilities,
      stats,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Analyze files for vulnerabilities
   * @param {Array} files - Files to analyze
   * @returns {Array} Found vulnerabilities
   */
  async analyzeFiles(files) {
    const allVulnerabilities = [];
    
    const analyzeFile = async (file, index) => {
      try {
        this.log('info', `Analyzing file ${index + 1}/${files.length}: ${file.relativePath}`);
        
        // Create analysis context
        const context = {
          filePath: file.path,
          relativePath: file.relativePath,
          fileType: file.type,
          language: file.language,
          size: file.size,
          plugin: this.plugin.name
        };
        
        // Use plugin to detect vulnerabilities
        const vulnerabilities = await this.plugin.detectVulnerabilities(file.parsed, context);
        
        // Add file context to each vulnerability
        const contextualizedVulnerabilities = vulnerabilities.map(vuln => ({
          ...vuln,
          file: file.path,
          relativePath: file.relativePath,
          evidence: vuln.evidence, // Ensure evidence is at the top level
          context: { ...context, ...vuln.context }
        }));
        
        this.log('info', `Found ${vulnerabilities.length} vulnerabilities in ${file.relativePath}`);
        
        return contextualizedVulnerabilities;
      } catch (error) {
        this.log('error', `Failed to analyze file: ${file.relativePath}`, { 
          error: error.message 
        });
        return [];
      }
    };

    // Process files in parallel
    const results = await this.processInParallel(files, analyzeFile, this.concurrency);
    
    // Flatten results
    for (const fileVulnerabilities of results) {
      allVulnerabilities.push(...fileVulnerabilities);
    }
    
    this.log('info', `Found ${allVulnerabilities.length} total vulnerabilities`);
    
    return allVulnerabilities;
  }

  /**
   * Post-process vulnerabilities for deduplication and enhancement
   * @param {Array} vulnerabilities - Raw vulnerabilities
   * @returns {Array} Processed vulnerabilities
   */
  async postProcessVulnerabilities(vulnerabilities) {
    // Remove duplicates
    const deduplicated = this.deduplicateVulnerabilities(vulnerabilities);
    
    // Filter by confidence threshold
    const filtered = deduplicated.filter(vuln => 
      vuln.confidence >= this.confidenceThreshold
    );
    
    // Enhance with additional context
    const enhanced = await this.enhanceVulnerabilities(filtered);
    
    // Sort by severity and confidence
    enhanced.sort((a, b) => {
      const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
      
      if (severityDiff !== 0) {
        return severityDiff;
      }
      
      return b.confidence - a.confidence;
    });
    
    return enhanced;
  }

  /**
   * Deduplicate vulnerabilities
   * @param {Array} vulnerabilities - Vulnerabilities to deduplicate
   * @returns {Array} Deduplicated vulnerabilities
   */
  deduplicateVulnerabilities(vulnerabilities) {
    const seen = new Map();
    
    for (const vuln of vulnerabilities) {
      // Create a unique key for the vulnerability
      const key = `${vuln.type}:${vuln.file}:${vuln.line}:${vuln.column}`;
      
      if (!seen.has(key)) {
        seen.set(key, vuln);
      }
    }
    
    const unique = Array.from(seen.values());
    this.log('info', `Deduplicated ${vulnerabilities.length} to ${unique.length} vulnerabilities`);
    
    return unique;
  }

  /**
   * Enhance vulnerabilities with additional context
   * @param {Array} vulnerabilities - Vulnerabilities to enhance
   * @returns {Array} Enhanced vulnerabilities
   */
  async enhanceVulnerabilities(vulnerabilities) {
    const enhanced = [];
    
    for (const vuln of vulnerabilities) {
      const enhancedVuln = {
        ...vuln,
        id: this.generateVulnerabilityId(vuln),
        evidence: vuln.evidence, // Explicitly include evidence
        discoveredBy: this.id,
        discoveredAt: new Date().toISOString(),
        risk: this.calculateRisk(vuln),
        remediation: await this.generateRemediation(vuln)
      };
      
      enhanced.push(enhancedVuln);
    }
    
    return enhanced;
  }

  /**
   * Generate unique vulnerability ID
   * @param {object} vulnerability - Vulnerability object
   * @returns {string} Unique ID
   */
  generateVulnerabilityId(vulnerability) {
    const hash = this.simpleHash(
      `${vulnerability.type}:${vulnerability.file}:${vulnerability.line}:${vulnerability.description}`
    );
    return `vuln-${hash}`;
  }

  /**
   * Simple hash function
   * @param {string} str - String to hash
   * @returns {string} Hash
   */
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Calculate risk score for vulnerability
   * @param {object} vulnerability - Vulnerability object
   * @returns {number} Risk score (0-100)
   */
  calculateRisk(vulnerability) {
    const severityScores = { CRITICAL: 25, HIGH: 20, MEDIUM: 15, LOW: 10 };
    const confidenceMultiplier = vulnerability.confidence || 0.5;
    
    const baseScore = severityScores[vulnerability.severity] || 5;
    const riskScore = Math.round(baseScore * confidenceMultiplier * 4);
    
    return Math.min(riskScore, 100);
  }

  /**
   * Generate remediation advice for vulnerability
   * @param {object} vulnerability - Vulnerability object
   * @returns {string} Remediation advice
   */
  async generateRemediation(vulnerability) {
    // Use plugin's remediation if available
    if (vulnerability.remediation) {
      return vulnerability.remediation;
    }
    
    // Generate generic remediation based on type
    const genericRemediations = {
      'SQL_INJECTION': 'Use parameterized queries or prepared statements instead of string concatenation',
      'XSS': 'Escape output data and validate input data',
      'PATH_TRAVERSAL': 'Validate and sanitize file paths, use allow-lists for permitted directories',
      'COMMAND_INJECTION': 'Avoid executing system commands with user input, use safe APIs instead',
      'LDAP_INJECTION': 'Use parameterized LDAP queries and input validation',
      'XXE': 'Disable external entity processing in XML parsers',
      'DESERIALIZATION': 'Avoid deserializing untrusted data, use safe serialization formats',
      'CRYPTO_WEAKNESS': 'Use strong, modern cryptographic algorithms and libraries'
    };
    
    return genericRemediations[vulnerability.type] || 'Review and remediate the identified security issue';
  }

  /**
   * Generate analysis statistics
   * @param {Array} vulnerabilities - Found vulnerabilities
   * @param {Array} files - Analyzed files
   * @returns {object} Analysis statistics
   */
  generateAnalysisStats(vulnerabilities, files) {
    const stats = {
      filesAnalyzed: files.length,
      vulnerabilitiesFound: vulnerabilities.length,
      riskScore: this.calculateOverallRisk(vulnerabilities),
      bySeverity: {},
      byType: {},
      byFile: {},
      averageConfidence: 0
    };

    let totalConfidence = 0;
    
    for (const vuln of vulnerabilities) {
      // Count by severity
      stats.bySeverity[vuln.severity] = (stats.bySeverity[vuln.severity] || 0) + 1;
      
      // Count by type
      stats.byType[vuln.type] = (stats.byType[vuln.type] || 0) + 1;
      
      // Count by file
      const fileName = vuln.relativePath || vuln.file;
      stats.byFile[fileName] = (stats.byFile[fileName] || 0) + 1;
      
      // Sum confidence
      totalConfidence += vuln.confidence || 0;
    }
    
    // Calculate average confidence
    stats.averageConfidence = vulnerabilities.length > 0 ? 
      totalConfidence / vulnerabilities.length : 0;
    
    return stats;
  }

  /**
   * Generate dependency analysis statistics
   * @param {Array} vulnerabilities - Dependency vulnerabilities
   * @returns {object} Dependency statistics
   */
  generateDependencyStats(vulnerabilities) {
    const stats = {
      dependencyVulnerabilities: vulnerabilities.length,
      riskScore: this.calculateOverallRisk(vulnerabilities),
      bySeverity: {},
      byType: {},
      uniqueDependencies: new Set()
    };

    for (const vuln of vulnerabilities) {
      // Count by severity
      stats.bySeverity[vuln.severity] = (stats.bySeverity[vuln.severity] || 0) + 1;
      
      // Count by type
      stats.byType[vuln.type] = (stats.byType[vuln.type] || 0) + 1;
      
      // Track unique dependencies
      if (vuln.dependency) {
        const depKey = `${vuln.dependency.groupId}:${vuln.dependency.artifactId}`;
        stats.uniqueDependencies.add(depKey);
      }
    }
    
    stats.uniqueDependencies = stats.uniqueDependencies.size;
    
    return stats;
  }

  /**
   * Calculate overall risk score
   * @param {Array} vulnerabilities - All vulnerabilities
   * @returns {number} Overall risk score
   */
  calculateOverallRisk(vulnerabilities) {
    if (vulnerabilities.length === 0) return 0;
    
    const severityScores = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
    let totalScore = 0;
    
    for (const vuln of vulnerabilities) {
      totalScore += severityScores[vuln.severity] || 0;
    }
    
    // Normalize to 0-100 scale
    const normalizedScore = Math.min(totalScore, 100);
    
    return normalizedScore;
  }

  /**
   * Filter vulnerabilities by criteria
   * @param {Array} vulnerabilities - Vulnerabilities to filter
   * @param {object} criteria - Filter criteria
   * @returns {Array} Filtered vulnerabilities
   */
  filterVulnerabilities(vulnerabilities, criteria) {
    return vulnerabilities.filter(vuln => {
      // Filter by severity
      if (criteria.severity && vuln.severity !== criteria.severity) {
        return false;
      }
      
      // Filter by type
      if (criteria.type && vuln.type !== criteria.type) {
        return false;
      }
      
      // Filter by minimum confidence
      if (criteria.minConfidence && vuln.confidence < criteria.minConfidence) {
        return false;
      }
      
      // Filter by file
      if (criteria.file && !vuln.file.includes(criteria.file)) {
        return false;
      }
      
      return true;
    });
  }

  /**
   * Get vulnerability summary
   * @param {Array} vulnerabilities - Vulnerabilities
   * @returns {object} Summary
   */
  getVulnerabilitySummary(vulnerabilities) {
    const summary = {
      total: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      topTypes: {},
      mostVulnerableFiles: {}
    };

    for (const vuln of vulnerabilities) {
      // Count by severity
      summary[vuln.severity.toLowerCase()]++;
      
      // Count by type
      summary.topTypes[vuln.type] = (summary.topTypes[vuln.type] || 0) + 1;
      
      // Count by file
      const fileName = vuln.relativePath || vuln.file;
      summary.mostVulnerableFiles[fileName] = (summary.mostVulnerableFiles[fileName] || 0) + 1;
    }

    return summary;
  }

  /**
   * Clean up analyzer agent resources
   */
  async cleanup() {
    await super.cleanup();
    this.log('info', 'Analyzer agent cleaned up');
  }
}

export default AnalyzerAgent;