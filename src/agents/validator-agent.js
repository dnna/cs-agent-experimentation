import { BaseAgent } from './base-agent.js';
import { llmService } from '../core/llm-service.js';

/**
 * Validator agent for validating and scoring vulnerabilities
 */
export class ValidatorAgent extends BaseAgent {
  constructor(id, config = {}, sessionId = null) {
    super(id, config, sessionId);
    this.plugin = config.plugin;
    this.falsePositiveThreshold = config.falsePositiveThreshold || 0.3;
    this.enableAI = true; // Always use LLM for validation
    this.concurrency = config.concurrency || 5;
    this.llmService = llmService;
  }

  /**
   * Initialize the validator agent
   */
  async initialize() {
    if (this.initialized) return;

    if (!this.plugin) {
      throw new Error('Validator agent requires a language plugin');
    }

    // Initialize LLM service if enabled
    if (this.enableAI) {
      try {
        await this.llmService.initialize();
        this.log('info', 'LLM service initialized for validation');
      } catch (error) {
        this.log('warn', 'LLM initialization failed, falling back to heuristics', { error: error.message });
        this.enableAI = false;
      }
    }

    await super.initialize();
    this.log('info', 'Validator agent initialized', { 
      plugin: this.plugin.name,
      falsePositiveThreshold: this.falsePositiveThreshold,
      enableAI: this.enableAI
    });
  }

  /**
   * Execute vulnerability validation
   * @param {object} input - Input containing vulnerabilities
   * @returns {object} Validation results
   */
  async execute(input) {
    return await this.executeTask(async (input) => {
      this.validateInput(input, ['vulnerabilities']);
      
      const { vulnerabilities } = input;
      
      if (!Array.isArray(vulnerabilities)) {
        throw new Error('Vulnerabilities must be an array');
      }

      this.log('info', `Starting validation of ${vulnerabilities.length} vulnerabilities`);
      
      // Validate vulnerabilities
      const validatedVulnerabilities = await this.validateVulnerabilities(vulnerabilities);
      
      // Generate validation statistics
      const stats = this.generateValidationStats(vulnerabilities, validatedVulnerabilities);
      
      return {
        vulnerabilities: validatedVulnerabilities,
        stats,
        timestamp: new Date().toISOString()
      };
    }, input);
  }

  /**
   * Validate vulnerabilities
   * @param {Array} vulnerabilities - Vulnerabilities to validate
   * @returns {Array} Validated vulnerabilities
   */
  async validateVulnerabilities(vulnerabilities) {
    const validateVulnerability = async (vulnerability, index) => {
      try {
        this.log('info', `Validating vulnerability ${index + 1}/${vulnerabilities.length}: ${vulnerability.type}`);
        
        // Perform multiple validation checks
        const validation = await this.performValidation(vulnerability);
        
        // Calculate final confidence score
        const finalConfidence = this.calculateFinalConfidence(vulnerability, validation);
        
        // Determine if vulnerability is valid
        const isValid = finalConfidence >= this.falsePositiveThreshold;
        
        if (isValid) {
          return {
            ...vulnerability,
            confidence: finalConfidence,
            validation: {
              ...validation,
              isValid: true,
              validatedAt: new Date().toISOString(),
              validatedBy: this.id
            }
          };
        } else {
          this.log('info', `Vulnerability marked as false positive: ${vulnerability.type} in ${vulnerability.relativePath}`);
          return null; // Filter out false positives
        }
      } catch (error) {
        this.log('error', `Failed to validate vulnerability: ${vulnerability.type}`, { 
          error: error.message 
        });
        
        // Return original vulnerability with validation error
        return {
          ...vulnerability,
          validation: {
            isValid: false,
            error: error.message,
            validatedAt: new Date().toISOString(),
            validatedBy: this.id
          }
        };
      }
    };

    // Process vulnerabilities in parallel
    const results = await this.processInParallel(vulnerabilities, validateVulnerability, this.concurrency);
    
    // Filter out null results (false positives)
    const validVulnerabilities = results.filter(vuln => vuln !== null);
    
    this.log('info', `Validated ${validVulnerabilities.length} vulnerabilities (${vulnerabilities.length - validVulnerabilities.length} false positives)`);
    
    return validVulnerabilities;
  }

  /**
   * Perform validation checks on a vulnerability
   * @param {object} vulnerability - Vulnerability to validate
   * @returns {object} Validation results
   */
  async performValidation(vulnerability) {
    const validation = {
      contextCheck: await this.validateContext(vulnerability),
      patternCheck: await this.validatePattern(vulnerability),
      semanticCheck: await this.validateSemantic(vulnerability),
      riskAssessment: await this.assessRisk(vulnerability)
    };

    // Add LLM-based validation if enabled
    if (this.enableAI) {
      try {
        validation.llmValidation = await this.validateWithLLM(vulnerability);
      } catch (error) {
        this.log('warn', `LLM validation failed for ${vulnerability.type}`, { error: error.message });
        validation.llmValidation = {
          isValid: true, // Default to valid if LLM fails
          confidence: 0.5,
          reasoning: 'LLM validation failed',
          error: error.message
        };
      }
    }

    return validation;
  }

  /**
   * Validate vulnerability using LLM
   * @param {object} vulnerability - Vulnerability to validate
   * @returns {object} LLM validation results
   */
  async validateWithLLM(vulnerability) {
    if (!this.enableAI) {
      return null;
    }

    try {
      // Get surrounding code context for better validation
      const context = await this.getValidationContext(vulnerability);
      
      const validation = await this.llmService.validateVulnerability(vulnerability, context);
      
      this.log('info', `LLM validation completed for ${vulnerability.type}`, {
        isValid: validation.isValid,
        confidence: validation.confidence,
        riskLevel: validation.riskLevel
      });
      
      return validation;
    } catch (error) {
      this.log('error', `LLM validation failed for ${vulnerability.type}`, { error: error.message });
      throw error;
    }
  }

  /**
   * Get validation context for LLM
   * @param {object} vulnerability - Vulnerability to get context for
   * @returns {object} Validation context
   */
  async getValidationContext(vulnerability) {
    return {
      language: 'java',
      filePath: vulnerability.file || vulnerability.relativePath,
      method: vulnerability.method,
      framework: vulnerability.context?.framework || 'Java',
      code: vulnerability.context?.evidence || vulnerability.evidence || '',
      dependencies: vulnerability.context?.dependencies || [],
      fileType: vulnerability.context?.fileType || 'source',
      plugin: this.plugin.name
    };
  }

  /**
   * Validate vulnerability context
   * @param {object} vulnerability - Vulnerability to validate
   * @returns {object} Context validation results
   */
  async validateContext(vulnerability) {
    const context = vulnerability.context || {};
    
    // Check if vulnerability is in test code
    const isTestCode = this.isTestCode(vulnerability.file || vulnerability.relativePath);
    
    // Check if vulnerability is in generated code
    const isGeneratedCode = this.isGeneratedCode(vulnerability.file || vulnerability.relativePath);
    
    // Check if vulnerability is in dead code
    const isDeadCode = await this.isDeadCode(vulnerability, context);
    
    // Check if vulnerability has proper context
    const hasProperContext = this.hasProperContext(vulnerability);
    
    return {
      isTestCode,
      isGeneratedCode,
      isDeadCode,
      hasProperContext,
      score: this.calculateContextScore(isTestCode, isGeneratedCode, isDeadCode, hasProperContext)
    };
  }

  /**
   * Validate vulnerability pattern
   * @param {object} vulnerability - Vulnerability to validate
   * @returns {object} Pattern validation results
   */
  async validatePattern(vulnerability) {
    // Get vulnerability patterns from plugin
    const patterns = this.plugin.getVulnerabilityPatterns();
    const vulnPatterns = patterns[vulnerability.type] || [];
    
    // Check if vulnerability matches known patterns
    const patternMatches = vulnPatterns.filter(pattern => {
      if (vulnerability.evidence && pattern.pattern) {
        return pattern.pattern.test(vulnerability.evidence);
      }
      return false;
    });
    
    // Check for known false positive patterns
    const falsePositivePatterns = this.getFalsePositivePatterns(vulnerability.type);
    const isFalsePositive = falsePositivePatterns.some(pattern => {
      if (vulnerability.evidence) {
        return pattern.test(vulnerability.evidence);
      }
      return false;
    });
    
    return {
      matchesKnownPatterns: patternMatches.length > 0,
      matchedPatterns: patternMatches.length,
      isFalsePositive,
      score: this.calculatePatternScore(patternMatches.length, isFalsePositive)
    };
  }

  /**
   * Validate vulnerability semantics
   * @param {object} vulnerability - Vulnerability to validate
   * @returns {object} Semantic validation results
   */
  async validateSemantic(vulnerability) {
    // Check if vulnerability has semantic context
    const hasSemanticContext = this.hasSemanticContext(vulnerability);
    
    // Check for input validation
    const hasInputValidation = await this.checkInputValidation(vulnerability);
    
    // Check for output encoding
    const hasOutputEncoding = await this.checkOutputEncoding(vulnerability);
    
    // Check for security controls
    const hasSecurityControls = await this.checkSecurityControls(vulnerability);
    
    return {
      hasSemanticContext,
      hasInputValidation,
      hasOutputEncoding,
      hasSecurityControls,
      score: this.calculateSemanticScore(hasSemanticContext, hasInputValidation, hasOutputEncoding, hasSecurityControls)
    };
  }

  /**
   * Assess vulnerability risk
   * @param {object} vulnerability - Vulnerability to assess
   * @returns {object} Risk assessment results
   */
  async assessRisk(vulnerability) {
    // Calculate exploitability score
    const exploitability = this.calculateExploitability(vulnerability);
    
    // Calculate impact score
    const impact = this.calculateImpact(vulnerability);
    
    // Calculate likelihood score
    const likelihood = this.calculateLikelihood(vulnerability);
    
    // Calculate overall risk score
    const riskScore = (exploitability + impact + likelihood) / 3;
    
    return {
      exploitability,
      impact,
      likelihood,
      riskScore,
      riskLevel: this.getRiskLevel(riskScore)
    };
  }

  /**
   * Calculate final confidence score
   * @param {object} vulnerability - Original vulnerability
   * @param {object} validation - Validation results
   * @returns {number} Final confidence score
   */
  calculateFinalConfidence(vulnerability, validation) {
    const originalConfidence = vulnerability.confidence || 0.5;
    
    // Weight factors
    const weights = {
      context: 0.3,
      pattern: 0.4,
      semantic: 0.2,
      risk: 0.1
    };
    
    // Calculate weighted score
    const weightedScore = (
      validation.contextCheck.score * weights.context +
      validation.patternCheck.score * weights.pattern +
      validation.semanticCheck.score * weights.semantic +
      validation.riskAssessment.riskScore * weights.risk
    );
    
    // Combine with original confidence
    const finalConfidence = (originalConfidence * 0.3) + (weightedScore * 0.7);
    
    return Math.min(Math.max(finalConfidence, 0), 1);
  }

  /**
   * Check if file is test code
   * @param {string} filePath - File path
   * @returns {boolean} True if test code
   */
  isTestCode(filePath) {
    const testPatterns = [
      /\/test\//,
      /\/tests\//,
      /Test\.java$/,
      /Tests\.java$/,
      /TestCase\.java$/,
      /Spec\.java$/
    ];
    
    return testPatterns.some(pattern => pattern.test(filePath));
  }

  /**
   * Check if file is generated code
   * @param {string} filePath - File path
   * @returns {boolean} True if generated code
   */
  isGeneratedCode(filePath) {
    const generatedPatterns = [
      /\/generated\//,
      /\/target\/generated-sources\//,
      /\/build\/generated\//,
      /Generated\.java$/,
      /\.generated\./
    ];
    
    return generatedPatterns.some(pattern => pattern.test(filePath));
  }

  /**
   * Check if code is dead/unreachable
   * @param {object} vulnerability - Vulnerability
   * @param {object} context - Context
   * @returns {boolean} True if dead code
   */
  async isDeadCode(vulnerability, context) {
    // Simple heuristic - check if method is private and unused
    // In a real implementation, this would require more sophisticated analysis
    return false;
  }

  /**
   * Check if vulnerability has proper context
   * @param {object} vulnerability - Vulnerability
   * @returns {boolean} True if has proper context
   */
  hasProperContext(vulnerability) {
    return !!(vulnerability.context && 
             vulnerability.line && 
             vulnerability.file && 
             vulnerability.evidence);
  }

  /**
   * Calculate context score
   * @param {boolean} isTestCode - Is test code
   * @param {boolean} isGeneratedCode - Is generated code
   * @param {boolean} isDeadCode - Is dead code
   * @param {boolean} hasProperContext - Has proper context
   * @returns {number} Context score
   */
  calculateContextScore(isTestCode, isGeneratedCode, isDeadCode, hasProperContext) {
    let score = 0.5;
    
    if (isTestCode) score -= 0.3;
    if (isGeneratedCode) score -= 0.4;
    if (isDeadCode) score -= 0.5;
    if (hasProperContext) score += 0.2;
    
    return Math.min(Math.max(score, 0), 1);
  }

  /**
   * Calculate pattern score
   * @param {number} matchedPatterns - Number of matched patterns
   * @param {boolean} isFalsePositive - Is false positive
   * @returns {number} Pattern score
   */
  calculatePatternScore(matchedPatterns, isFalsePositive) {
    let score = 0.5;
    
    if (matchedPatterns > 0) {
      score += Math.min(matchedPatterns * 0.2, 0.4);
    }
    
    if (isFalsePositive) {
      score -= 0.6;
    }
    
    return Math.min(Math.max(score, 0), 1);
  }

  /**
   * Calculate semantic score
   * @param {boolean} hasSemanticContext - Has semantic context
   * @param {boolean} hasInputValidation - Has input validation
   * @param {boolean} hasOutputEncoding - Has output encoding
   * @param {boolean} hasSecurityControls - Has security controls
   * @returns {number} Semantic score
   */
  calculateSemanticScore(hasSemanticContext, hasInputValidation, hasOutputEncoding, hasSecurityControls) {
    let score = 0.5;
    
    if (hasSemanticContext) score += 0.1;
    if (!hasInputValidation) score += 0.2;
    if (!hasOutputEncoding) score += 0.2;
    if (!hasSecurityControls) score += 0.1;
    
    return Math.min(Math.max(score, 0), 1);
  }

  /**
   * Check if vulnerability has semantic context
   * @param {object} vulnerability - Vulnerability
   * @returns {boolean} True if has semantic context
   */
  hasSemanticContext(vulnerability) {
    return !!(vulnerability.context && 
             vulnerability.context.method && 
             vulnerability.description);
  }

  /**
   * Check for input validation
   * @param {object} vulnerability - Vulnerability
   * @returns {boolean} True if has input validation
   */
  async checkInputValidation(vulnerability) {
    // Check if evidence contains validation patterns
    const validationPatterns = [
      /validate\(/,
      /sanitize\(/,
      /escape\(/,
      /filter\(/,
      /isValid\(/,
      /Pattern\.matches\(/,
      /Validator\./
    ];
    
    const evidence = vulnerability.evidence || '';
    return validationPatterns.some(pattern => pattern.test(evidence));
  }

  /**
   * Check for output encoding
   * @param {object} vulnerability - Vulnerability
   * @returns {boolean} True if has output encoding
   */
  async checkOutputEncoding(vulnerability) {
    // Check if evidence contains encoding patterns
    const encodingPatterns = [
      /encode\(/,
      /escape\(/,
      /ESAPI\./,
      /StringEscapeUtils\./,
      /HtmlUtils\./,
      /c:out/
    ];
    
    const evidence = vulnerability.evidence || '';
    return encodingPatterns.some(pattern => pattern.test(evidence));
  }

  /**
   * Check for security controls
   * @param {object} vulnerability - Vulnerability
   * @returns {boolean} True if has security controls
   */
  async checkSecurityControls(vulnerability) {
    // Check if evidence contains security control patterns
    const securityPatterns = [
      /authentication/i,
      /authorization/i,
      /security/i,
      /csrf/i,
      /xss/i,
      /sanitizer/i,
      /@PreAuthorize/,
      /@Secured/,
      /@RolesAllowed/
    ];
    
    const evidence = vulnerability.evidence || '';
    return securityPatterns.some(pattern => pattern.test(evidence));
  }

  /**
   * Calculate exploitability score
   * @param {object} vulnerability - Vulnerability
   * @returns {number} Exploitability score
   */
  calculateExploitability(vulnerability) {
    const exploitabilityScores = {
      'SQL_INJECTION': 0.9,
      'XSS': 0.8,
      'COMMAND_INJECTION': 0.9,
      'PATH_TRAVERSAL': 0.7,
      'DESERIALIZATION': 0.8,
      'XXE': 0.6,
      'SSRF': 0.7,
      'LDAP_INJECTION': 0.6
    };
    
    return exploitabilityScores[vulnerability.type] || 0.5;
  }

  /**
   * Calculate impact score
   * @param {object} vulnerability - Vulnerability
   * @returns {number} Impact score
   */
  calculateImpact(vulnerability) {
    const impactScores = {
      'CRITICAL': 1.0,
      'HIGH': 0.8,
      'MEDIUM': 0.6,
      'LOW': 0.4
    };
    
    return impactScores[vulnerability.severity] || 0.5;
  }

  /**
   * Calculate likelihood score
   * @param {object} vulnerability - Vulnerability
   * @returns {number} Likelihood score
   */
  calculateLikelihood(vulnerability) {
    let likelihood = 0.5;
    
    // Higher likelihood for web-facing components
    if (vulnerability.context?.fileType === 'controller') {
      likelihood += 0.3;
    }
    
    // Higher likelihood for public methods
    if (vulnerability.context?.method?.includes('public')) {
      likelihood += 0.2;
    }
    
    // Lower likelihood for internal components
    if (vulnerability.context?.fileType === 'service') {
      likelihood -= 0.1;
    }
    
    return Math.min(Math.max(likelihood, 0), 1);
  }

  /**
   * Get risk level from score
   * @param {number} riskScore - Risk score
   * @returns {string} Risk level
   */
  getRiskLevel(riskScore) {
    if (riskScore >= 0.8) return 'CRITICAL';
    if (riskScore >= 0.6) return 'HIGH';
    if (riskScore >= 0.4) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Get false positive patterns for vulnerability type
   * @param {string} type - Vulnerability type
   * @returns {Array} False positive patterns
   */
  getFalsePositivePatterns(type) {
    const patterns = {
      'SQL_INJECTION': [
        /PreparedStatement.*setString/,
        /\?.*parameter/,
        /createQuery.*:parameter/
      ],
      'XSS': [
        /StringEscapeUtils\.escapeHtml/,
        /ESAPI\.encoder/,
        /c:out.*escapeXml/
      ],
      'PATH_TRAVERSAL': [
        /Paths\.get.*normalize/,
        /File.*getCanonicalPath/,
        /validatePath/
      ]
    };
    
    return patterns[type] || [];
  }

  /**
   * Generate validation statistics
   * @param {Array} original - Original vulnerabilities
   * @param {Array} validated - Validated vulnerabilities
   * @returns {object} Validation statistics
   */
  generateValidationStats(original, validated) {
    const stats = {
      original: original.length,
      validated: validated.length,
      falsePositives: original.length - validated.length,
      falsePositiveRate: original.length > 0 ? 
        ((original.length - validated.length) / original.length) * 100 : 0,
      averageConfidence: 0,
      confidenceDistribution: { low: 0, medium: 0, high: 0 }
    };

    let totalConfidence = 0;
    
    for (const vuln of validated) {
      totalConfidence += vuln.confidence;
      
      // Confidence distribution
      if (vuln.confidence >= 0.8) {
        stats.confidenceDistribution.high++;
      } else if (vuln.confidence >= 0.5) {
        stats.confidenceDistribution.medium++;
      } else {
        stats.confidenceDistribution.low++;
      }
    }
    
    stats.averageConfidence = validated.length > 0 ? 
      totalConfidence / validated.length : 0;
    
    return stats;
  }

  /**
   * Clean up validator agent resources
   */
  async cleanup() {
    await super.cleanup();
    this.log('info', 'Validator agent cleaned up');
  }
}

export default ValidatorAgent;