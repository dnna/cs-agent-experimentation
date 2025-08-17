import { ChatOpenAI } from '@langchain/openai';
import { ChatAnthropic } from '@langchain/anthropic';
import { ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { HumanMessage, SystemMessage } from '@langchain/core/messages';
import { z } from 'zod';
import { logger } from './logger.js';

/**
 * Vulnerability schema for structured output
 */
// Provider-specific vulnerability schemas
const VulnerabilitySchemaOpenAI = z.object({
  type: z.string().describe('Vulnerability type (e.g., SQL_INJECTION, XSS, PATH_TRAVERSAL)'),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).describe('Severity level'),
  confidence: z.number().min(0).max(1).describe('Confidence score from 0.0 to 1.0'),
  line: z.number().nullable().describe('Line number where vulnerability occurs'),
  description: z.string().describe('Clear description of the vulnerability'),
  cwe: z.number().nullable().describe('CWE ID if applicable'),
  evidence: z.string().describe('Specific code snippet demonstrating the vulnerability'),
  remediation: z.string().describe('Specific remediation advice')
});

// Gemini doesn't support nullable in the same way, use optional instead
const VulnerabilitySchemaGemini = z.object({
  type: z.string().describe('Vulnerability type (e.g., SQL_INJECTION, XSS, PATH_TRAVERSAL)'),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).describe('Severity level'),
  confidence: z.number().min(0).max(1).describe('Confidence score from 0.0 to 1.0'),
  line: z.number().optional().describe('Line number where vulnerability occurs'),
  description: z.string().describe('Clear description of the vulnerability'),
  cwe: z.number().optional().describe('CWE ID if applicable'),
  evidence: z.string().describe('Specific code snippet demonstrating the vulnerability'),
  remediation: z.string().describe('Specific remediation advice')
});

// We'll select the appropriate schema in the methods based on provider

/**
 * Validation result schema
 */
const ValidationSchema = z.object({
  isValid: z.boolean().describe('True if legitimate vulnerability, false if false positive'),
  confidence: z.number().min(0).max(1).describe('Confidence in the assessment from 0.0 to 1.0'),
  reasoning: z.string().describe('Detailed explanation of the assessment'),
  riskLevel: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).describe('Risk level assessment'),
  exploitability: z.number().min(0).max(1).describe('How easily exploitable (0.0 to 1.0)'),
  impact: z.number().min(0).max(1).describe('Potential impact if exploited (0.0 to 1.0)'),
  recommendations: z.array(z.string()).describe('Specific remediation steps')
});

/**
 * Remediation schema
 */
const RemediationSchema = z.object({
  immediate: z.array(z.object({
    priority: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    action: z.string(),
    details: z.string(),
    affected: z.string()
  })).describe('Immediate actions to take'),
  shortTerm: z.array(z.object({
    priority: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    action: z.string(),
    timeline: z.string(),
    resources: z.string()
  })).describe('Short-term improvements'),
  longTerm: z.array(z.object({
    priority: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    action: z.string(),
    timeline: z.string(),
    resources: z.string()
  })).describe('Long-term strategic improvements'),
  general: z.array(z.string()).describe('General security best practices'),
  tools: z.array(z.string()).describe('Recommended security tools'),
  training: z.array(z.string()).describe('Security training recommendations')
});

/**
 * LLM Service abstraction layer using LangChain
 * Provides consistent interface across different LLM providers
 */
export class LLMService {
  constructor(config = {}) {
    const provider = config.provider || process.env.LLM_PROVIDER || 'openai';
    this.config = {
      provider,
      model: config.model || process.env.LLM_MODEL || this.getDefaultModel(provider),
      temperature: config.temperature || 0.1,
      maxTokens: config.maxTokens || 2000,
      timeout: config.timeout || 30000,
      ...config
    };
    
    this.llm = null;
    this.initialized = false;
  }

  /**
   * Initialize the LLM service
   */
  async initialize() {
    if (this.initialized) return;

    try {
      this.llm = await this.createLLMInstance();
      this.initialized = true;
      logger.log(`[LLMService] Initialized with provider: ${this.config.provider}, model: ${this.config.model}`);
    } catch (error) {
      logger.error('[LLMService] Failed to initialize:', error.message);
      throw error;
    }
  }

  /**
   * Create LLM instance based on provider
   */
  async createLLMInstance() {
    switch (this.config.provider) {
      case 'openai':
        const openAIConfig = {
          model: this.config.model,
          timeout: this.config.timeout,
          apiKey: process.env.OPENAI_API_KEY
        };
        
        // Add GPT-5 specific parameters for faster responses
        if (this.config.model && this.config.model.includes('gpt-5')) {
          openAIConfig.modelKwargs = {
            reasoning_effort: 'minimal',  // Minimize reasoning for faster responses
            verbosity: 'low'  // Shorter responses
          };
        }
        
        return new ChatOpenAI(openAIConfig);

      case 'anthropic':
        return new ChatAnthropic({
          model: this.config.model,
          temperature: this.config.temperature,
          maxTokens: this.config.maxTokens,
          timeout: this.config.timeout,
          apiKey: process.env.ANTHROPIC_API_KEY
        });

      case 'google':
        return new ChatGoogleGenerativeAI({
          model: this.config.model,
          temperature: this.config.temperature,
          maxOutputTokens: this.config.maxTokens,
          apiKey: process.env.GOOGLE_API_KEY
        });

      default:
        throw new Error(`Unsupported LLM provider: ${this.config.provider}`);
    }
  }

  /**
   * Get default model for provider
   */
  getDefaultModel(provider) {
    const defaults = {
      openai: 'gpt-5-mini',
      anthropic: 'claude-3-sonnet-20240229',
      google: 'gemini-2.5-flash'
    };
    
    return defaults[provider] || 'gpt-5-mini';
  }

  /**
   * Send a message to the LLM
   * @param {string} systemPrompt - System prompt
   * @param {string} userPrompt - User prompt
   * @param {object} options - Additional options
   * @returns {Promise<string>} LLM response
   */
  async chat(systemPrompt, userPrompt, options = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      const messages = [
        new SystemMessage(systemPrompt),
        new HumanMessage(userPrompt)
      ];

      const response = await this.llm.invoke(messages, {
        ...options
      });

      return response.content;
    } catch (error) {
      logger.error('[LLMService] Chat failed:', error.message);
      throw error;
    }
  }

  /**
   * Analyze multiple code segments in batch for better efficiency
   * @param {Array} codeSegments - Array of {code, context} objects
   * @returns {Promise<Array>} Array of vulnerability arrays
   */
  async analyzeVulnerabilitiesBatch(codeSegments) {
    if (!this.initialized) {
      await this.initialize();
    }

    const results = [];
    const batchSize = 3; // Process 3 code segments per LLM call
    
    for (let i = 0; i < codeSegments.length; i += batchSize) {
      const batch = codeSegments.slice(i, i + batchSize);
      
      const systemPrompt = `You are an expert security analyst specializing in code security vulnerabilities.

Your task is to analyze multiple code segments for security vulnerabilities following the OWASP Top 10 and CWE classifications.

Focus on these vulnerability types:
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Path Traversal (CWE-22)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)
- XML External Entity (CWE-611)
- Broken Authentication (CWE-287)
- Sensitive Data Exposure (CWE-200)
- Broken Access Control (CWE-284)
- Security Misconfiguration (CWE-16)

Return an array of vulnerability arrays, one for each code segment. Return an empty array for segments with no vulnerabilities.`;

      let userPrompt = `Analyze these code segments for security vulnerabilities:

${batch.map((segment, index) => `
**Code Segment ${index + 1}:**
File: ${segment.context.filePath || 'unknown'}
Method: ${segment.context.method || 'unknown'}
Framework: ${segment.context.framework || 'unknown'}

\`\`\`${segment.context.language || 'java'}
${segment.code}
\`\`\`
`).join('')}

Return a JSON array where each element is an array of vulnerabilities for the corresponding code segment.`;

      // Add provider-specific prompt adjustments
      if (this.config.provider === 'google') {
        // Gemini sometimes has issues with complex nested structures, so add more explicit instructions
        userPrompt += '\n\nIMPORTANT: Ensure all string values are properly escaped and terminated. Do not include line breaks within string values.';
      }

      try {
        // Select schema based on provider
        const VulnerabilitySchema = this.config.provider === 'google' ? VulnerabilitySchemaGemini : VulnerabilitySchemaOpenAI;
        
        const BatchVulnerabilitySchema = z.object({
          results: z.array(z.array(VulnerabilitySchema)).describe('Array of vulnerability arrays, one for each code segment')
        });
        
        const structuredLLM = this.llm.withStructuredOutput(BatchVulnerabilitySchema);
        
        const response = await structuredLLM.invoke([
          new SystemMessage(systemPrompt),
          new HumanMessage(userPrompt)
        ], {
          temperature: 0.1
        });

        logger.log(`[LLMService] Batch analysis completed for ${batch.length} segments`);
        
        // Add metadata to each vulnerability in each result
        const batchResults = response.results.map((segmentVulns, batchIndex) => {
          const segment = batch[batchIndex];
          return segmentVulns.map(vuln => ({
            ...vuln,
            id: this.generateVulnerabilityId(),
            discoveredBy: 'llm-batch-analysis',
            discoveredAt: new Date().toISOString(),
            context: {
              ...segment.context,
              llmProvider: this.config.provider,
              llmModel: this.config.model
            }
          }));
        });
        
        results.push(...batchResults);
        
      } catch (error) {
        logger.error(`[LLMService] Batch vulnerability analysis failed:`, error.message);
        
        // Check if it's a JSON parsing error and retry with fallback approach
        if (error.message.includes('JSON') || error.message.includes('Unterminated string')) {
          logger.log(`[LLMService] Retrying batch with individual analysis due to JSON error`);
          
          try {
            // Fallback: analyze each segment individually
            const fallbackResults = [];
            for (const segment of batch) {
              try {
                const individualResult = await this.analyzeVulnerabilities(segment.code, segment.context);
                fallbackResults.push(individualResult);
              } catch (segmentError) {
                logger.error(`[LLMService] Individual segment analysis failed:`, segmentError.message);
                fallbackResults.push([]);
              }
            }
            results.push(...fallbackResults);
          } catch (fallbackError) {
            logger.error(`[LLMService] Fallback analysis also failed:`, fallbackError.message);
            // Add empty arrays for failed batch
            results.push(...batch.map(() => []));
          }
        } else {
          // Add empty arrays for failed batch
          results.push(...batch.map(() => []));
        }
      }
    }
    
    return results;
  }

  /**
   * Analyze code for vulnerabilities using structured output
   * @param {string} code - Code to analyze
   * @param {object} context - Analysis context
   * @returns {Promise<Array>} Vulnerabilities found
   */
  async analyzeVulnerabilities(code, context = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const systemPrompt = `You are an expert security analyst specializing in ${context.language || 'code'} security vulnerabilities.

Your task is to analyze source code for security vulnerabilities following the OWASP Top 10 and CWE classifications.

Focus on these vulnerability types:
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Path Traversal (CWE-22)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)
- XML External Entity (CWE-611)
- Broken Authentication (CWE-287)
- Sensitive Data Exposure (CWE-200)
- Broken Access Control (CWE-284)
- Security Misconfiguration (CWE-16)

Return an empty array if no vulnerabilities are found.`;

    const userPrompt = `Analyze this ${context.language || 'code'} code for security vulnerabilities:

File: ${context.filePath || 'unknown'}
Method: ${context.method || 'unknown'}

\`\`\`${context.language || 'code'}
${code}
\`\`\`

Context information:
- File type: ${context.fileType || 'source'}
- Framework: ${context.framework || 'unknown'}
- Dependencies: ${context.dependencies ? context.dependencies.join(', ') : 'unknown'}

Analyze the code carefully and identify any security vulnerabilities.`;

    try {
      // Select schema based on provider
      const VulnerabilitySchema = this.config.provider === 'google' ? VulnerabilitySchemaGemini : VulnerabilitySchemaOpenAI;
      const VulnerabilityListSchema = z.object({
        vulnerabilities: z.array(VulnerabilitySchema).describe('Array of vulnerabilities found in the code')
      });
      
      // Create structured LLM with vulnerability schema
      const structuredLLM = this.llm.withStructuredOutput(VulnerabilityListSchema);
      
      const response = await structuredLLM.invoke([
        new SystemMessage(systemPrompt),
        new HumanMessage(userPrompt)
      ], {
        temperature: 0.1 // Lower temperature for more consistent analysis
      });

      logger.log('[LLMService] Structured LLM response:', response);

      // Extract vulnerabilities from response object
      const vulnerabilities = response.vulnerabilities || [];

      // Add metadata to each vulnerability
      return vulnerabilities.map(vuln => ({
        ...vuln,
        id: this.generateVulnerabilityId(),
        discoveredBy: 'llm-analysis',
        discoveredAt: new Date().toISOString(),
        context: {
          ...context,
          llmProvider: this.config.provider,
          llmModel: this.config.model
        }
      }));

    } catch (error) {
      logger.error('[LLMService] Vulnerability analysis failed:', error.message);
      return [];
    }
  }

  /**
   * Validate vulnerability findings using structured output
   * @param {object} vulnerability - Vulnerability to validate
   * @param {object} context - Validation context
   * @returns {Promise<object>} Validation result
   */
  async validateVulnerability(vulnerability, context = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const systemPrompt = `You are an expert security analyst specializing in vulnerability validation and false positive reduction.

Your task is to validate whether a reported vulnerability is legitimate or a false positive.

Consider these factors in your validation:
- Code context and surrounding logic
- Input validation and sanitization
- Security controls and mitigations
- Framework-specific protections
- Business logic and intended behavior`;

    const userPrompt = `Validate this vulnerability report:

Vulnerability Details:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- Description: ${vulnerability.description}
- Evidence: ${vulnerability.evidence}
- Line: ${vulnerability.line}

Code Context:
\`\`\`${context.language || 'code'}
${context.code || vulnerability.evidence}
\`\`\`

File: ${context.filePath || vulnerability.file}
Method: ${context.method || 'unknown'}

Analyze whether this is a legitimate vulnerability or a false positive and provide detailed reasoning.`;

    try {
      // Create structured LLM with validation schema
      const structuredLLM = this.llm.withStructuredOutput(ValidationSchema);
      
      const validation = await structuredLLM.invoke([
        new SystemMessage(systemPrompt),
        new HumanMessage(userPrompt)
      ], {
        temperature: 0.1
      });

      logger.log('[LLMService] Structured validation response:', validation);

      return {
        ...validation,
        validatedAt: new Date().toISOString(),
        validatedBy: `llm-${this.config.provider}-${this.config.model}`,
        originalVulnerability: vulnerability.id
      };

    } catch (error) {
      logger.error('[LLMService] Vulnerability validation failed:', error.message);
      
      // Return default validation if LLM fails
      return {
        isValid: true, // Default to valid to avoid missing real vulnerabilities
        confidence: 0.5,
        reasoning: 'LLM validation failed, defaulting to valid',
        riskLevel: vulnerability.severity,
        exploitability: 0.5,
        impact: 0.5,
        recommendations: ['Manual review required'],
        validatedAt: new Date().toISOString(),
        validatedBy: `fallback-validation`,
        error: error.message
      };
    }
  }

  /**
   * Generate contextual remediation advice using structured output
   * @param {Array} vulnerabilities - List of vulnerabilities
   * @param {object} context - Remediation context
   * @returns {Promise<object>} Remediation recommendations
   */
  async generateRemediation(vulnerabilities, context = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const systemPrompt = `You are an expert security consultant providing remediation advice for security vulnerabilities.

Your task is to generate comprehensive, actionable remediation advice based on the vulnerabilities found.

Provide specific, technical recommendations that developers can implement immediately.`;

    const vulnSummary = vulnerabilities.map(v => ({
      type: v.type,
      severity: v.severity,
      file: v.file,
      description: v.description
    }));

    const userPrompt = `Generate remediation advice for these vulnerabilities:

Project Context:
- Language: ${context.language || 'unknown'}
- Framework: ${context.framework || 'unknown'}
- Project Type: ${context.projectType || 'unknown'}

Vulnerabilities Found:
${JSON.stringify(vulnSummary, null, 2)}

Provide comprehensive remediation advice organized by priority and timeline.`;

    try {
      // Create structured LLM with remediation schema
      const structuredLLM = this.llm.withStructuredOutput(RemediationSchema);
      
      const remediation = await structuredLLM.invoke([
        new SystemMessage(systemPrompt),
        new HumanMessage(userPrompt)
      ]);
      
      logger.log('[LLMService] Structured remediation response:', remediation);
      
      return remediation;
    } catch (error) {
      logger.error('[LLMService] Remediation generation failed:', error.message);
      return {
        immediate: [],
        shortTerm: [],
        longTerm: [],
        general: ['Manual security review required'],
        tools: [],
        training: []
      };
    }
  }

  /**
   * Clean JSON response from LLM (deprecated - now using structured output)
   * @deprecated Use structured output instead
   */
  cleanJsonResponse(response) {
    logger.warn('[LLMService] cleanJsonResponse is deprecated - use structured output instead');
    
    // Remove markdown code blocks
    let cleaned = response.replace(/```json\s*|\s*```/g, '');
    cleaned = cleaned.replace(/```\s*|\s*```/g, '');
    
    // Remove any leading/trailing whitespace
    cleaned = cleaned.trim();
    
    // Check if response starts with [ (array) or { (object)
    if (cleaned.startsWith('[')) {
      // Handle array responses
      const firstBracket = cleaned.indexOf('[');
      const lastBracket = cleaned.lastIndexOf(']');
      
      if (firstBracket !== -1 && lastBracket !== -1 && firstBracket < lastBracket) {
        cleaned = cleaned.substring(firstBracket, lastBracket + 1);
      }
    } else if (cleaned.startsWith('{')) {
      // Handle object responses
      const firstBrace = cleaned.indexOf('{');
      const lastBrace = cleaned.lastIndexOf('}');
      
      if (firstBrace !== -1 && lastBrace !== -1 && firstBrace < lastBrace) {
        cleaned = cleaned.substring(firstBrace, lastBrace + 1);
      }
    } else {
      // Try to extract JSON from text
      const jsonMatch = cleaned.match(/\[[\s\S]*\]/) || cleaned.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        cleaned = jsonMatch[0];
      }
    }
    
    return cleaned;
  }

  /**
   * Generate unique vulnerability ID
   */
  generateVulnerabilityId() {
    return `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get service statistics
   */
  getStats() {
    return {
      provider: this.config.provider,
      model: this.config.model,
      initialized: this.initialized,
      config: {
        temperature: this.config.temperature,
        maxTokens: this.config.maxTokens,
        timeout: this.config.timeout
      }
    };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.initialized = false; // Force re-initialization
  }

  /**
   * Test LLM connectivity
   */
  async testConnection() {
    try {
      const response = await this.chat(
        'You are a helpful assistant.',
        'Reply with exactly: "Connection successful"'
      );
      
      return {
        success: true,
        response: response.trim(),
        provider: this.config.provider,
        model: this.config.model
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        provider: this.config.provider,
        model: this.config.model
      };
    }
  }
}

// Singleton instance
export const llmService = new LLMService();
export default LLMService;