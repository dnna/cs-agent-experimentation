/**
 * Base class for language-specific plugins
 * All language plugins must extend this class and implement the required methods
 */
export class BaseLanguagePlugin {
  /**
   * Create a new language plugin
   * @param {string} name - Plugin name (must match directory name)
   * @param {string} version - Plugin version
   */
  constructor(name, version) {
    this.name = name;
    this.version = version;
    this.supportedExtensions = [];
    this.buildFiles = [];
    this.vulnerabilityTypes = [];
    this.initialized = false;
  }

  /**
   * Initialize the plugin (called once during loading)
   * Override this method to perform any necessary setup
   */
  async initialize() {
    this.initialized = true;
  }

  /**
   * Parse a source file and extract structural information
   * @param {string} filePath - Path to the file
   * @param {string} content - File content
   * @returns {object} Parsed file information
   */
  async parseFile(filePath, content) {
    throw new Error(`parseFile must be implemented by ${this.name} plugin`);
  }

  /**
   * Detect vulnerabilities in parsed file data
   * @param {object} ast - Abstract syntax tree or parsed structure
   * @param {object} context - Analysis context
   * @returns {Array} Array of vulnerability objects
   */
  async detectVulnerabilities(ast, context) {
    throw new Error(`detectVulnerabilities must be implemented by ${this.name} plugin`);
  }

  /**
   * Analyze project dependencies for known vulnerabilities
   * @param {string} projectPath - Path to the project root
   * @returns {Array} Array of dependency vulnerabilities
   */
  async analyzeDependencies(projectPath) {
    throw new Error(`analyzeDependencies must be implemented by ${this.name} plugin`);
  }

  /**
   * Get vulnerability patterns for static analysis
   * @returns {object} Vulnerability patterns by type
   */
  getVulnerabilityPatterns() {
    return {};
  }

  /**
   * Get CWE mappings for vulnerability types
   * @returns {object} CWE mappings
   */
  getCWEMappings() {
    return {};
  }

  /**
   * Get OWASP mappings for vulnerability types
   * @returns {object} OWASP mappings
   */
  getOWASPMappings() {
    return {};
  }

  /**
   * Preprocess file content before parsing (optional)
   * @param {string} content - Original file content
   * @returns {string} Preprocessed content
   */
  async preprocessFile(content) {
    return content;
  }

  /**
   * Postprocess vulnerability results (optional)
   * @param {Array} results - Raw vulnerability results
   * @returns {Array} Processed vulnerability results
   */
  async postprocessResults(results) {
    return results;
  }

  /**
   * Validate file for analysis (optional)
   * @param {string} filePath - Path to the file
   * @param {object} stats - File statistics
   * @returns {boolean} True if file should be analyzed
   */
  shouldAnalyzeFile(filePath, stats) {
    // Default implementation - analyze all files with supported extensions
    const ext = filePath.split('.').pop();
    return this.supportedExtensions.includes(`.${ext}`);
  }

  /**
   * Get plugin metadata
   * @returns {object} Plugin metadata
   */
  getMetadata() {
    return {
      name: this.name,
      version: this.version,
      supportedExtensions: this.supportedExtensions,
      buildFiles: this.buildFiles,
      vulnerabilityTypes: this.vulnerabilityTypes,
      initialized: this.initialized
    };
  }

  /**
   * Get plugin capabilities
   * @returns {object} Plugin capabilities
   */
  getCapabilities() {
    return {
      parsing: typeof this.parseFile === 'function',
      vulnerabilityDetection: typeof this.detectVulnerabilities === 'function',
      dependencyAnalysis: typeof this.analyzeDependencies === 'function',
      patternMatching: Object.keys(this.getVulnerabilityPatterns()).length > 0,
      aiAnalysis: false,
      preprocessing: this.preprocessFile !== BaseLanguagePlugin.prototype.preprocessFile,
      postprocessing: this.postprocessResults !== BaseLanguagePlugin.prototype.postprocessResults
    };
  }

  /**
   * Validate plugin configuration
   * @throws {Error} If configuration is invalid
   */
  validateConfiguration() {
    if (!this.name || typeof this.name !== 'string') {
      throw new Error('Plugin name must be a non-empty string');
    }

    if (!this.version || typeof this.version !== 'string') {
      throw new Error('Plugin version must be a non-empty string');
    }

    if (!Array.isArray(this.supportedExtensions)) {
      throw new Error('supportedExtensions must be an array');
    }

    if (!Array.isArray(this.buildFiles)) {
      throw new Error('buildFiles must be an array');
    }

    if (!Array.isArray(this.vulnerabilityTypes)) {
      throw new Error('vulnerabilityTypes must be an array');
    }

    // Validate extensions format
    for (const ext of this.supportedExtensions) {
      if (typeof ext !== 'string' || !ext.startsWith('.')) {
        throw new Error(`Invalid extension format: ${ext}. Extensions must start with a dot.`);
      }
    }
  }

  /**
   * Create a standardized vulnerability object
   * @param {object} vulnerability - Vulnerability data
   * @returns {object} Standardized vulnerability object
   */
  createVulnerability(vulnerability) {
    const cweMapping = this.getCWEMappings();
    const owaspMapping = this.getOWASPMappings();

    return {
      id: vulnerability.id || this.generateVulnerabilityId(),
      type: vulnerability.type,
      severity: vulnerability.severity || 'MEDIUM',
      confidence: vulnerability.confidence || 0.8,
      file: vulnerability.file,
      line: vulnerability.line,
      column: vulnerability.column,
      description: vulnerability.description,
      evidence: vulnerability.evidence, // Include evidence field
      cwe: vulnerability.cwe || cweMapping[vulnerability.type],
      owasp: vulnerability.owasp || owaspMapping[vulnerability.type],
      context: vulnerability.context || {},
      remediation: vulnerability.remediation,
      references: vulnerability.references || [],
      plugin: this.name,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generate a unique vulnerability ID
   * @returns {string} Unique vulnerability ID
   */
  generateVulnerabilityId() {
    return `${this.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Log a message with plugin context
   * @param {string} level - Log level (info, warn, error)
   * @param {string} message - Log message
   * @param {object} data - Additional data
   */
  log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      plugin: this.name,
      level,
      message,
      ...data
    };

    console.log(`[${timestamp}] [${this.name}] ${level.toUpperCase()}: ${message}`, data);
  }

  /**
   * Create an analysis context object
   * @param {string} filePath - File path
   * @param {object} options - Additional context options
   * @returns {object} Analysis context
   */
  createContext(filePath, options = {}) {
    return {
      filePath,
      fileName: filePath.split('/').pop(),
      extension: filePath.split('.').pop(),
      plugin: this.name,
      timestamp: new Date().toISOString(),
      ...options
    };
  }

  /**
   * Cleanup resources (called when plugin is unloaded)
   */
  async cleanup() {
    // Override if cleanup is needed
  }
}

export default BaseLanguagePlugin;