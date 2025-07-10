import { BaseAgent } from './base-agent.js';
import { promises as fs } from 'fs';

/**
 * Parser agent for parsing source files using language plugins
 */
export class ParserAgent extends BaseAgent {
  constructor(id, config = {}, sessionId = null) {
    super(id, config, sessionId);
    this.plugin = config.plugin;
    this.concurrency = config.concurrency || 5;
    this.maxFileSize = config.maxFileSize || 5 * 1024 * 1024; // 5MB
  }

  /**
   * Initialize the parser agent
   */
  async initialize() {
    if (this.initialized) return;

    if (!this.plugin) {
      throw new Error('Parser agent requires a language plugin');
    }

    // Initialize the plugin if not already done
    if (!this.plugin.initialized) {
      await this.plugin.initialize();
    }

    await super.initialize();
    this.log('info', 'Parser agent initialized', { 
      plugin: this.plugin.name,
      concurrency: this.concurrency
    });
  }

  /**
   * Execute file parsing
   * @param {object} input - Input containing files array
   * @returns {object} Parsing results
   */
  async execute(input) {
    return await this.executeTask(async (input) => {
      this.validateInput(input, ['files']);
      
      const { files } = input;
      
      if (!Array.isArray(files)) {
        throw new Error('Files must be an array');
      }

      this.log('info', `Starting to parse ${files.length} files`);
      
      // Parse files in parallel
      const parsedFiles = await this.parseFiles(files);
      
      // Generate parsing statistics
      const stats = this.generateParsingStats(parsedFiles);
      
      return {
        files: parsedFiles,
        stats,
        timestamp: new Date().toISOString()
      };
    }, input);
  }

  /**
   * Parse multiple files
   * @param {Array} files - Files to parse
   * @returns {Array} Parsed files
   */
  async parseFiles(files) {
    const parseFile = async (fileInfo, index) => {
      try {
        this.log('info', `Parsing file ${index + 1}/${files.length}: ${fileInfo.relativePath}`);
        
        // Read file content
        const content = await this.readFileContent(fileInfo.path);
        
        // Parse with plugin
        const parsed = await this.plugin.parseFile(fileInfo.path, content);
        
        // Enhance with original file info
        const result = {
          ...fileInfo,
          parsed,
          contentLength: content.length,
          parseSuccess: true,
          parseTimestamp: new Date().toISOString()
        };
        
        this.log('info', `Successfully parsed: ${fileInfo.relativePath}`);
        return result;
      } catch (error) {
        this.log('error', `Failed to parse file: ${fileInfo.relativePath}`, { 
          error: error.message 
        });
        
        return {
          ...fileInfo,
          parsed: null,
          parseSuccess: false,
          parseError: error.message,
          parseTimestamp: new Date().toISOString()
        };
      }
    };

    // Process files in parallel with limited concurrency
    const results = await this.processInParallel(files, parseFile, this.concurrency);
    
    return results;
  }

  /**
   * Read file content with error handling
   * @param {string} filePath - File path
   * @returns {string} File content
   */
  async readFileContent(filePath) {
    try {
      // Check file size before reading
      const stats = await fs.stat(filePath);
      if (stats.size > this.maxFileSize) {
        throw new Error(`File too large: ${stats.size} bytes`);
      }
      
      const content = await fs.readFile(filePath, 'utf8');
      return content;
    } catch (error) {
      throw new Error(`Failed to read file: ${error.message}`);
    }
  }

  /**
   * Generate parsing statistics
   * @param {Array} parsedFiles - Parsed files
   * @returns {object} Parsing statistics
   */
  generateParsingStats(parsedFiles) {
    const stats = {
      totalFiles: parsedFiles.length,
      successful: 0,
      failed: 0,
      totalContent: 0,
      averageContentLength: 0,
      parseErrors: [],
      byFileType: {},
      complexity: {
        totalClasses: 0,
        totalMethods: 0,
        totalImports: 0,
        averageMethodsPerClass: 0
      }
    };

    let totalMethods = 0;
    let totalClasses = 0;

    for (const file of parsedFiles) {
      // Count successes and failures
      if (file.parseSuccess) {
        stats.successful++;
        stats.totalContent += file.contentLength || 0;
        
        // Analyze parsed content
        if (file.parsed) {
          const classes = file.parsed.classes || [];
          const methods = file.parsed.methods || [];
          const imports = file.parsed.imports || [];
          
          stats.complexity.totalClasses += classes.length;
          stats.complexity.totalMethods += methods.length;
          stats.complexity.totalImports += imports.length;
          
          totalClasses += classes.length;
          totalMethods += methods.length;
        }
      } else {
        stats.failed++;
        stats.parseErrors.push({
          file: file.relativePath,
          error: file.parseError
        });
      }
      
      // Count by file type
      const fileType = file.type || 'unknown';
      stats.byFileType[fileType] = (stats.byFileType[fileType] || 0) + 1;
    }

    // Calculate averages
    stats.averageContentLength = stats.successful > 0 ? 
      stats.totalContent / stats.successful : 0;
    
    stats.complexity.averageMethodsPerClass = totalClasses > 0 ? 
      totalMethods / totalClasses : 0;

    return stats;
  }

  /**
   * Extract specific elements from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @param {string} elementType - Type of element to extract
   * @returns {Array} Extracted elements
   */
  extractElements(parsedFiles, elementType) {
    const elements = [];
    
    for (const file of parsedFiles) {
      if (!file.parseSuccess || !file.parsed) continue;
      
      const fileElements = file.parsed[elementType] || [];
      
      for (const element of fileElements) {
        elements.push({
          ...element,
          file: file.relativePath,
          filePath: file.path
        });
      }
    }
    
    return elements;
  }

  /**
   * Get all methods from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @returns {Array} All methods
   */
  getAllMethods(parsedFiles) {
    return this.extractElements(parsedFiles, 'methods');
  }

  /**
   * Get all classes from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @returns {Array} All classes
   */
  getAllClasses(parsedFiles) {
    return this.extractElements(parsedFiles, 'classes');
  }

  /**
   * Get all imports from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @returns {Array} All imports
   */
  getAllImports(parsedFiles) {
    return this.extractElements(parsedFiles, 'imports');
  }

  /**
   * Get all SQL queries from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @returns {Array} All SQL queries
   */
  getAllSqlQueries(parsedFiles) {
    return this.extractElements(parsedFiles, 'sqlQueries');
  }

  /**
   * Get all HTTP handlers from parsed files
   * @param {Array} parsedFiles - Parsed files
   * @returns {Array} All HTTP handlers
   */
  getAllHttpHandlers(parsedFiles) {
    return this.extractElements(parsedFiles, 'httpHandlers');
  }

  /**
   * Filter parsed files by criteria
   * @param {Array} parsedFiles - Parsed files
   * @param {object} criteria - Filter criteria
   * @returns {Array} Filtered files
   */
  filterParsedFiles(parsedFiles, criteria) {
    return parsedFiles.filter(file => {
      // Filter by parse success
      if (criteria.onlySuccessful && !file.parseSuccess) {
        return false;
      }
      
      // Filter by file type
      if (criteria.fileType && file.type !== criteria.fileType) {
        return false;
      }
      
      // Filter by extension
      if (criteria.extension && file.extension !== criteria.extension) {
        return false;
      }
      
      // Filter by minimum content length
      if (criteria.minContentLength && 
          (file.contentLength || 0) < criteria.minContentLength) {
        return false;
      }
      
      // Filter by presence of specific elements
      if (criteria.hasElements) {
        const hasRequired = criteria.hasElements.every(elementType => {
          const elements = file.parsed?.[elementType] || [];
          return elements.length > 0;
        });
        
        if (!hasRequired) {
          return false;
        }
      }
      
      return true;
    });
  }

  /**
   * Get parsing summary
   * @param {Array} parsedFiles - Parsed files
   * @returns {object} Parsing summary
   */
  getParsingSummary(parsedFiles) {
    const successful = parsedFiles.filter(f => f.parseSuccess);
    const failed = parsedFiles.filter(f => !f.parseSuccess);
    
    return {
      total: parsedFiles.length,
      successful: successful.length,
      failed: failed.length,
      successRate: parsedFiles.length > 0 ? 
        (successful.length / parsedFiles.length) * 100 : 0,
      failedFiles: failed.map(f => ({
        file: f.relativePath,
        error: f.parseError
      }))
    };
  }

  /**
   * Validate parsed file structure
   * @param {object} parsedFile - Parsed file
   * @returns {boolean} True if valid
   */
  validateParsedFile(parsedFile) {
    if (!parsedFile.parseSuccess) {
      return false;
    }
    
    const parsed = parsedFile.parsed;
    if (!parsed) {
      return false;
    }
    
    // Check for required structure
    const requiredFields = ['classes', 'methods', 'imports'];
    const hasRequiredFields = requiredFields.every(field => 
      Array.isArray(parsed[field])
    );
    
    return hasRequiredFields;
  }

  /**
   * Clean up parser agent resources
   */
  async cleanup() {
    await super.cleanup();
    this.log('info', 'Parser agent cleaned up');
  }
}

export default ParserAgent;