import { BaseAgent } from './base-agent.js';
import { promises as fs } from 'fs';
import path from 'path';
import glob from 'fast-glob';

/**
 * Explorer agent for discovering and filtering files in repositories
 */
export class ExplorerAgent extends BaseAgent {
  constructor(id, config = {}, sessionId = null) {
    super(id, config, sessionId);
    this.plugin = config.plugin;
    this.maxFileSize = config.maxFileSize || 5 * 1024 * 1024; // 5MB default
    this.maxFiles = config.maxFiles || 10000;
    this.excludePatterns = config.excludePatterns || [
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
      '**/.nyc_output/**'
    ];
  }

  /**
   * Initialize the explorer agent
   */
  async initialize() {
    if (this.initialized) return;

    if (!this.plugin) {
      throw new Error('Explorer agent requires a language plugin');
    }

    await super.initialize();
    this.log('info', 'Explorer agent initialized', { 
      plugin: this.plugin.name,
      maxFileSize: this.maxFileSize,
      maxFiles: this.maxFiles
    });
  }

  /**
   * Execute file discovery
   * @param {object} input - Input containing repositoryPath
   * @returns {object} Discovery results
   */
  async execute(input) {
    return await this.executeTask(async (input) => {
      this.validateInput(input, ['repositoryPath']);
      
      const { repositoryPath } = input;
      
      // Verify repository exists
      await this.verifyRepository(repositoryPath);
      
      // Discover files
      const files = await this.discoverFiles(repositoryPath);
      
      // Filter and analyze files
      const filteredFiles = await this.filterFiles(files, repositoryPath);
      
      // Generate statistics
      const stats = this.generateStats(filteredFiles);
      
      return {
        repositoryPath,
        files: filteredFiles,
        stats,
        timestamp: new Date().toISOString()
      };
    }, input);
  }

  /**
   * Verify repository exists and is accessible
   * @param {string} repositoryPath - Repository path
   */
  async verifyRepository(repositoryPath) {
    try {
      const stats = await fs.stat(repositoryPath);
      if (!stats.isDirectory()) {
        throw new Error(`Repository path is not a directory: ${repositoryPath}`);
      }
      
      // Check if we can read the directory
      await fs.access(repositoryPath, fs.constants.R_OK);
      
      this.log('info', 'Repository verified', { repositoryPath });
    } catch (error) {
      throw new Error(`Repository verification failed: ${error.message}`);
    }
  }

  /**
   * Discover files in repository
   * @param {string} repositoryPath - Repository path
   * @returns {Array} Discovered files
   */
  async discoverFiles(repositoryPath) {
    try {
      const patterns = this.buildSearchPatterns();
      
      this.log('info', 'Starting file discovery', { 
        patterns: patterns.slice(0, 5), // Log first 5 patterns
        excludePatterns: this.excludePatterns.slice(0, 5)
      });

      const files = await glob(patterns, {
        cwd: repositoryPath,
        absolute: true,
        ignore: this.excludePatterns,
        followSymbolicLinks: false,
        suppressErrors: true
      });

      this.log('info', `Discovered ${files.length} files`);
      
      // Limit number of files to prevent memory issues
      const limitedFiles = files.slice(0, this.maxFiles);
      
      if (files.length > this.maxFiles) {
        this.log('warn', `File limit exceeded, processing first ${this.maxFiles} files`);
      }

      return limitedFiles;
    } catch (error) {
      throw new Error(`File discovery failed: ${error.message}`);
    }
  }

  /**
   * Build search patterns based on plugin configuration
   * @returns {Array} Search patterns
   */
  buildSearchPatterns() {
    const patterns = [];
    
    // Add patterns for supported extensions
    for (const ext of this.plugin.supportedExtensions) {
      patterns.push(`**/*${ext}`);
    }
    
    // Add patterns for build files
    for (const buildFile of this.plugin.buildFiles) {
      if (buildFile.includes('*')) {
        patterns.push(`**/${buildFile}`);
      } else {
        patterns.push(`**/${buildFile}`);
      }
    }
    
    // Add common configuration files
    patterns.push('**/web.xml');
    patterns.push('**/application.properties');
    patterns.push('**/application.yml');
    patterns.push('**/application.yaml');
    
    return patterns;
  }

  /**
   * Filter and analyze discovered files
   * @param {Array} files - Discovered files
   * @param {string} repositoryPath - Repository path
   * @returns {Array} Filtered files with metadata
   */
  async filterFiles(files, repositoryPath) {
    const filteredFiles = [];
    
    this.log('info', 'Filtering and analyzing files');
    
    // Process files in parallel but with limited concurrency
    const processFile = async (filePath) => {
      try {
        const stats = await fs.stat(filePath);
        
        // Skip if file is too large
        if (stats.size > this.maxFileSize) {
          this.log('warn', `File too large, skipping: ${filePath} (${stats.size} bytes)`);
          return null;
        }
        
        // Check if plugin should analyze this file
        if (!this.plugin.shouldAnalyzeFile(filePath, stats)) {
          return null;
        }
        
        // Create file metadata
        const fileInfo = {
          path: filePath,
          relativePath: path.relative(repositoryPath, filePath),
          size: stats.size,
          extension: path.extname(filePath),
          lastModified: stats.mtime.toISOString(),
          language: this.plugin.name,
          type: this.determineFileType(filePath)
        };
        
        return fileInfo;
      } catch (error) {
        this.log('error', `Failed to process file: ${filePath}`, { error: error.message });
        return null;
      }
    };
    
    // Process files in parallel
    const results = await this.processInParallel(files, processFile, 10);
    
    // Filter out null results
    const validFiles = results.filter(file => file !== null);
    
    this.log('info', `Filtered to ${validFiles.length} files for analysis`);
    
    return validFiles;
  }

  /**
   * Determine file type based on path and name
   * @param {string} filePath - File path
   * @returns {string} File type
   */
  determineFileType(filePath) {
    const fileName = path.basename(filePath);
    const relativePath = filePath.toLowerCase();
    
    // Test files
    if (relativePath.includes('/test/') || 
        fileName.includes('test') || 
        fileName.includes('spec')) {
      return 'test';
    }
    
    // Build files
    if (this.plugin.buildFiles.some(buildFile => 
        buildFile.includes('*') ? 
        fileName.match(buildFile.replace('*', '.*')) : 
        fileName === buildFile)) {
      return 'build';
    }
    
    // Configuration files
    if (fileName.includes('config') || 
        fileName.includes('properties') || 
        fileName.includes('yml') || 
        fileName.includes('yaml') ||
        fileName.includes('xml')) {
      return 'config';
    }
    
    // Source files
    if (this.plugin.supportedExtensions.includes(path.extname(filePath))) {
      return 'source';
    }
    
    return 'other';
  }

  /**
   * Generate statistics about discovered files
   * @param {Array} files - Filtered files
   * @returns {object} File statistics
   */
  generateStats(files) {
    const stats = {
      totalFiles: files.length,
      totalSize: 0,
      byType: {},
      byExtension: {},
      largestFile: null,
      averageSize: 0,
      languages: {}
    };

    let maxSize = 0;
    
    for (const file of files) {
      // Total size
      stats.totalSize += file.size;
      
      // Track largest file
      if (file.size > maxSize) {
        maxSize = file.size;
        stats.largestFile = {
          path: file.relativePath,
          size: file.size
        };
      }
      
      // Count by type
      stats.byType[file.type] = (stats.byType[file.type] || 0) + 1;
      
      // Count by extension
      stats.byExtension[file.extension] = (stats.byExtension[file.extension] || 0) + 1;
      
      // Count by language
      stats.languages[file.language] = (stats.languages[file.language] || 0) + 1;
    }
    
    // Calculate average size
    stats.averageSize = files.length > 0 ? stats.totalSize / files.length : 0;
    
    return stats;
  }

  /**
   * Get file content for analysis
   * @param {string} filePath - File path
   * @returns {string} File content
   */
  async getFileContent(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      return content;
    } catch (error) {
      this.log('error', `Failed to read file: ${filePath}`, { error: error.message });
      throw error;
    }
  }

  /**
   * Check if file should be analyzed based on various criteria
   * @param {string} filePath - File path
   * @param {object} stats - File stats
   * @returns {boolean} True if file should be analyzed
   */
  shouldAnalyzeFile(filePath, stats) {
    // Check file size
    if (stats.size > this.maxFileSize) {
      return false;
    }
    
    // Check if it's a binary file (simple heuristic)
    if (this.isBinaryFile(filePath)) {
      return false;
    }
    
    // Check if it's in excluded directories
    for (const excludePattern of this.excludePatterns) {
      const pattern = excludePattern.replace('**/', '').replace('/**', '');
      if (filePath.includes(pattern)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Simple binary file detection
   * @param {string} filePath - File path
   * @returns {boolean} True if likely binary
   */
  isBinaryFile(filePath) {
    const binaryExtensions = [
      '.class', '.jar', '.war', '.ear', '.zip', '.tar', '.gz',
      '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
      '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
      '.exe', '.dll', '.so', '.dylib', '.bin'
    ];
    
    const ext = path.extname(filePath).toLowerCase();
    return binaryExtensions.includes(ext);
  }

  /**
   * Cleanup explorer agent resources
   */
  async cleanup() {
    await super.cleanup();
    this.log('info', 'Explorer agent cleaned up');
  }
}

export default ExplorerAgent;