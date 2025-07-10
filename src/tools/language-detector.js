import { promises as fs } from 'fs';
import path from 'path';
import glob from 'fast-glob';

/**
 * Language detector for automatically identifying programming languages in repositories
 */
export class LanguageDetector {
  constructor() {
    this.detectionRules = {
      java: {
        files: ['pom.xml', 'build.gradle', 'gradlew', 'gradle.properties', 'settings.gradle'],
        extensions: ['.java'],
        directories: ['src/main/java', 'src/test/java', 'src/main/resources'],
        keywords: ['package ', 'import java.', 'public class', 'public interface', '@Override'],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      javascript: {
        files: ['package.json', 'yarn.lock', 'package-lock.json', 'webpack.config.js', 'babel.config.js'],
        extensions: ['.js', '.jsx', '.mjs'],
        directories: ['node_modules', 'src', 'lib', 'dist'],
        keywords: ['require(', 'import {', 'export default', 'module.exports', 'const ', 'let '],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      typescript: {
        files: ['tsconfig.json', 'package.json'],
        extensions: ['.ts', '.tsx'],
        directories: ['src', 'lib', 'types'],
        keywords: ['interface ', 'type ', 'export type', 'import type', 'declare '],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      python: {
        files: ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile', 'setup.cfg'],
        extensions: ['.py', '.pyx', '.pyi'],
        directories: ['__pycache__', 'venv', '.venv', 'env'],
        keywords: ['def ', 'import ', 'from ', 'class ', 'if __name__'],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      csharp: {
        files: ['*.csproj', '*.sln', 'packages.config', 'Directory.Build.props'],
        extensions: ['.cs', '.csx'],
        directories: ['bin', 'obj', 'Properties', 'packages'],
        keywords: ['using System', 'namespace ', 'public class', 'public interface', '[assembly:'],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      go: {
        files: ['go.mod', 'go.sum', 'Gopkg.toml', 'Gopkg.lock'],
        extensions: ['.go'],
        directories: ['vendor', 'cmd', 'internal', 'pkg'],
        keywords: ['package ', 'import (', 'func ', 'type ', 'var '],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      rust: {
        files: ['Cargo.toml', 'Cargo.lock'],
        extensions: ['.rs'],
        directories: ['src', 'target', 'tests'],
        keywords: ['fn ', 'use ', 'mod ', 'struct ', 'impl '],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      },
      php: {
        files: ['composer.json', 'composer.lock'],
        extensions: ['.php', '.phtml'],
        directories: ['vendor', 'src', 'app'],
        keywords: ['<?php', 'namespace ', 'class ', 'function ', 'use '],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      }
    };
  }

  /**
   * Detect languages in a repository
   * @param {string} repositoryPath - Path to the repository
   * @param {object} options - Detection options
   * @returns {object} Detection results
   */
  async detectLanguages(repositoryPath, options = {}) {
    const {
      maxFileSize = 1024 * 1024, // 1MB
      maxFiles = 1000,
      sampleSize = 10,
      confidenceThreshold = 0.3
    } = options;

    const results = {
      primary: null,
      secondary: [],
      confidence: {},
      details: {},
      repositoryPath,
      timestamp: new Date().toISOString()
    };

    // Check if repository exists
    try {
      await fs.access(repositoryPath);
    } catch (error) {
      throw new Error(`Repository path does not exist: ${repositoryPath}`);
    }

    // Calculate scores for each language
    for (const [language, rules] of Object.entries(this.detectionRules)) {
      try {
        const score = await this.calculateLanguageScore(repositoryPath, rules, {
          maxFileSize,
          maxFiles,
          sampleSize
        });
        
        results.confidence[language] = score;
        results.details[language] = await this.getLanguageDetails(repositoryPath, rules);
      } catch (error) {
        console.warn(`[LanguageDetector] Error analyzing ${language}:`, error.message);
        results.confidence[language] = 0;
        results.details[language] = { error: error.message };
      }
    }

    // Determine primary and secondary languages
    const sortedLanguages = Object.entries(results.confidence)
      .sort(([,a], [,b]) => b - a)
      .filter(([, score]) => score >= confidenceThreshold);

    if (sortedLanguages.length > 0) {
      results.primary = sortedLanguages[0][0];
      results.secondary = sortedLanguages.slice(1, 4).map(([lang]) => lang);
    }

    return results;
  }

  /**
   * Calculate language score based on detection rules
   * @param {string} repoPath - Repository path
   * @param {object} rules - Language detection rules
   * @param {object} options - Analysis options
   * @returns {number} Score between 0 and 1
   */
  async calculateLanguageScore(repoPath, rules, options = {}) {
    let score = 0;
    const { maxFileSize, maxFiles, sampleSize } = options;

    // Check for specific files
    const fileScore = await this.checkFiles(repoPath, rules.files);
    score += fileScore * rules.weight.files;

    // Check file extensions
    const extensionScore = await this.checkExtensions(repoPath, rules.extensions, maxFiles);
    score += extensionScore * rules.weight.extensions;

    // Check directory patterns
    const directoryScore = await this.checkDirectories(repoPath, rules.directories);
    score += directoryScore * rules.weight.directories;

    // Check keywords in sample files
    const keywordScore = await this.checkKeywords(repoPath, rules.extensions, rules.keywords, {
      maxFileSize,
      sampleSize
    });
    score += keywordScore * rules.weight.keywords;

    return Math.min(score, 1);
  }

  /**
   * Check for specific files in repository
   * @param {string} repoPath - Repository path
   * @param {Array} files - Files to check for
   * @returns {number} Score between 0 and 1
   */
  async checkFiles(repoPath, files) {
    let foundCount = 0;
    
    for (const file of files) {
      try {
        const pattern = file.includes('*') ? file : `**/${file}`;
        const matches = await glob(pattern, { cwd: repoPath, absolute: false });
        if (matches.length > 0) {
          foundCount++;
        }
      } catch (error) {
        // Ignore glob errors
      }
    }

    return foundCount / files.length;
  }

  /**
   * Check for file extensions in repository
   * @param {string} repoPath - Repository path
   * @param {Array} extensions - Extensions to check for
   * @param {number} maxFiles - Maximum files to analyze
   * @returns {number} Score between 0 and 1
   */
  async checkExtensions(repoPath, extensions, maxFiles) {
    const patterns = extensions.map(ext => `**/*${ext}`);
    
    try {
      const files = await glob(patterns, { 
        cwd: repoPath, 
        absolute: false,
        ignore: ['node_modules/**', '.git/**', '**/target/**', '**/build/**']
      });
      
      const relevantFiles = files.slice(0, maxFiles);
      
      if (relevantFiles.length === 0) return 0;
      
      // Score based on number of files (logarithmic scale)
      const score = Math.min(Math.log(relevantFiles.length + 1) / Math.log(101), 1);
      return score;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Check for directory patterns in repository
   * @param {string} repoPath - Repository path
   * @param {Array} directories - Directories to check for
   * @returns {number} Score between 0 and 1
   */
  async checkDirectories(repoPath, directories) {
    let foundCount = 0;
    
    for (const dir of directories) {
      try {
        const dirPath = path.join(repoPath, dir);
        const stat = await fs.stat(dirPath);
        if (stat.isDirectory()) {
          foundCount++;
        }
      } catch (error) {
        // Directory doesn't exist
      }
    }

    return foundCount / directories.length;
  }

  /**
   * Check for keywords in sample files
   * @param {string} repoPath - Repository path
   * @param {Array} extensions - File extensions to sample
   * @param {Array} keywords - Keywords to search for
   * @param {object} options - Analysis options
   * @returns {number} Score between 0 and 1
   */
  async checkKeywords(repoPath, extensions, keywords, options = {}) {
    const { maxFileSize, sampleSize } = options;
    
    if (keywords.length === 0) return 0;

    const patterns = extensions.map(ext => `**/*${ext}`);
    
    try {
      const files = await glob(patterns, { 
        cwd: repoPath, 
        absolute: true,
        ignore: ['node_modules/**', '.git/**', '**/target/**', '**/build/**']
      });
      
      const sampleFiles = files.slice(0, sampleSize);
      if (sampleFiles.length === 0) return 0;

      let totalKeywords = 0;
      let foundKeywords = 0;
      
      for (const file of sampleFiles) {
        try {
          const stat = await fs.stat(file);
          if (stat.size > maxFileSize) continue;
          
          const content = await fs.readFile(file, 'utf8');
          
          for (const keyword of keywords) {
            totalKeywords++;
            if (content.includes(keyword)) {
              foundKeywords++;
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }

      return totalKeywords > 0 ? foundKeywords / totalKeywords : 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Get detailed information about a language in the repository
   * @param {string} repoPath - Repository path
   * @param {object} rules - Language detection rules
   * @returns {object} Language details
   */
  async getLanguageDetails(repoPath, rules) {
    const details = {
      files: { found: [], expected: rules.files },
      extensions: { count: 0, files: [] },
      directories: { found: [], expected: rules.directories },
      keywords: { found: [], expected: rules.keywords }
    };

    // Check files
    for (const file of rules.files) {
      try {
        const pattern = file.includes('*') ? file : `**/${file}`;
        const matches = await glob(pattern, { cwd: repoPath, absolute: false });
        details.files.found.push(...matches);
      } catch (error) {
        // Ignore errors
      }
    }

    // Check extensions
    const patterns = rules.extensions.map(ext => `**/*${ext}`);
    try {
      const files = await glob(patterns, { 
        cwd: repoPath, 
        absolute: false,
        ignore: ['node_modules/**', '.git/**', '**/target/**', '**/build/**']
      });
      details.extensions.count = files.length;
      details.extensions.files = files.slice(0, 10); // Sample
    } catch (error) {
      // Ignore errors
    }

    // Check directories
    for (const dir of rules.directories) {
      try {
        const dirPath = path.join(repoPath, dir);
        const stat = await fs.stat(dirPath);
        if (stat.isDirectory()) {
          details.directories.found.push(dir);
        }
      } catch (error) {
        // Ignore errors
      }
    }

    return details;
  }

  /**
   * Get supported languages
   * @returns {Array} Array of supported language names
   */
  getSupportedLanguages() {
    return Object.keys(this.detectionRules);
  }

  /**
   * Get detection rules for a specific language
   * @param {string} language - Language name
   * @returns {object|null} Detection rules or null if not found
   */
  getLanguageRules(language) {
    return this.detectionRules[language] || null;
  }

  /**
   * Add or update detection rules for a language
   * @param {string} language - Language name
   * @param {object} rules - Detection rules
   */
  addLanguageRules(language, rules) {
    // Validate rules structure
    const requiredFields = ['files', 'extensions', 'directories', 'keywords', 'weight'];
    for (const field of requiredFields) {
      if (!(field in rules)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    this.detectionRules[language] = rules;
  }
}

// Singleton instance
export const languageDetector = new LanguageDetector();