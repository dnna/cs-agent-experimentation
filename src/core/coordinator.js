import { agentManager } from './agent-manager.js';
import { pluginLoader } from './plugin-loader.js';
import { languageDetector } from '../tools/language-detector.js';
import { stateStore } from './state-store.js';
import { messageBus } from './message-bus.js';
import { logger } from './logger.js';

/**
 * Main coordinator for orchestrating vulnerability scanning
 */
export class VulnerabilityCoordinator {
  constructor() {
    this.agentManager = agentManager;
    this.pluginLoader = pluginLoader;
    this.languageDetector = languageDetector;
    this.stateStore = stateStore;
    this.messageBus = messageBus;
    this.initialized = false;
  }

  /**
   * Initialize the coordinator
   */
  async initialize() {
    if (this.initialized) return;

    logger.always('🚀 Initializing AI-Powered Agentic Vulnerability Scanner...');

    try {
      // Initialize core components
      await this.stateStore.initialize();
      await this.pluginLoader.loadAllPlugins();
      await this.agentManager.initialize();

      this.initialized = true;
      logger.always('✅ Scanner initialized successfully');
      
      // Log loaded plugins
      const pluginInfo = this.pluginLoader.getPluginInfo();
      logger.log(`📦 Loaded ${pluginInfo.count} language plugins: ${pluginInfo.plugins.map(p => p.name).join(', ')}`);
      
    } catch (error) {
      logger.error('❌ Failed to initialize scanner:', error.message);
      throw error;
    }
  }

  /**
   * Scan a repository for vulnerabilities
   * @param {string} repositoryPath - Path to repository
   * @param {object} options - Scan options
   * @returns {object} Scan results
   */
  async scanRepository(repositoryPath, options = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const startTime = Date.now();
    logger.always(`🔍 Starting scan of repository: ${repositoryPath}`);

    try {
      // Create scan session
      const sessionId = await this.stateStore.createSession(repositoryPath, options);
      
      // Step 1: Detect languages or use forced language
      let languageDetection;
      if (options.language) {
        logger.log(`🔍 Using forced language: ${options.language}`);
        languageDetection = {
          primary: options.language,
          secondary: [],
          confidence: { [options.language]: 1.0 },
          details: {}
        };
      } else {
        logger.log('🔍 Detecting programming languages...');
        languageDetection = await this.languageDetector.detectLanguages(repositoryPath);
        
        if (!languageDetection.primary) {
          throw new Error('No supported programming languages detected in repository');
        }
      }

      logger.always(`📝 Primary language: ${languageDetection.primary}`);
      if (languageDetection.secondary.length > 0) {
        logger.log(`📝 Secondary languages: ${languageDetection.secondary.join(', ')}`);
      }

      // Step 2: Load appropriate plugins
      const activePlugins = await this.loadActivePlugins(languageDetection, options);
      
      // Step 3: Scan with each plugin
      const allResults = {
        repository: repositoryPath,
        sessionId,
        languages: languageDetection,
        vulnerabilities: [],
        metrics: {},
        timestamp: new Date().toISOString(),
        duration: 0
      };

      for (const plugin of activePlugins) {
        logger.log(`🔍 Scanning with ${plugin.name} plugin...`);
        
        try {
          const pluginResults = await this.scanWithPlugin(repositoryPath, plugin, options, sessionId);
          
          // Merge results
          allResults.vulnerabilities.push(...pluginResults.vulnerabilities);
          allResults.metrics[plugin.name] = pluginResults.metrics;
          
          logger.log(`✅ ${plugin.name} scan completed: ${pluginResults.vulnerabilities.length} vulnerabilities found`);
          
        } catch (error) {
          logger.error(`❌ ${plugin.name} scan failed:`, error.message);
          allResults.metrics[plugin.name] = {
            error: error.message,
            vulnerabilitiesFound: 0
          };
        }
      }

      // Step 4: Update session with results
      const duration = Date.now() - startTime;
      allResults.duration = duration;
      
      await this.stateStore.updateSession(sessionId, 'completed', allResults);

      logger.always(`✅ Scan completed in ${this.formatDuration(duration)}`);
      logger.always(`📊 Total vulnerabilities found: ${allResults.vulnerabilities.length}`);

      return allResults;

    } catch (error) {
      logger.error('❌ Scan failed:', error.message);
      throw error;
    }
  }

  /**
   * Analyze dependencies for vulnerabilities
   * @param {string} repositoryPath - Path to repository
   * @param {object} options - Analysis options
   * @returns {object} Analysis results
   */
  async analyzeDependencies(repositoryPath, options = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    logger.log(`🔍 Analyzing dependencies in: ${repositoryPath}`);

    try {
      // Create analysis session
      const sessionId = await this.stateStore.createSession(repositoryPath, { 
        ...options, 
        type: 'dependency_analysis' 
      });

      // Detect languages if not specified
      let targetLanguage = options.language;
      if (!targetLanguage) {
        const languageDetection = await this.languageDetector.detectLanguages(repositoryPath);
        targetLanguage = languageDetection.primary;
      }

      if (!targetLanguage) {
        throw new Error('No supported programming languages detected');
      }

      // Load plugin for target language
      const plugin = this.pluginLoader.getPluginForLanguage(targetLanguage);
      if (!plugin) {
        throw new Error(`No plugin available for language: ${targetLanguage}`);
      }

      logger.log(`📝 Using ${plugin.name} plugin for dependency analysis`);

      // Run dependency analysis workflow
      const results = await this.agentManager.orchestrateWorkflow(
        'dependency_analysis',
        { repositoryPath, languagePlugin: plugin },
        sessionId
      );

      // Update session with results
      await this.stateStore.updateSession(sessionId, 'completed', results);

      logger.always(`✅ Dependency analysis completed`);
      logger.always(`📊 Dependency vulnerabilities found: ${results.vulnerabilities.length}`);

      return results;

    } catch (error) {
      logger.error('❌ Dependency analysis failed:', error.message);
      throw error;
    }
  }

  /**
   * Run OWASP Benchmark evaluation
   * @param {string} benchmarkPath - Path to OWASP Benchmark
   * @param {object} options - Benchmark options
   * @returns {object} Benchmark results
   */
  async runBenchmark(benchmarkPath, options = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    logger.log(`📊 Running OWASP Benchmark evaluation: ${benchmarkPath}`);

    try {
      // Import benchmark evaluator
      const { OwaspBenchmarkEvaluator } = await import('../evaluation/owasp-benchmark.js');
      const evaluator = new OwaspBenchmarkEvaluator();

      // Load benchmark
      await evaluator.loadBenchmark(benchmarkPath);

      // Scan benchmark with our tool
      const scanResults = await this.scanRepository(benchmarkPath, {
        language: 'java',
        ...options
      });

      // Evaluate results against expected outcomes
      const benchmarkResults = await evaluator.evaluateResults(scanResults.vulnerabilities);

      logger.always(`✅ Benchmark evaluation completed`);
      logger.always(`📊 Precision: ${(benchmarkResults.precision * 100).toFixed(1)}%`);
      logger.always(`📊 Recall: ${(benchmarkResults.recall * 100).toFixed(1)}%`);
      logger.always(`📊 F1-Score: ${(benchmarkResults.f1Score * 100).toFixed(1)}%`);

      return {
        ...benchmarkResults,
        scanResults,
        benchmarkPath,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      logger.error('❌ Benchmark evaluation failed:', error.message);
      throw error;
    }
  }

  /**
   * Load active plugins based on language detection
   * @param {object} languageDetection - Language detection results
   * @param {object} options - Scan options
   * @returns {Array} Active plugins
   */
  async loadActivePlugins(languageDetection, options) {
    const activePlugins = [];

    // Force specific language if specified
    if (options.language) {
      const plugin = this.pluginLoader.getPluginForLanguage(options.language);
      if (!plugin) {
        throw new Error(`No plugin available for language: ${options.language}`);
      }
      activePlugins.push(plugin);
      return activePlugins;
    }

    // Load plugin for primary language
    if (languageDetection.primary) {
      const primaryPlugin = this.pluginLoader.getPluginForLanguage(languageDetection.primary);
      if (primaryPlugin) {
        activePlugins.push(primaryPlugin);
      }
    }

    // Load plugins for secondary languages (if confidence is high enough)
    for (const secondaryLang of languageDetection.secondary) {
      const confidence = languageDetection.confidence[secondaryLang];
      if (confidence >= 0.5) { // Only load if confidence is reasonable
        const plugin = this.pluginLoader.getPluginForLanguage(secondaryLang);
        if (plugin) {
          activePlugins.push(plugin);
        }
      }
    }

    if (activePlugins.length === 0) {
      throw new Error('No plugins could be loaded for detected languages');
    }

    return activePlugins;
  }

  /**
   * Scan repository with a specific plugin
   * @param {string} repositoryPath - Repository path
   * @param {object} plugin - Language plugin
   * @param {object} options - Scan options
   * @param {string} sessionId - Session ID
   * @returns {object} Scan results
   */
  async scanWithPlugin(repositoryPath, plugin, options, sessionId) {
    try {
      // Run vulnerability scan workflow
      const results = await this.agentManager.orchestrateWorkflow(
        'vulnerability_scan',
        { 
          repositoryPath, 
          languagePlugin: plugin,
          ...options 
        },
        sessionId
      );

      return results;

    } catch (error) {
      logger.error(`Plugin scan failed for ${plugin.name}:`, error.message);
      throw error;
    }
  }

  /**
   * Get scan history
   * @returns {Array} Scan history
   */
  async getScanHistory() {
    return await this.stateStore.getAllSessions();
  }

  /**
   * Get scan session details
   * @param {string} sessionId - Session ID
   * @returns {object} Session details
   */
  async getSessionDetails(sessionId) {
    return await this.stateStore.getSession(sessionId);
  }

  /**
   * Get scanner statistics
   * @returns {object} Scanner statistics
   */
  getStatistics() {
    return {
      plugins: this.pluginLoader.getStats(),
      agents: this.agentManager.getAgentStats(),
      messageBus: this.messageBus.getStats(),
      sessions: this.stateStore.cache.size
    };
  }

  /**
   * Format duration in human readable format
   * @param {number} ms - Duration in milliseconds
   * @returns {string} Formatted duration
   */
  formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  }

  /**
   * Validate repository path
   * @param {string} repositoryPath - Repository path
   * @returns {boolean} True if valid
   */
  async validateRepository(repositoryPath) {
    try {
      const { promises: fs } = await import('fs');
      const stats = await fs.stat(repositoryPath);
      return stats.isDirectory();
    } catch (error) {
      return false;
    }
  }

  /**
   * Cleanup coordinator resources
   */
  async cleanup() {
    logger.log('🧹 Cleaning up coordinator resources...');
    
    try {
      await this.agentManager.cleanup();
      await this.stateStore.close();
      
      logger.log('✅ Cleanup completed');
    } catch (error) {
      logger.error('❌ Cleanup failed:', error.message);
    }
  }

  /**
   * Handle process termination
   */
  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      logger.always(`\n🛑 Received ${signal}, shutting down gracefully...`);
      await this.cleanup();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    process.on('uncaughtException', async (error) => {
      logger.error('❌ Uncaught exception:', error);
      await this.cleanup();
      process.exit(1);
    });
  }
}

// Export singleton instance
export const vulnerabilityCoordinator = new VulnerabilityCoordinator();
export default VulnerabilityCoordinator;