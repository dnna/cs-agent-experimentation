import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Plugin loader for managing language-specific plugins
 */
export class PluginLoader {
  constructor() {
    this.plugins = new Map();
    this.languageExtensions = new Map();
    this.buildFilePatterns = new Map();
    this.loaded = false;
  }

  /**
   * Load a single plugin from a file path
   * @param {string} pluginPath - Path to the plugin file
   * @returns {object} Loaded plugin instance
   */
  async loadPlugin(pluginPath) {
    try {
      const absolutePath = path.resolve(pluginPath);
      const { default: PluginClass } = await import(`file://${absolutePath}`);
      
      if (!PluginClass) {
        throw new Error(`Plugin at ${pluginPath} does not export a default class`);
      }

      const plugin = new PluginClass();
      
      // Validate plugin interface
      this.validatePlugin(plugin);
      
      // Register plugin
      this.plugins.set(plugin.name, plugin);
      
      // Map extensions to plugin
      for (const ext of plugin.supportedExtensions) {
        this.languageExtensions.set(ext, plugin.name);
      }
      
      // Map build files to plugin
      for (const buildFile of plugin.buildFiles) {
        this.buildFilePatterns.set(buildFile, plugin.name);
      }
      
      console.log(`[PluginLoader] Loaded plugin: ${plugin.name} v${plugin.version}`);
      return plugin;
    } catch (error) {
      console.error(`[PluginLoader] Failed to load plugin ${pluginPath}:`, error.message);
      throw new Error(`Failed to load plugin ${pluginPath}: ${error.message}`);
    }
  }

  /**
   * Load all plugins from the languages directory
   */
  async loadAllPlugins() {
    if (this.loaded) return;

    const languagesDir = path.join(__dirname, '../languages');
    
    try {
      const entries = await fs.readdir(languagesDir, { withFileTypes: true });
      const languageDirs = entries.filter(entry => entry.isDirectory()).map(entry => entry.name);
      
      const loadPromises = languageDirs.map(async (langDir) => {
        const pluginPath = path.join(languagesDir, langDir, `${langDir}-plugin.js`);
        
        try {
          await fs.access(pluginPath);
          return this.loadPlugin(pluginPath);
        } catch (error) {
          console.warn(`[PluginLoader] Plugin file not found: ${pluginPath}`);
          return null;
        }
      });

      const results = await Promise.allSettled(loadPromises);
      
      let loadedCount = 0;
      let failedCount = 0;
      
      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          loadedCount++;
        } else if (result.status === 'rejected') {
          failedCount++;
          console.error(`[PluginLoader] Failed to load plugin for ${languageDirs[index]}:`, result.reason);
        }
      });

      console.log(`[PluginLoader] Loaded ${loadedCount} plugins, ${failedCount} failed`);
      this.loaded = true;
    } catch (error) {
      console.error(`[PluginLoader] Failed to load plugins from ${languagesDir}:`, error.message);
      throw error;
    }
  }

  /**
   * Get plugin for a specific file based on extension
   * @param {string} filePath - File path
   * @returns {object|null} Plugin instance or null if not found
   */
  getPluginForFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const pluginName = this.languageExtensions.get(ext);
    return pluginName ? this.plugins.get(pluginName) : null;
  }

  /**
   * Get plugin for a specific language
   * @param {string} language - Language name
   * @returns {object|null} Plugin instance or null if not found
   */
  getPluginForLanguage(language) {
    return this.plugins.get(language.toLowerCase());
  }

  /**
   * Get plugin for a build file
   * @param {string} fileName - Build file name
   * @returns {object|null} Plugin instance or null if not found
   */
  getPluginForBuildFile(fileName) {
    // Check exact matches first
    const exactMatch = this.buildFilePatterns.get(fileName);
    if (exactMatch) {
      return this.plugins.get(exactMatch);
    }

    // Check pattern matches
    for (const [pattern, pluginName] of this.buildFilePatterns.entries()) {
      if (pattern.includes('*') && this.matchesPattern(fileName, pattern)) {
        return this.plugins.get(pluginName);
      }
    }

    return null;
  }

  /**
   * Get all loaded plugins
   * @returns {Array} Array of plugin instances
   */
  getAllPlugins() {
    return Array.from(this.plugins.values());
  }

  /**
   * Get plugin information
   * @returns {object} Plugin information
   */
  getPluginInfo() {
    const plugins = Array.from(this.plugins.values()).map(plugin => ({
      name: plugin.name,
      version: plugin.version,
      supportedExtensions: plugin.supportedExtensions,
      buildFiles: plugin.buildFiles,
      vulnerabilityTypes: plugin.vulnerabilityTypes
    }));

    return {
      loaded: this.loaded,
      count: plugins.length,
      plugins,
      extensionMappings: Object.fromEntries(this.languageExtensions),
      buildFileMappings: Object.fromEntries(this.buildFilePatterns)
    };
  }

  /**
   * Validate that a plugin implements the required interface
   * @param {object} plugin - Plugin instance to validate
   */
  validatePlugin(plugin) {
    const requiredProperties = ['name', 'version', 'supportedExtensions', 'buildFiles', 'vulnerabilityTypes'];
    const requiredMethods = ['parseFile', 'detectVulnerabilities', 'analyzeDependencies'];

    // Check required properties
    for (const prop of requiredProperties) {
      if (!(prop in plugin)) {
        throw new Error(`Plugin missing required property: ${prop}`);
      }
    }

    // Check required methods
    for (const method of requiredMethods) {
      if (typeof plugin[method] !== 'function') {
        throw new Error(`Plugin missing required method: ${method}`);
      }
    }

    // Validate property types
    if (typeof plugin.name !== 'string') {
      throw new Error('Plugin name must be a string');
    }

    if (typeof plugin.version !== 'string') {
      throw new Error('Plugin version must be a string');
    }

    if (!Array.isArray(plugin.supportedExtensions)) {
      throw new Error('Plugin supportedExtensions must be an array');
    }

    if (!Array.isArray(plugin.buildFiles)) {
      throw new Error('Plugin buildFiles must be an array');
    }

    if (!Array.isArray(plugin.vulnerabilityTypes)) {
      throw new Error('Plugin vulnerabilityTypes must be an array');
    }

    // Check for duplicate extensions
    const extensions = plugin.supportedExtensions;
    for (const ext of extensions) {
      if (this.languageExtensions.has(ext)) {
        const existingPlugin = this.languageExtensions.get(ext);
        if (existingPlugin !== plugin.name) {
          throw new Error(`Extension ${ext} is already registered by plugin ${existingPlugin}`);
        }
      }
    }
  }

  /**
   * Check if a filename matches a pattern
   * @param {string} fileName - File name to check
   * @param {string} pattern - Pattern to match against
   * @returns {boolean} True if matches
   */
  matchesPattern(fileName, pattern) {
    // Simple glob pattern matching
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    
    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(fileName);
  }

  /**
   * Reload all plugins (useful for development)
   */
  async reloadPlugins() {
    this.plugins.clear();
    this.languageExtensions.clear();
    this.buildFilePatterns.clear();
    this.loaded = false;
    
    await this.loadAllPlugins();
  }

  /**
   * Get statistics about loaded plugins
   * @returns {object} Statistics
   */
  getStats() {
    const stats = {
      totalPlugins: this.plugins.size,
      supportedExtensions: this.languageExtensions.size,
      buildFilePatterns: this.buildFilePatterns.size,
      plugins: {}
    };

    for (const [name, plugin] of this.plugins) {
      stats.plugins[name] = {
        version: plugin.version,
        extensionCount: plugin.supportedExtensions.length,
        buildFileCount: plugin.buildFiles.length,
        vulnerabilityTypeCount: plugin.vulnerabilityTypes.length
      };
    }

    return stats;
  }
}

// Singleton instance
export const pluginLoader = new PluginLoader();