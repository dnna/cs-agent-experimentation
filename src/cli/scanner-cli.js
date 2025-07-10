#!/usr/bin/env node

import { Command } from 'commander';
import { VulnerabilityCoordinator } from '../core/coordinator.js';
import { promises as fs } from 'fs';
import path from 'path';

/**
 * CLI interface for the vulnerability scanner
 */
class ScannerCLI {
  constructor() {
    this.program = new Command();
    this.coordinator = new VulnerabilityCoordinator();
    this.setupCommands();
  }

  /**
   * Setup CLI commands
   */
  setupCommands() {
    this.program
      .name('aavs')
      .description('AI-Powered Agentic Vulnerability Scanner')
      .version('1.0.0');

    // Main scan command
    this.program
      .command('scan')
      .description('Scan a repository for vulnerabilities')
      .argument('<repository>', 'Path to repository to scan')
      .option('-l, --language <language>', 'Force specific language (auto-detect if not specified)')
      .option('-o, --output <format>', 'Output format (json, html, markdown)', 'json')
      .option('-f, --file <path>', 'Output file path')
      .option('--max-files <number>', 'Maximum number of files to analyze', parseInt, 10000)
      .option('--max-size <size>', 'Maximum file size in bytes', parseInt, 5242880)
      .option('--confidence <threshold>', 'Minimum confidence threshold', parseFloat, 0.5)
      .option('--ai', 'Enable AI-powered analysis')
      .option('--verbose', 'Enable verbose logging')
      .option('--include-tests', 'Include test files in analysis')
      .action(async (repository, options) => {
        await this.handleScanCommand(repository, options);
      });

    // Language detection command
    this.program
      .command('detect')
      .description('Detect programming languages in a repository')
      .argument('<repository>', 'Path to repository to analyze')
      .option('-o, --output <format>', 'Output format (json, table)', 'table')
      .action(async (repository, options) => {
        await this.handleDetectCommand(repository, options);
      });

    // Dependency analysis command
    this.program
      .command('dependencies')
      .description('Analyze dependencies for vulnerabilities')
      .argument('<repository>', 'Path to repository to analyze')
      .option('-l, --language <language>', 'Force specific language (auto-detect if not specified)')
      .option('-o, --output <format>', 'Output format (json, html, markdown)', 'json')
      .option('-f, --file <path>', 'Output file path')
      .option('--verbose', 'Enable verbose logging')
      .action(async (repository, options) => {
        await this.handleDependenciesCommand(repository, options);
      });

    // Plugin management commands
    this.program
      .command('plugins')
      .description('List available language plugins')
      .action(async () => {
        await this.handlePluginsCommand();
      });

    // Benchmark command
    this.program
      .command('benchmark')
      .description('Run OWASP Benchmark evaluation')
      .argument('<benchmark-path>', 'Path to OWASP Benchmark')
      .option('-o, --output <format>', 'Output format (json, html)', 'json')
      .option('-f, --file <path>', 'Output file path')
      .option('--verbose', 'Enable verbose logging')
      .action(async (benchmarkPath, options) => {
        await this.handleBenchmarkCommand(benchmarkPath, options);
      });

    // Version command
    this.program
      .command('version')
      .description('Show version information')
      .action(() => {
        this.showVersion();
      });

    // Help command
    this.program
      .command('help')
      .description('Show help information')
      .action(() => {
        this.program.help();
      });
  }

  /**
   * Handle scan command
   */
  async handleScanCommand(repository, options) {
    try {
      console.log('🔍 Starting vulnerability scan...');
      
      // Validate repository path
      await this.validateRepositoryPath(repository);
      
      // Setup logging
      if (options.verbose) {
        this.enableVerboseLogging();
      }
      
      // Initialize coordinator
      await this.coordinator.initialize();
      
      // Configure scan options
      const scanOptions = {
        language: options.language,
        maxFiles: options.maxFiles,
        maxSize: options.maxSize,
        confidenceThreshold: options.confidence,
        enableAI: options.ai,
        includeTests: options.includeTests
      };
      
      console.log(`Repository: ${repository}`);
      if (options.language) {
        console.log(`Language: ${options.language}`);
      }
      console.log(`Max files: ${options.maxFiles}`);
      console.log(`Confidence threshold: ${options.confidence}`);
      console.log('');
      
      // Perform scan
      const results = await this.coordinator.scanRepository(repository, scanOptions);
      
      // Output results
      await this.outputResults(results, options.output, options.file);
      
      // Show summary
      this.showScanSummary(results);
      
    } catch (error) {
      console.error('❌ Scan failed:', error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  }

  /**
   * Handle detect command
   */
  async handleDetectCommand(repository, options) {
    try {
      console.log('🔍 Detecting programming languages...');
      
      // Validate repository path
      await this.validateRepositoryPath(repository);
      
      // Initialize coordinator
      await this.coordinator.initialize();
      
      // Detect languages
      const detection = await this.coordinator.languageDetector.detectLanguages(repository);
      
      // Output results
      if (options.output === 'json') {
        console.log(JSON.stringify(detection, null, 2));
      } else {
        this.showLanguageDetectionTable(detection);
      }
      
    } catch (error) {
      console.error('❌ Language detection failed:', error.message);
      process.exit(1);
    }
  }

  /**
   * Handle dependencies command
   */
  async handleDependenciesCommand(repository, options) {
    try {
      console.log('🔍 Analyzing dependencies...');
      
      // Validate repository path
      await this.validateRepositoryPath(repository);
      
      // Setup logging
      if (options.verbose) {
        this.enableVerboseLogging();
      }
      
      // Initialize coordinator
      await this.coordinator.initialize();
      
      // Analyze dependencies
      const results = await this.coordinator.analyzeDependencies(repository, {
        language: options.language
      });
      
      // Output results
      await this.outputResults(results, options.output, options.file);
      
      // Show summary
      this.showDependencySummary(results);
      
    } catch (error) {
      console.error('❌ Dependency analysis failed:', error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  }

  /**
   * Handle plugins command
   */
  async handlePluginsCommand() {
    try {
      console.log('📋 Available language plugins:');
      
      // Initialize coordinator
      await this.coordinator.initialize();
      
      // Get plugin info
      const pluginInfo = this.coordinator.pluginLoader.getPluginInfo();
      
      this.showPluginTable(pluginInfo);
      
    } catch (error) {
      console.error('❌ Failed to list plugins:', error.message);
      process.exit(1);
    }
  }

  /**
   * Handle benchmark command
   */
  async handleBenchmarkCommand(benchmarkPath, options) {
    try {
      console.log('📊 Running OWASP Benchmark evaluation...');
      
      // Validate benchmark path
      await this.validateRepositoryPath(benchmarkPath);
      
      // Setup logging
      if (options.verbose) {
        this.enableVerboseLogging();
      }
      
      // Initialize coordinator
      await this.coordinator.initialize();
      
      // Run benchmark
      const results = await this.coordinator.runBenchmark(benchmarkPath);
      
      // Output results
      await this.outputResults(results, options.output, options.file);
      
      // Show summary
      this.showBenchmarkSummary(results);
      
    } catch (error) {
      console.error('❌ Benchmark evaluation failed:', error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  }

  /**
   * Validate repository path
   */
  async validateRepositoryPath(repositoryPath) {
    try {
      const stats = await fs.stat(repositoryPath);
      if (!stats.isDirectory()) {
        throw new Error(`Path is not a directory: ${repositoryPath}`);
      }
    } catch (error) {
      throw new Error(`Invalid repository path: ${repositoryPath}`);
    }
  }

  /**
   * Enable verbose logging
   */
  enableVerboseLogging() {
    // Enable debug logging
    process.env.DEBUG = 'true';
    console.log('📝 Verbose logging enabled');
  }

  /**
   * Output results
   */
  async outputResults(results, format, filePath) {
    let output;
    
    if (format === 'json') {
      output = JSON.stringify(results, null, 2);
    } else if (format === 'html') {
      output = await this.generateHtmlOutput(results);
    } else if (format === 'markdown') {
      output = await this.generateMarkdownOutput(results);
    } else {
      throw new Error(`Unsupported output format: ${format}`);
    }
    
    if (filePath) {
      await fs.writeFile(filePath, output, 'utf8');
      console.log(`📄 Results saved to: ${filePath}`);
    } else {
      console.log(output);
    }
  }

  /**
   * Show scan summary
   */
  showScanSummary(results) {
    console.log('\n📊 Scan Summary:');
    console.log(`├── Languages detected: ${results.languages.primary} ${results.languages.secondary.length > 0 ? `(+${results.languages.secondary.join(', ')})` : ''}`);
    console.log(`├── Vulnerabilities found: ${results.vulnerabilities.length}`);
    
    if (results.vulnerabilities.length > 0) {
      const severityCounts = this.countBySeverity(results.vulnerabilities);
      console.log(`├── Severity breakdown:`);
      console.log(`│   ├── Critical: ${severityCounts.CRITICAL || 0}`);
      console.log(`│   ├── High: ${severityCounts.HIGH || 0}`);
      console.log(`│   ├── Medium: ${severityCounts.MEDIUM || 0}`);
      console.log(`│   └── Low: ${severityCounts.LOW || 0}`);
    }
    
    console.log(`└── Scan completed in ${this.formatDuration(results.duration)}`);
    
    if (results.vulnerabilities.length > 0) {
      console.log('\n⚠️  Vulnerabilities detected! Review the results above.');
    } else {
      console.log('\n✅ No vulnerabilities detected.');
    }
  }

  /**
   * Show dependency summary
   */
  showDependencySummary(results) {
    console.log('\n📊 Dependency Analysis Summary:');
    console.log(`├── Dependencies analyzed: ${results.stats?.dependenciesAnalyzed || 0}`);
    console.log(`├── Vulnerabilities found: ${results.vulnerabilities.length}`);
    
    if (results.vulnerabilities.length > 0) {
      const severityCounts = this.countBySeverity(results.vulnerabilities);
      console.log(`├── Severity breakdown:`);
      console.log(`│   ├── Critical: ${severityCounts.CRITICAL || 0}`);
      console.log(`│   ├── High: ${severityCounts.HIGH || 0}`);
      console.log(`│   ├── Medium: ${severityCounts.MEDIUM || 0}`);
      console.log(`│   └── Low: ${severityCounts.LOW || 0}`);
    }
    
    console.log(`└── Analysis completed`);
  }

  /**
   * Show benchmark summary
   */
  showBenchmarkSummary(results) {
    console.log('\n📊 Benchmark Results:');
    console.log(`├── Precision: ${(results.precision * 100).toFixed(1)}%`);
    console.log(`├── Recall: ${(results.recall * 100).toFixed(1)}%`);
    console.log(`├── F1-Score: ${(results.f1Score * 100).toFixed(1)}%`);
    console.log(`├── Accuracy: ${(results.accuracy * 100).toFixed(1)}%`);
    console.log(`└── Test cases: ${results.totalTestCases}`);
  }

  /**
   * Show language detection table
   */
  showLanguageDetectionTable(detection) {
    console.log('\n📋 Language Detection Results:');
    console.log(`Primary language: ${detection.primary || 'None detected'}`);
    console.log(`Secondary languages: ${detection.secondary.length > 0 ? detection.secondary.join(', ') : 'None'}`);
    console.log('\nConfidence scores:');
    
    const sortedLanguages = Object.entries(detection.confidence)
      .sort(([,a], [,b]) => b - a)
      .filter(([,confidence]) => confidence > 0);
    
    for (const [language, confidence] of sortedLanguages) {
      const percentage = (confidence * 100).toFixed(1);
      const bar = '█'.repeat(Math.round(confidence * 20));
      console.log(`├── ${language.padEnd(12)} ${percentage.padStart(5)}% ${'│'.padEnd(1)}${bar}`);
    }
  }

  /**
   * Show plugin table
   */
  showPluginTable(pluginInfo) {
    console.log(`\nTotal plugins: ${pluginInfo.count}`);
    console.log('\nPlugin details:');
    
    for (const plugin of pluginInfo.plugins) {
      console.log(`├── ${plugin.name} (v${plugin.version})`);
      console.log(`│   ├── Extensions: ${plugin.supportedExtensions.join(', ')}`);
      console.log(`│   ├── Build files: ${plugin.buildFiles.join(', ')}`);
      console.log(`│   └── Vulnerability types: ${plugin.vulnerabilityTypes.length}`);
    }
  }

  /**
   * Generate HTML output
   */
  async generateHtmlOutput(results) {
    // Basic HTML output - can be enhanced
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .vulnerability { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Results</h1>
    <h2>Summary</h2>
    <p>Total vulnerabilities: ${results.vulnerabilities.length}</p>
    
    <h2>Vulnerabilities</h2>
    ${results.vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity.toLowerCase()}">
            <h3>${vuln.type} - ${vuln.severity}</h3>
            <p><strong>File:</strong> ${vuln.file}</p>
            <p><strong>Line:</strong> ${vuln.line}</p>
            <p><strong>Description:</strong> ${vuln.description}</p>
        </div>
    `).join('')}
</body>
</html>
    `;
  }

  /**
   * Generate Markdown output
   */
  async generateMarkdownOutput(results) {
    let markdown = '# Vulnerability Scan Results\n\n';
    markdown += `## Summary\n\n`;
    markdown += `- **Total vulnerabilities:** ${results.vulnerabilities.length}\n`;
    markdown += `- **Languages:** ${results.languages.primary}\n\n`;
    
    markdown += `## Vulnerabilities\n\n`;
    for (const vuln of results.vulnerabilities) {
      markdown += `### ${vuln.type} - ${vuln.severity}\n\n`;
      markdown += `- **File:** ${vuln.file}\n`;
      markdown += `- **Line:** ${vuln.line}\n`;
      markdown += `- **Description:** ${vuln.description}\n\n`;
    }
    
    return markdown;
  }

  /**
   * Count vulnerabilities by severity
   */
  countBySeverity(vulnerabilities) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const vuln of vulnerabilities) {
      counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
    }
    return counts;
  }

  /**
   * Format duration
   */
  formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  }

  /**
   * Show version information
   */
  showVersion() {
    console.log('AI-Powered Agentic Vulnerability Scanner v1.0.0');
    console.log('Built for cybersecurity thesis research');
    console.log('Node.js version:', process.version);
  }

  /**
   * Run the CLI
   */
  async run() {
    try {
      await this.program.parseAsync(process.argv);
    } catch (error) {
      console.error('❌ CLI error:', error.message);
      process.exit(1);
    }
  }
}

// Run CLI if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const cli = new ScannerCLI();
  cli.run();
}

export default ScannerCLI;