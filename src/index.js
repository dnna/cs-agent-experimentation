/**
 * Main entry point for the AI-Powered Agentic Vulnerability Scanner
 */

export { VulnerabilityCoordinator } from './core/coordinator.js';
export { AgentManager } from './core/agent-manager.js';
export { PluginLoader } from './core/plugin-loader.js';
export { LanguageDetector } from './tools/language-detector.js';
export { StateStore } from './core/state-store.js';
export { MessageBus } from './core/message-bus.js';

// Base classes
export { BaseAgent } from './agents/base-agent.js';
export { BaseLanguagePlugin } from './languages/base-language-plugin.js';

// Agents
export { ExplorerAgent } from './agents/explorer-agent.js';
export { ParserAgent } from './agents/parser-agent.js';
export { AnalyzerAgent } from './agents/analyzer-agent.js';
export { ValidatorAgent } from './agents/validator-agent.js';
export { ReporterAgent } from './agents/reporter-agent.js';

// Language plugins
export { JavaLanguagePlugin } from './languages/java/java-plugin.js';

// Evaluation
export { OwaspBenchmarkEvaluator } from './evaluation/owasp-benchmark.js';

// CLI
export { default as ScannerCLI } from './cli/scanner-cli.js';

// Default export
export { VulnerabilityCoordinator as default } from './core/coordinator.js';