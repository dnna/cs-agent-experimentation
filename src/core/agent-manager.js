import { messageBus } from './message-bus.js';
import { stateStore } from './state-store.js';
import { BaseAgent } from '../agents/base-agent.js';
import { ExplorerAgent } from '../agents/explorer-agent.js';
import { ParserAgent } from '../agents/parser-agent.js';
import { AnalyzerAgent } from '../agents/analyzer-agent.js';
import { ValidatorAgent } from '../agents/validator-agent.js';
import { ReporterAgent } from '../agents/reporter-agent.js';
import { logger } from './logger.js';

/**
 * Agent manager for spawning, monitoring, and coordinating agents
 */
export class AgentManager {
  constructor() {
    this.agents = new Map();
    this.agentTypes = new Map();
    this.maxConcurrentAgents = 10;
    this.agentCounter = 0;
    this.initialized = false;
  }

  /**
   * Initialize the agent manager
   */
  async initialize() {
    if (this.initialized) return;

    // Register built-in agent types
    this.registerAgentType('explorer', ExplorerAgent);
    this.registerAgentType('parser', ParserAgent);
    this.registerAgentType('analyzer', AnalyzerAgent);
    this.registerAgentType('validator', ValidatorAgent);
    this.registerAgentType('reporter', ReporterAgent);

    // Subscribe to agent lifecycle events
    messageBus.subscribe('agent.created', this.handleAgentCreated.bind(this), 'AgentManager');
    messageBus.subscribe('agent.completed', this.handleAgentCompleted.bind(this), 'AgentManager');
    messageBus.subscribe('agent.failed', this.handleAgentFailed.bind(this), 'AgentManager');
    messageBus.subscribe('agent.terminated', this.handleAgentTerminated.bind(this), 'AgentManager');

    this.initialized = true;
  }

  /**
   * Register a new agent type
   * @param {string} type - Agent type name
   * @param {Class} AgentClass - Agent class constructor
   */
  registerAgentType(type, AgentClass) {
    if (!AgentClass.prototype instanceof BaseAgent) {
      throw new Error(`Agent class must extend BaseAgent: ${type}`);
    }

    this.agentTypes.set(type, AgentClass);
    logger.log(`[AgentManager] Registered agent type: ${type}`);
  }

  /**
   * Spawn a new agent
   * @param {string} type - Agent type
   * @param {object} config - Agent configuration
   * @param {string} sessionId - Session ID
   * @returns {string} Agent ID
   */
  async spawnAgent(type, config = {}, sessionId = null) {
    if (!this.initialized) {
      await this.initialize();
    }

    // Check if agent type exists
    if (!this.agentTypes.has(type)) {
      throw new Error(`Unknown agent type: ${type}`);
    }

    // Check concurrent agent limit
    if (this.agents.size >= this.maxConcurrentAgents) {
      throw new Error(`Maximum concurrent agents reached: ${this.maxConcurrentAgents}`);
    }

    // Create agent instance
    const AgentClass = this.agentTypes.get(type);
    const agentId = this.generateAgentId(type);
    const agent = new AgentClass(agentId, config, sessionId);

    // Initialize agent
    await agent.initialize();

    // Register agent
    this.agents.set(agentId, agent);

    // Update state store
    if (sessionId) {
      await stateStore.updateAgentState(sessionId, type, agentId, 'spawned', config);
    }

    // Notify about agent creation
    messageBus.publish('agent.created', {
      agentId,
      type,
      config,
      sessionId
    }, 'AgentManager');

    logger.log(`[AgentManager] Spawned agent: ${agentId} (${type})`);
    return agentId;
  }

  /**
   * Get agent by ID
   * @param {string} agentId - Agent ID
   * @returns {object|null} Agent instance or null
   */
  getAgent(agentId) {
    return this.agents.get(agentId) || null;
  }

  /**
   * Get all agents of a specific type
   * @param {string} type - Agent type
   * @returns {Array} Array of agents
   */
  getAgentsByType(type) {
    return Array.from(this.agents.values()).filter(agent => agent.type === type);
  }

  /**
   * Get all agents for a session
   * @param {string} sessionId - Session ID
   * @returns {Array} Array of agents
   */
  getAgentsBySession(sessionId) {
    return Array.from(this.agents.values()).filter(agent => agent.sessionId === sessionId);
  }

  /**
   * Start an agent's execution
   * @param {string} agentId - Agent ID
   * @param {object} input - Input data for the agent
   * @returns {Promise} Agent execution promise
   */
  async startAgent(agentId, input = {}) {
    const agent = this.getAgent(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status !== 'idle') {
      throw new Error(`Agent is not idle: ${agentId} (status: ${agent.status})`);
    }

    try {
      // Update agent state
      await this.updateAgentState(agentId, 'running');

      // Start agent execution
      const result = await agent.execute(input);

      // Update agent state
      await this.updateAgentState(agentId, 'completed', result);

      // Notify about completion
      messageBus.publish('agent.completed', {
        agentId,
        result,
        sessionId: agent.sessionId
      }, 'AgentManager');

      return result;
    } catch (error) {
      // Update agent state
      await this.updateAgentState(agentId, 'failed', { error: error.message });

      // Notify about failure
      messageBus.publish('agent.failed', {
        agentId,
        error: error.message,
        sessionId: agent.sessionId
      }, 'AgentManager');

      throw error;
    }
  }

  /**
   * Terminate an agent
   * @param {string} agentId - Agent ID
   * @param {string} reason - Termination reason
   */
  async terminateAgent(agentId, reason = 'manual') {
    const agent = this.getAgent(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    try {
      // Terminate agent
      await agent.terminate(reason);

      // Update state
      await this.updateAgentState(agentId, 'terminated', { reason });

      // Remove from active agents
      this.agents.delete(agentId);

      // Notify about termination
      messageBus.publish('agent.terminated', {
        agentId,
        reason,
        sessionId: agent.sessionId
      }, 'AgentManager');

      logger.log(`[AgentManager] Terminated agent: ${agentId} (${reason})`);
    } catch (error) {
      logger.error(`[AgentManager] Error terminating agent ${agentId}:`, error.message);
      throw error;
    }
  }

  /**
   * Terminate all agents for a session
   * @param {string} sessionId - Session ID
   * @param {string} reason - Termination reason
   */
  async terminateSessionAgents(sessionId, reason = 'session_ended') {
    const sessionAgents = this.getAgentsBySession(sessionId);
    
    const terminationPromises = sessionAgents.map(agent => 
      this.terminateAgent(agent.id, reason)
    );

    await Promise.allSettled(terminationPromises);
  }

  /**
   * Terminate all agents
   * @param {string} reason - Termination reason
   */
  async terminateAllAgents(reason = 'shutdown') {
    const terminationPromises = Array.from(this.agents.keys()).map(agentId => 
      this.terminateAgent(agentId, reason)
    );

    await Promise.allSettled(terminationPromises);
  }

  /**
   * Update agent state
   * @param {string} agentId - Agent ID
   * @param {string} status - New status
   * @param {object} data - Additional data
   */
  async updateAgentState(agentId, status, data = null) {
    const agent = this.getAgent(agentId);
    if (!agent) return;

    // Update agent status
    agent.status = status;
    agent.lastUpdate = new Date().toISOString();

    // Update state store
    if (agent.sessionId) {
      await stateStore.updateAgentState(
        agent.sessionId,
        agent.type,
        agentId,
        status,
        data
      );
    }

    // Publish state update
    messageBus.publish('agent.state_updated', {
      agentId,
      status,
      data,
      sessionId: agent.sessionId
    }, 'AgentManager');
  }

  /**
   * Get agent statistics
   * @returns {object} Agent statistics
   */
  getAgentStats() {
    const stats = {
      total: this.agents.size,
      byType: {},
      byStatus: {},
      bySession: {}
    };

    for (const agent of this.agents.values()) {
      // Count by type
      stats.byType[agent.type] = (stats.byType[agent.type] || 0) + 1;
      
      // Count by status
      stats.byStatus[agent.status] = (stats.byStatus[agent.status] || 0) + 1;
      
      // Count by session
      if (agent.sessionId) {
        stats.bySession[agent.sessionId] = (stats.bySession[agent.sessionId] || 0) + 1;
      }
    }

    stats.maxConcurrent = this.maxConcurrentAgents;
    stats.registeredTypes = Array.from(this.agentTypes.keys());

    return stats;
  }

  /**
   * Orchestrate a multi-agent workflow
   * @param {string} workflow - Workflow name
   * @param {object} input - Input data
   * @param {string} sessionId - Session ID
   * @returns {object} Workflow result
   */
  async orchestrateWorkflow(workflow, input, sessionId) {
    switch (workflow) {
      case 'vulnerability_scan':
        return await this.orchestrateVulnerabilityScan(input, sessionId);
      case 'dependency_analysis':
        return await this.orchestrateDependencyAnalysis(input, sessionId);
      default:
        throw new Error(`Unknown workflow: ${workflow}`);
    }
  }

  /**
   * Orchestrate vulnerability scan workflow
   * @param {object} input - Input data
   * @param {string} sessionId - Session ID
   * @returns {object} Scan result
   */
  async orchestrateVulnerabilityScan(input, sessionId) {
    const { repositoryPath, languagePlugin } = input;
    
    try {
      // Step 1: Spawn Explorer Agent
      const explorerId = await this.spawnAgent('explorer', {
        repositoryPath,
        plugin: languagePlugin
      }, sessionId);

      // Step 2: Discover files
      const explorerResult = await this.startAgent(explorerId, { repositoryPath });
      const files = explorerResult.files;

      // Step 3: Spawn Parser Agent
      const parserId = await this.spawnAgent('parser', {
        plugin: languagePlugin
      }, sessionId);

      // Step 4: Parse files
      const parserResult = await this.startAgent(parserId, { files });
      const parsedFiles = parserResult.files;

      // Step 5: Spawn Analyzer Agent
      const analyzerId = await this.spawnAgent('analyzer', {
        plugin: languagePlugin
      }, sessionId);

      // Step 6: Analyze for vulnerabilities
      const analyzerResult = await this.startAgent(analyzerId, { parsedFiles });
      
      // Step 7: Spawn Validator Agent
      const validatorId = await this.spawnAgent('validator', {
        plugin: languagePlugin
      }, sessionId);

      // Step 8: Validate vulnerabilities
      const validatorResult = await this.startAgent(validatorId, analyzerResult);
      const validatedVulnerabilities = validatorResult.vulnerabilities;

      // Step 9: Spawn Reporter Agent
      const reporterId = await this.spawnAgent('reporter', {}, sessionId);

      // Step 10: Generate report
      const report = await this.startAgent(reporterId, {
        vulnerabilities: validatedVulnerabilities,
        files: parsedFiles,
        repositoryPath
      });

      return {
        vulnerabilities: validatedVulnerabilities,
        report,
        metadata: {
          filesAnalyzed: files.length,
          vulnerabilitiesFound: validatedVulnerabilities.length,
          agents: [explorerId, parserId, analyzerId, validatorId, reporterId]
        }
      };
    } catch (error) {
      logger.error('[AgentManager] Vulnerability scan workflow failed:', error.message);
      throw error;
    }
  }

  /**
   * Orchestrate dependency analysis workflow
   * @param {object} input - Input data
   * @param {string} sessionId - Session ID
   * @returns {object} Analysis result
   */
  async orchestrateDependencyAnalysis(input, sessionId) {
    const { repositoryPath, languagePlugin } = input;
    
    try {
      // Step 1: Spawn Analyzer Agent for dependency analysis
      const analyzerId = await this.spawnAgent('analyzer', {
        plugin: languagePlugin,
        mode: 'dependency_analysis'
      }, sessionId);

      // Step 2: Analyze dependencies
      const dependencyVulnerabilities = await this.startAgent(analyzerId, { 
        repositoryPath,
        analysisType: 'dependencies'
      });

      // Step 3: Spawn Reporter Agent
      const reporterId = await this.spawnAgent('reporter', {}, sessionId);

      // Step 4: Generate dependency report
      const report = await this.startAgent(reporterId, {
        vulnerabilities: dependencyVulnerabilities,
        repositoryPath,
        reportType: 'dependency_analysis'
      });

      return {
        vulnerabilities: dependencyVulnerabilities,
        report,
        metadata: {
          dependenciesAnalyzed: dependencyVulnerabilities.length,
          agents: [analyzerId, reporterId]
        }
      };
    } catch (error) {
      logger.error('[AgentManager] Dependency analysis workflow failed:', error.message);
      throw error;
    }
  }

  /**
   * Generate unique agent ID
   * @param {string} type - Agent type
   * @returns {string} Unique agent ID
   */
  generateAgentId(type) {
    return `${type}-${++this.agentCounter}-${Date.now()}`;
  }

  /**
   * Handle agent created event
   * @param {object} event - Event data
   */
  handleAgentCreated(event) {
    logger.log(`[AgentManager] Agent created: ${event.message.agentId}`);
  }

  /**
   * Handle agent completed event
   * @param {object} event - Event data
   */
  handleAgentCompleted(event) {
    logger.log(`[AgentManager] Agent completed: ${event.message.agentId}`);
  }

  /**
   * Handle agent failed event
   * @param {object} event - Event data
   */
  handleAgentFailed(event) {
    logger.error(`[AgentManager] Agent failed: ${event.message.agentId} - ${event.message.error}`);
  }

  /**
   * Handle agent terminated event
   * @param {object} event - Event data
   */
  handleAgentTerminated(event) {
    logger.log(`[AgentManager] Agent terminated: ${event.message.agentId} - ${event.message.reason}`);
  }

  /**
   * Cleanup resources
   */
  async cleanup() {
    await this.terminateAllAgents('cleanup');
    
    // Unsubscribe from events
    messageBus.unsubscribe('agent.created', this.handleAgentCreated);
    messageBus.unsubscribe('agent.completed', this.handleAgentCompleted);
    messageBus.unsubscribe('agent.failed', this.handleAgentFailed);
    messageBus.unsubscribe('agent.terminated', this.handleAgentTerminated);
  }
}

// Singleton instance
export const agentManager = new AgentManager();