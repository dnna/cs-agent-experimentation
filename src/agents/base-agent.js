import { messageBus } from '../core/message-bus.js';
import { logger } from '../core/logger.js';

/**
 * Base class for all agents
 */
export class BaseAgent {
  /**
   * Create a new agent
   * @param {string} id - Agent ID
   * @param {object} config - Agent configuration
   * @param {string} sessionId - Session ID
   */
  constructor(id, config = {}, sessionId = null) {
    this.id = id;
    this.type = this.constructor.name.replace('Agent', '').toLowerCase();
    this.config = config;
    this.sessionId = sessionId;
    this.status = 'idle';
    this.createdAt = new Date().toISOString();
    this.lastUpdate = this.createdAt;
    this.result = null;
    this.error = null;
    this.initialized = false;
  }

  /**
   * Initialize the agent
   * Override this method in subclasses for specific initialization
   */
  async initialize() {
    if (this.initialized) return;
    
    this.log('info', 'Initializing agent');
    this.initialized = true;
    this.status = 'idle';
  }

  /**
   * Execute the agent's main task
   * This method must be implemented by subclasses
   * @param {object} input - Input data
   * @returns {object} Execution result
   */
  async execute(input) {
    throw new Error(`execute method must be implemented by ${this.constructor.name}`);
  }

  /**
   * Terminate the agent
   * @param {string} reason - Termination reason
   */
  async terminate(reason = 'manual') {
    this.log('info', `Terminating agent: ${reason}`);
    this.status = 'terminated';
    this.lastUpdate = new Date().toISOString();
    
    // Perform cleanup
    await this.cleanup();
  }

  /**
   * Cleanup resources
   * Override this method in subclasses for specific cleanup
   */
  async cleanup() {
    // Default cleanup - can be overridden by subclasses
  }

  /**
   * Log a message with agent context
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {object} data - Additional data
   */
  log(level, message, data = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      agent: this.id,
      type: this.type,
      level,
      message,
      ...data
    };

    logger.log(`[${logEntry.timestamp}] [${this.id}] ${level.toUpperCase()}: ${message}`, data);
    
    // Publish log event
    messageBus.publish('agent.log', logEntry, this.id);
  }

  /**
   * Update agent status
   * @param {string} status - New status
   * @param {object} data - Additional data
   */
  updateStatus(status, data = null) {
    this.status = status;
    this.lastUpdate = new Date().toISOString();
    
    if (data) {
      if (status === 'completed') {
        this.result = data;
      } else if (status === 'failed') {
        this.error = data;
      }
    }

    this.log('info', `Status updated to: ${status}`);
    
    // Publish status update
    messageBus.publish('agent.status_updated', {
      agentId: this.id,
      status,
      data,
      timestamp: this.lastUpdate
    }, this.id);
  }

  /**
   * Publish a message to other agents
   * @param {string} topic - Message topic
   * @param {object} message - Message data
   */
  publish(topic, message) {
    messageBus.publish(topic, message, this.id);
  }

  /**
   * Subscribe to messages from other agents
   * @param {string} topic - Message topic
   * @param {Function} callback - Callback function
   */
  subscribe(topic, callback) {
    messageBus.subscribe(topic, callback, this.id);
  }

  /**
   * Unsubscribe from messages
   * @param {string} topic - Message topic
   * @param {Function} callback - Callback function
   */
  unsubscribe(topic, callback) {
    messageBus.unsubscribe(topic, callback, this.id);
  }

  /**
   * Execute a task with error handling and status updates
   * @param {Function} task - Task function to execute
   * @param {object} input - Input data
   * @returns {object} Task result
   */
  async executeTask(task, input) {
    try {
      this.updateStatus('running');
      this.log('info', 'Starting task execution');

      const result = await task(input);

      this.updateStatus('completed', result);
      this.log('info', 'Task completed successfully');

      return result;
    } catch (error) {
      this.updateStatus('failed', { error: error.message });
      this.log('error', 'Task failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Validate input data
   * @param {object} input - Input data
   * @param {Array} required - Required fields
   * @throws {Error} If validation fails
   */
  validateInput(input, required = []) {
    if (!input || typeof input !== 'object') {
      throw new Error('Input must be an object');
    }

    for (const field of required) {
      if (!(field in input)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
  }

  /**
   * Get agent metadata
   * @returns {object} Agent metadata
   */
  getMetadata() {
    return {
      id: this.id,
      type: this.type,
      status: this.status,
      createdAt: this.createdAt,
      lastUpdate: this.lastUpdate,
      sessionId: this.sessionId,
      initialized: this.initialized,
      config: this.config
    };
  }

  /**
   * Get agent performance metrics
   * @returns {object} Performance metrics
   */
  getMetrics() {
    const now = new Date();
    const created = new Date(this.createdAt);
    const lastUpdate = new Date(this.lastUpdate);

    return {
      agentId: this.id,
      type: this.type,
      uptime: now - created,
      timeSinceLastUpdate: now - lastUpdate,
      status: this.status,
      hasResult: this.result !== null,
      hasError: this.error !== null
    };
  }

  /**
   * Check if agent is in a specific state
   * @param {string} state - State to check
   * @returns {boolean} True if agent is in the specified state
   */
  isInState(state) {
    return this.status === state;
  }

  /**
   * Check if agent is active (running or idle)
   * @returns {boolean} True if agent is active
   */
  isActive() {
    return ['idle', 'running'].includes(this.status);
  }

  /**
   * Check if agent is completed
   * @returns {boolean} True if agent is completed
   */
  isCompleted() {
    return this.status === 'completed';
  }

  /**
   * Check if agent has failed
   * @returns {boolean} True if agent has failed
   */
  hasFailed() {
    return this.status === 'failed';
  }

  /**
   * Check if agent is terminated
   * @returns {boolean} True if agent is terminated
   */
  isTerminated() {
    return this.status === 'terminated';
  }

  /**
   * Wait for agent to complete
   * @param {number} timeout - Timeout in milliseconds
   * @returns {Promise} Promise that resolves when agent completes
   */
  async waitForCompletion(timeout = 30000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      
      const checkStatus = () => {
        if (this.isCompleted()) {
          resolve(this.result);
        } else if (this.hasFailed()) {
          reject(new Error(this.error?.error || 'Agent failed'));
        } else if (this.isTerminated()) {
          reject(new Error('Agent was terminated'));
        } else if (Date.now() - startTime > timeout) {
          reject(new Error('Agent timeout'));
        } else {
          setTimeout(checkStatus, 100);
        }
      };

      checkStatus();
    });
  }

  /**
   * Send a message to another agent
   * @param {string} targetAgentId - Target agent ID
   * @param {string} messageType - Message type
   * @param {object} data - Message data
   */
  sendMessage(targetAgentId, messageType, data) {
    const message = {
      from: this.id,
      to: targetAgentId,
      type: messageType,
      data,
      timestamp: new Date().toISOString()
    };

    this.publish(`agent.${targetAgentId}.message`, message);
  }

  /**
   * Handle incoming messages
   * @param {object} message - Incoming message
   */
  handleMessage(message) {
    this.log('info', `Received message: ${message.type}`, { from: message.from });
  }

  /**
   * Process work items in parallel
   * @param {Array} items - Items to process
   * @param {Function} processor - Processing function
   * @param {number} concurrency - Maximum concurrent operations
   * @returns {Array} Processed results
   */
  async processInParallel(items, processor, concurrency = 5) {
    const results = [];
    const semaphore = new Array(concurrency).fill(null);
    
    const processItem = async (item, index) => {
      try {
        const result = await processor(item, index);
        results[index] = result;
      } catch (error) {
        this.log('error', `Failed to process item ${index}`, { error: error.message });
        results[index] = { error: error.message };
      }
    };

    const processBatch = async (startIndex) => {
      const batch = items.slice(startIndex, startIndex + concurrency);
      const promises = batch.map((item, batchIndex) => 
        processItem(item, startIndex + batchIndex)
      );
      
      await Promise.all(promises);
      
      if (startIndex + concurrency < items.length) {
        await processBatch(startIndex + concurrency);
      }
    };

    await processBatch(0);
    return results;
  }
}

export default BaseAgent;