import EventEmitter from 'eventemitter3';
import { logger } from './logger.js';

/**
 * Message bus for inter-agent communication
 * Provides pub/sub pattern for loose coupling between agents
 */
export class MessageBus extends EventEmitter {
  constructor() {
    super();
    this.messageHistory = [];
    this.subscriberCount = new Map();
  }

  /**
   * Publish a message to all subscribers of a topic
   * @param {string} topic - The topic to publish to
   * @param {object} message - The message payload
   * @param {string} sender - The sender identifier
   */
  publish(topic, message, sender = 'unknown') {
    const envelope = {
      topic,
      message,
      sender,
      timestamp: new Date().toISOString(),
      id: this.generateMessageId()
    };

    this.messageHistory.push(envelope);
    this.emit(topic, envelope);
    
    // Emit to wildcard subscribers
    this.emit('*', envelope);
    
    logger.debug(`[MessageBus] Published ${topic} from ${sender}`);
  }

  /**
   * Subscribe to a topic with a callback
   * @param {string} topic - The topic to subscribe to
   * @param {Function} callback - The callback function
   * @param {string} subscriber - The subscriber identifier
   */
  subscribe(topic, callback, subscriber = 'unknown') {
    this.on(topic, callback);
    
    // Track subscriber count
    if (!this.subscriberCount.has(topic)) {
      this.subscriberCount.set(topic, 0);
    }
    this.subscriberCount.set(topic, this.subscriberCount.get(topic) + 1);
    
    logger.debug(`[MessageBus] ${subscriber} subscribed to ${topic}`);
  }

  /**
   * Unsubscribe from a topic
   * @param {string} topic - The topic to unsubscribe from
   * @param {Function} callback - The callback function to remove
   * @param {string} subscriber - The subscriber identifier
   */
  unsubscribe(topic, callback, subscriber = 'unknown') {
    this.off(topic, callback);
    
    // Update subscriber count
    if (this.subscriberCount.has(topic)) {
      const count = this.subscriberCount.get(topic) - 1;
      if (count <= 0) {
        this.subscriberCount.delete(topic);
      } else {
        this.subscriberCount.set(topic, count);
      }
    }
    
    logger.debug(`[MessageBus] ${subscriber} unsubscribed from ${topic}`);
  }

  /**
   * Get message history for a topic
   * @param {string} topic - The topic to get history for
   * @param {number} limit - Maximum number of messages to return
   * @returns {Array} Array of message envelopes
   */
  getHistory(topic, limit = 100) {
    return this.messageHistory
      .filter(msg => msg.topic === topic)
      .slice(-limit);
  }

  /**
   * Clear message history
   */
  clearHistory() {
    this.messageHistory = [];
  }

  /**
   * Get statistics about the message bus
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      totalMessages: this.messageHistory.length,
      subscribers: Object.fromEntries(this.subscriberCount),
      topics: Array.from(this.subscriberCount.keys()),
      activeListeners: this.eventNames().length
    };
  }

  /**
   * Generate a unique message ID
   * @returns {string} Unique message ID
   */
  generateMessageId() {
    return `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Singleton instance
export const messageBus = new MessageBus();