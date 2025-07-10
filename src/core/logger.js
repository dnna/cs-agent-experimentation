/**
 * Simple logger utility that respects verbose/debug mode
 */
export class Logger {
  static isVerbose() {
    return process.env.DEBUG === 'true';
  }

  static log(...args) {
    if (this.isVerbose()) {
      console.log(...args);
    }
  }

  static info(...args) {
    if (this.isVerbose()) {
      console.info(...args);
    }
  }

  static warn(...args) {
    // Warnings are always shown
    console.warn(...args);
  }

  static error(...args) {
    // Errors are always shown
    console.error(...args);
  }

  static debug(...args) {
    if (this.isVerbose()) {
      console.log('[DEBUG]', ...args);
    }
  }

  // Always log important messages regardless of verbose mode
  static always(...args) {
    console.log(...args);
  }
}

export const logger = Logger;