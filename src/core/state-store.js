import sqlite3 from 'sqlite3';
import { promises as fs } from 'fs';
import path from 'path';
import { logger } from './logger.js';

/**
 * State store for managing scan state and results
 * Uses SQLite for persistence and in-memory caching
 */
export class StateStore {
  constructor(dbPath = ':memory:') {
    this.dbPath = dbPath;
    this.db = null;
    this.cache = new Map();
    this.initialized = false;
  }

  /**
   * Initialize the state store
   */
  async initialize() {
    if (this.initialized) return;

    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(err);
          return;
        }
        
        this.createTables()
          .then(() => {
            this.initialized = true;
            resolve();
          })
          .catch(reject);
      });
    });
  }

  /**
   * Create database tables
   */
  async createTables() {
    const tables = [
      `CREATE TABLE IF NOT EXISTS scan_sessions (
        id TEXT PRIMARY KEY,
        repository_path TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        status TEXT NOT NULL,
        config TEXT,
        results TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_number INTEGER,
        column_number INTEGER,
        description TEXT,
        cwe INTEGER,
        confidence REAL,
        context TEXT,
        evidence TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
      )`,
      `CREATE TABLE IF NOT EXISTS agent_state (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        agent_type TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        state TEXT NOT NULL,
        data TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
      )`,
      `CREATE TABLE IF NOT EXISTS file_analysis (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_hash TEXT,
        language TEXT,
        ast_data TEXT,
        analysis_results TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
      )`
    ];

    for (const sql of tables) {
      await this.run(sql);
    }
  }

  /**
   * Create a new scan session
   * @param {string} repositoryPath - Path to the repository being scanned
   * @param {object} config - Scan configuration
   * @returns {string} Session ID
   */
  async createSession(repositoryPath, config = {}) {
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    await this.run(
      `INSERT INTO scan_sessions (id, repository_path, start_time, status, config) 
       VALUES (?, ?, ?, ?, ?)`,
      [sessionId, repositoryPath, new Date().toISOString(), 'running', JSON.stringify(config)]
    );

    this.cache.set(`session:${sessionId}`, {
      id: sessionId,
      repositoryPath,
      startTime: new Date().toISOString(),
      status: 'running',
      config,
      vulnerabilities: [],
      agentStates: new Map(),
      fileAnalysis: new Map()
    });

    return sessionId;
  }

  /**
   * Update session status
   * @param {string} sessionId - Session ID
   * @param {string} status - New status
   * @param {object} results - Optional results data
   */
  async updateSession(sessionId, status, results = null) {
    const endTime = status === 'completed' || status === 'failed' ? new Date().toISOString() : null;
    
    await this.run(
      `UPDATE scan_sessions SET status = ?, end_time = ?, results = ? WHERE id = ?`,
      [status, endTime, results ? JSON.stringify(results) : null, sessionId]
    );

    const cached = this.cache.get(`session:${sessionId}`);
    if (cached) {
      cached.status = status;
      if (endTime) cached.endTime = endTime;
      if (results) cached.results = results;
    }
  }

  /**
   * Add a vulnerability to a session
   * @param {string} sessionId - Session ID
   * @param {object} vulnerability - Vulnerability data
   */
  async addVulnerability(sessionId, vulnerability) {
    const vulnId = `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    await this.run(
      `INSERT INTO vulnerabilities 
       (id, session_id, type, severity, file_path, line_number, column_number, description, cwe, confidence, context, evidence)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        vulnId,
        sessionId,
        vulnerability.type,
        vulnerability.severity,
        vulnerability.file,
        vulnerability.line,
        vulnerability.column,
        vulnerability.description,
        vulnerability.cwe,
        vulnerability.confidence,
        JSON.stringify(vulnerability.context || {}),
        vulnerability.evidence
      ]
    );

    const cached = this.cache.get(`session:${sessionId}`);
    if (cached) {
      cached.vulnerabilities.push({ ...vulnerability, id: vulnId });
    }
  }

  /**
   * Update agent state
   * @param {string} sessionId - Session ID
   * @param {string} agentType - Type of agent
   * @param {string} agentId - Agent ID
   * @param {string} state - Agent state
   * @param {object} data - Optional state data
   */
  async updateAgentState(sessionId, agentType, agentId, state, data = null) {
    const stateId = `state-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    await this.run(
      `INSERT INTO agent_state (id, session_id, agent_type, agent_id, state, data, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [stateId, sessionId, agentType, agentId, state, data ? JSON.stringify(data) : null, new Date().toISOString()]
    );

    const cached = this.cache.get(`session:${sessionId}`);
    if (cached) {
      cached.agentStates.set(agentId, { type: agentType, state, data, timestamp: new Date().toISOString() });
    }
  }

  /**
   * Store file analysis results
   * @param {string} sessionId - Session ID
   * @param {string} filePath - File path
   * @param {string} language - Programming language
   * @param {object} ast - AST data
   * @param {object} analysis - Analysis results
   */
  async storeFileAnalysis(sessionId, filePath, language, ast, analysis) {
    const fileId = `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const fileHash = this.generateFileHash(filePath);
    
    await this.run(
      `INSERT INTO file_analysis (id, session_id, file_path, file_hash, language, ast_data, analysis_results, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fileId,
        sessionId,
        filePath,
        fileHash,
        language,
        JSON.stringify(ast),
        JSON.stringify(analysis),
        new Date().toISOString()
      ]
    );

    const cached = this.cache.get(`session:${sessionId}`);
    if (cached) {
      cached.fileAnalysis.set(filePath, { language, ast, analysis, timestamp: new Date().toISOString() });
    }
  }

  /**
   * Get session data
   * @param {string} sessionId - Session ID
   * @returns {object} Session data
   */
  async getSession(sessionId) {
    // Check cache first
    const cached = this.cache.get(`session:${sessionId}`);
    if (cached) return cached;

    // Query database
    const session = await this.get(
      `SELECT * FROM scan_sessions WHERE id = ?`,
      [sessionId]
    );

    if (!session) return null;

    // Load related data
    const vulnerabilities = await this.all(
      `SELECT * FROM vulnerabilities WHERE session_id = ?`,
      [sessionId]
    );

    const agentStates = await this.all(
      `SELECT * FROM agent_state WHERE session_id = ? ORDER BY timestamp DESC`,
      [sessionId]
    );

    const fileAnalysis = await this.all(
      `SELECT * FROM file_analysis WHERE session_id = ?`,
      [sessionId]
    );

    const sessionData = {
      id: session.id,
      repositoryPath: session.repository_path,
      startTime: session.start_time,
      endTime: session.end_time,
      status: session.status,
      config: session.config ? JSON.parse(session.config) : {},
      results: session.results ? JSON.parse(session.results) : null,
      vulnerabilities: vulnerabilities.map(v => ({
        id: v.id,
        type: v.type,
        severity: v.severity,
        file: v.file_path,
        line: v.line_number,
        column: v.column_number,
        description: v.description,
        cwe: v.cwe,
        confidence: v.confidence,
        evidence: v.evidence,
        context: v.context ? JSON.parse(v.context) : {}
      })),
      agentStates: new Map(agentStates.map(s => [s.agent_id, {
        type: s.agent_type,
        state: s.state,
        data: s.data ? JSON.parse(s.data) : null,
        timestamp: s.timestamp
      }])),
      fileAnalysis: new Map(fileAnalysis.map(f => [f.file_path, {
        language: f.language,
        ast: f.ast_data ? JSON.parse(f.ast_data) : null,
        analysis: f.analysis_results ? JSON.parse(f.analysis_results) : null,
        timestamp: f.timestamp
      }]))
    };

    // Cache the result
    this.cache.set(`session:${sessionId}`, sessionData);
    return sessionData;
  }

  /**
   * Get all sessions
   * @returns {Array} Array of session summaries
   */
  async getAllSessions() {
    const sessions = await this.all(
      `SELECT id, repository_path, start_time, end_time, status FROM scan_sessions ORDER BY start_time DESC`
    );

    return sessions.map(s => ({
      id: s.id,
      repositoryPath: s.repository_path,
      startTime: s.start_time,
      endTime: s.end_time,
      status: s.status
    }));
  }

  /**
   * Close the database connection
   */
  async close() {
    if (!this.db) return;
    
    return new Promise((resolve) => {
      this.db.close((err) => {
        if (err) logger.error('Error closing database:', err);
        resolve();
      });
    });
  }

  /**
   * Helper method to run SQL statements
   */
  async run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve(this);
      });
    });
  }

  /**
   * Helper method to get single row
   */
  async get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  /**
   * Helper method to get all rows
   */
  async all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  /**
   * Generate a hash for a file path
   */
  generateFileHash(filePath) {
    return Buffer.from(filePath).toString('base64');
  }
}

// Singleton instance
export const stateStore = new StateStore();