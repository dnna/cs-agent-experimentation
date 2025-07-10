import BaseLanguagePlugin from '../base-language-plugin.js';
import { JavaParser } from './java-parser.js';
import { JavaVulnerabilityDetector } from './java-vulnerability-detector.js';
import { JavaDependencyAnalyzer } from './java-dependency-analyzer.js';

/**
 * Java language plugin for vulnerability detection
 */
export class JavaLanguagePlugin extends BaseLanguagePlugin {
  constructor() {
    super('java', '1.0.0');
    
    this.supportedExtensions = ['.java'];
    this.buildFiles = ['pom.xml', 'build.gradle', 'gradlew', 'gradle.properties', 'settings.gradle'];
    this.vulnerabilityTypes = [
      'SQL_INJECTION',
      'XSS',
      'PATH_TRAVERSAL',
      'LDAP_INJECTION',
      'COMMAND_INJECTION',
      'XXE',
      'DESERIALIZATION',
      'CRYPTO_WEAKNESS',
      'AUTHENTICATION_BYPASS',
      'AUTHORIZATION_BYPASS',
      'SESSION_FIXATION',
      'CSRF',
      'SSRF',
      'REGEX_DOS',
      'INFORMATION_DISCLOSURE'
    ];

    this.parser = null;
    this.vulnerabilityDetector = null;
    this.dependencyAnalyzer = null;
  }

  /**
   * Initialize the Java plugin
   */
  async initialize() {
    if (this.initialized) return;

    try {
      this.parser = new JavaParser();
      this.vulnerabilityDetector = new JavaVulnerabilityDetector();
      this.dependencyAnalyzer = new JavaDependencyAnalyzer();

      await this.parser.initialize();
      await this.vulnerabilityDetector.initialize();
      await this.dependencyAnalyzer.initialize();

      this.initialized = true;
      this.log('info', 'Java plugin initialized successfully');
    } catch (error) {
      this.log('error', 'Failed to initialize Java plugin', { error: error.message });
      throw error;
    }
  }

  /**
   * Parse a Java file and extract structural information
   * @param {string} filePath - Path to the Java file
   * @param {string} content - File content
   * @returns {object} Parsed file information
   */
  async parseFile(filePath, content) {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      const context = this.createContext(filePath, {
        language: 'java',
        fileType: this.getFileType(filePath)
      });

      const preprocessedContent = await this.preprocessFile(content);
      const ast = await this.parser.parse(preprocessedContent, context);

      return {
        filePath,
        language: 'java',
        ast,
        classes: ast.classes || [],
        methods: ast.methods || [],
        imports: ast.imports || [],
        annotations: ast.annotations || [],
        variables: ast.variables || [],
        sqlQueries: ast.sqlQueries || [],
        httpHandlers: ast.httpHandlers || [],
        fileOperations: ast.fileOperations || [],
        networkCalls: ast.networkCalls || [],
        context
      };
    } catch (error) {
      this.log('error', 'Failed to parse Java file', { filePath, error: error.message });
      throw new Error(`Failed to parse Java file ${filePath}: ${error.message}`);
    }
  }

  /**
   * Detect vulnerabilities in parsed Java code
   * @param {object} ast - Abstract syntax tree
   * @param {object} context - Analysis context
   * @returns {Array} Array of vulnerability objects
   */
  async detectVulnerabilities(ast, context) {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      const vulnerabilities = await this.vulnerabilityDetector.analyze(ast, context);
      return await this.postprocessResults(vulnerabilities);
    } catch (error) {
      this.log('error', 'Failed to detect vulnerabilities', { context, error: error.message });
      throw error;
    }
  }

  /**
   * Analyze Java project dependencies
   * @param {string} projectPath - Path to the project root
   * @returns {Array} Array of dependency vulnerabilities
   */
  async analyzeDependencies(projectPath) {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      return await this.dependencyAnalyzer.analyze(projectPath);
    } catch (error) {
      this.log('error', 'Failed to analyze dependencies', { projectPath, error: error.message });
      throw error;
    }
  }

  /**
   * Get vulnerability patterns for static analysis
   * @returns {object} Vulnerability patterns by type
   */
  getVulnerabilityPatterns() {
    return {
      SQL_INJECTION: [
        {
          pattern: /Statement\.execute(Query|Update)?\s*\(\s*[^"'][^)]*\)/g,
          severity: 'HIGH',
          cwe: 89,
          description: 'Dynamic SQL query construction with Statement.execute()'
        },
        {
          pattern: /createQuery\s*\(\s*[^"'][^)]*\+/g,
          severity: 'HIGH',
          cwe: 89,
          description: 'JPA dynamic query construction with string concatenation'
        },
        {
          pattern: /createNativeQuery\s*\(\s*[^"'][^)]*\+/g,
          severity: 'HIGH',
          cwe: 89,
          description: 'JPA native query construction with string concatenation'
        },
        {
          pattern: /PreparedStatement.*setString\s*\(\s*\d+\s*,\s*[^"'][^)]*\+/g,
          severity: 'MEDIUM',
          cwe: 89,
          description: 'PreparedStatement with concatenated parameter'
        }
      ],
      XSS: [
        {
          pattern: /response\.getWriter\(\)\.print\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 79,
          description: 'Direct output of user input to response'
        },
        {
          pattern: /out\.print\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 79,
          description: 'Direct output of user input via JSP out.print'
        },
        {
          pattern: /@RequestMapping.*\n.*return.*\+.*request/g,
          severity: 'MEDIUM',
          cwe: 79,
          description: 'Spring MVC controller returning unescaped user input'
        }
      ],
      PATH_TRAVERSAL: [
        {
          pattern: /new File\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 22,
          description: 'File constructor with user input'
        },
        {
          pattern: /Files\.(read|write)\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 22,
          description: 'File operation with user input'
        },
        {
          pattern: /FileInputStream\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 22,
          description: 'FileInputStream with user input'
        }
      ],
      LDAP_INJECTION: [
        {
          pattern: /LdapContext\.search\s*\([^)]*\+/g,
          severity: 'HIGH',
          cwe: 90,
          description: 'LDAP search with string concatenation'
        },
        {
          pattern: /DirContext\.search\s*\([^)]*\+/g,
          severity: 'HIGH',
          cwe: 90,
          description: 'Directory search with string concatenation'
        }
      ],
      COMMAND_INJECTION: [
        {
          pattern: /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/g,
          severity: 'HIGH',
          cwe: 78,
          description: 'Runtime.exec with string concatenation'
        },
        {
          pattern: /ProcessBuilder\s*\([^)]*request\.getParameter/g,
          severity: 'HIGH',
          cwe: 78,
          description: 'ProcessBuilder with user input'
        }
      ],
      XXE: [
        {
          pattern: /DocumentBuilderFactory\.newInstance\(\)(?!.*setFeature)/g,
          severity: 'HIGH',
          cwe: 611,
          description: 'DocumentBuilderFactory without XXE protection'
        },
        {
          pattern: /SAXParserFactory\.newInstance\(\)(?!.*setFeature)/g,
          severity: 'HIGH',
          cwe: 611,
          description: 'SAXParserFactory without XXE protection'
        }
      ],
      DESERIALIZATION: [
        {
          pattern: /ObjectInputStream\s*\([^)]*\)\.readObject\(\)/g,
          severity: 'HIGH',
          cwe: 502,
          description: 'Unsafe deserialization with ObjectInputStream'
        },
        {
          pattern: /Serializable.*readObject\s*\(/g,
          severity: 'MEDIUM',
          cwe: 502,
          description: 'Custom readObject implementation'
        }
      ],
      CRYPTO_WEAKNESS: [
        {
          pattern: /Cipher\.getInstance\s*\(\s*"(DES|RC4|MD5)"/g,
          severity: 'HIGH',
          cwe: 327,
          description: 'Use of weak cryptographic algorithm'
        },
        {
          pattern: /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA1)"/g,
          severity: 'MEDIUM',
          cwe: 327,
          description: 'Use of weak hashing algorithm'
        }
      ]
    };
  }

  /**
   * Get AI prompts for semantic analysis
   * @returns {object} AI prompts by vulnerability type
   */
  getAIPrompts() {
    return {
      SQL_INJECTION: `
        Analyze this Java code for SQL injection vulnerabilities:
        
        Look for:
        - String concatenation in SQL queries
        - Missing prepared statement parameters
        - Dynamic query construction
        - User input directly in SQL statements
        - ORM query construction with user input
        
        Consider safe patterns:
        - PreparedStatement with proper parameter binding
        - JPA named parameters
        - Hibernate criteria queries
        - Input validation and sanitization
        
        Return JSON: {
          isVulnerable: boolean,
          severity: "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          confidence: number (0-1),
          details: string,
          location: {line: number, column: number},
          remediation: string
        }
      `,
      XSS: `
        Analyze this Java web code for Cross-Site Scripting (XSS) vulnerabilities:
        
        Look for:
        - Direct output of request parameters
        - Missing output encoding/escaping
        - Unsafe JSP/template usage
        - Response writer direct usage
        - Reflected user input in responses
        
        Consider safe patterns:
        - OWASP ESAPI encoding
        - Spring Security HTML escaping
        - JSP c:out tags with escapeXml
        - Proper content type headers
        
        Return JSON: {
          isVulnerable: boolean,
          severity: "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          confidence: number (0-1),
          details: string,
          location: {line: number, column: number},
          remediation: string
        }
      `,
      PATH_TRAVERSAL: `
        Analyze this Java code for path traversal vulnerabilities:
        
        Look for:
        - File operations with user input
        - Missing path validation
        - Directory traversal sequences (../)
        - Unsafe file handling
        
        Consider safe patterns:
        - Path validation and sanitization
        - Whitelisting allowed directories
        - Using Path.resolve() safely
        - Input validation
        
        Return JSON: {
          isVulnerable: boolean,
          severity: "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          confidence: number (0-1),
          details: string,
          location: {line: number, column: number},
          remediation: string
        }
      `
    };
  }

  /**
   * Get CWE mappings for vulnerability types
   * @returns {object} CWE mappings
   */
  getCWEMappings() {
    return {
      SQL_INJECTION: 89,
      XSS: 79,
      PATH_TRAVERSAL: 22,
      LDAP_INJECTION: 90,
      COMMAND_INJECTION: 78,
      XXE: 611,
      DESERIALIZATION: 502,
      CRYPTO_WEAKNESS: 327,
      AUTHENTICATION_BYPASS: 287,
      AUTHORIZATION_BYPASS: 285,
      SESSION_FIXATION: 384,
      CSRF: 352,
      SSRF: 918,
      REGEX_DOS: 1333,
      INFORMATION_DISCLOSURE: 200
    };
  }

  /**
   * Get OWASP Top 10 mappings
   * @returns {object} OWASP mappings
   */
  getOWASPMappings() {
    return {
      SQL_INJECTION: 'A03:2021',
      XSS: 'A03:2021',
      PATH_TRAVERSAL: 'A01:2021',
      LDAP_INJECTION: 'A03:2021',
      COMMAND_INJECTION: 'A03:2021',
      XXE: 'A05:2021',
      DESERIALIZATION: 'A08:2021',
      CRYPTO_WEAKNESS: 'A02:2021',
      AUTHENTICATION_BYPASS: 'A07:2021',
      AUTHORIZATION_BYPASS: 'A01:2021',
      SESSION_FIXATION: 'A07:2021',
      CSRF: 'A01:2021',
      SSRF: 'A10:2021',
      REGEX_DOS: 'A06:2021',
      INFORMATION_DISCLOSURE: 'A01:2021'
    };
  }

  /**
   * Determine file type for analysis context
   * @param {string} filePath - File path
   * @returns {string} File type
   */
  getFileType(filePath) {
    const fileName = filePath.split('/').pop();
    
    if (fileName.endsWith('Test.java') || fileName.endsWith('Tests.java') || filePath.includes('/test/')) {
      return 'test';
    }
    
    if (fileName.endsWith('Controller.java') || fileName.endsWith('RestController.java')) {
      return 'controller';
    }
    
    if (fileName.endsWith('Service.java') || fileName.endsWith('ServiceImpl.java')) {
      return 'service';
    }
    
    if (fileName.endsWith('Repository.java') || fileName.endsWith('DAO.java')) {
      return 'repository';
    }
    
    if (fileName.endsWith('Entity.java') || fileName.endsWith('Model.java')) {
      return 'model';
    }
    
    if (fileName.endsWith('Config.java') || fileName.endsWith('Configuration.java')) {
      return 'configuration';
    }
    
    return 'source';
  }

  /**
   * Validate Java file for analysis
   * @param {string} filePath - File path
   * @param {object} stats - File statistics
   * @returns {boolean} True if file should be analyzed
   */
  shouldAnalyzeFile(filePath, stats) {
    // Skip test files unless explicitly requested
    if (filePath.includes('/test/') && !process.env.ANALYZE_TESTS) {
      return false;
    }
    
    // Skip generated files
    if (filePath.includes('/generated/') || filePath.includes('/target/')) {
      return false;
    }
    
    // Skip very large files (> 5MB)
    if (stats.size > 5 * 1024 * 1024) {
      return false;
    }
    
    return super.shouldAnalyzeFile(filePath, stats);
  }

  /**
   * Preprocess Java file content
   * @param {string} content - Original content
   * @returns {string} Preprocessed content
   */
  async preprocessFile(content) {
    // Remove comments to reduce noise in analysis
    let processed = content
      .replace(/\/\*[\s\S]*?\*\//g, '') // Remove block comments
      .replace(/\/\/.*$/gm, ''); // Remove line comments
    
    return processed;
  }

  /**
   * Postprocess vulnerability results
   * @param {Array} results - Raw vulnerability results
   * @returns {Array} Processed vulnerability results
   */
  async postprocessResults(results) {
    return results.map(vuln => {
      // Enhance vulnerabilities with plugin-specific context
      const enhanced = this.createVulnerability(vuln);
      
      // Add Java-specific remediation advice
      if (enhanced.type === 'SQL_INJECTION') {
        enhanced.remediation = enhanced.remediation || 'Use PreparedStatement with parameter binding instead of string concatenation';
      } else if (enhanced.type === 'XSS') {
        enhanced.remediation = enhanced.remediation || 'Use OWASP ESAPI encoding or Spring Security escaping for output';
      } else if (enhanced.type === 'PATH_TRAVERSAL') {
        enhanced.remediation = enhanced.remediation || 'Validate and sanitize file paths, use whitelisting for allowed directories';
      }
      
      return enhanced;
    });
  }
}

export default JavaLanguagePlugin;