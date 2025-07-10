/**
 * Java parser using regex-based AST generation (simplified for demo)
 * In a production system, this would use a proper parser like tree-sitter
 */
export class JavaParser {
  constructor() {
    this.initialized = false;
  }

  /**
   * Initialize the parser
   */
  async initialize() {
    if (this.initialized) return;
    this.initialized = true;
  }

  /**
   * Parse Java source code
   * @param {string} content - Java source code
   * @param {object} context - Parsing context
   * @returns {object} Parsed AST and extracted information
   */
  async parse(content, context = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      const ast = {
        type: 'compilation_unit',
        classes: this.extractClasses(content),
        methods: this.extractMethods(content),
        imports: this.extractImports(content),
        annotations: this.extractAnnotations(content),
        variables: this.extractVariables(content),
        sqlQueries: this.extractSqlQueries(content),
        httpHandlers: this.extractHttpHandlers(content),
        fileOperations: this.extractFileOperations(content),
        networkCalls: this.extractNetworkCalls(content)
      };

      return ast;
    } catch (error) {
      throw new Error(`Failed to parse Java code: ${error.message}`);
    }
  }

  /**
   * Extract class definitions from source code
   * @param {string} content - Source content
   * @returns {Array} Class definitions
   */
  extractClasses(content) {
    const classes = [];
    const classPattern = /(?:public\s+|private\s+|protected\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([^{]+))?\s*{/g;
    
    let match;
    while ((match = classPattern.exec(content)) !== null) {
      const className = match[1];
      const superclass = match[2] || null;
      const interfaces = match[3] ? match[3].split(',').map(i => i.trim()) : [];
      
      classes.push({
        name: className,
        superclass,
        interfaces,
        startLine: this.getLineNumber(content, match.index),
        modifiers: this.extractModifiersFromMatch(match[0])
      });
    }
    
    return classes;
  }

  /**
   * Extract method definitions from source code
   * @param {string} content - Source content
   * @returns {Array} Method definitions
   */
  extractMethods(content) {
    const methods = [];
    // Simplified regex for method detection
    const methodPattern = /(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(\w+|\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\s*{/g;
    
    let match;
    while ((match = methodPattern.exec(content)) !== null) {
      const returnType = match[1];
      const methodName = match[2];
      const parameters = match[3];
      
      // Extract method body
      const methodStart = match.index + match[0].length;
      const methodBody = this.extractMethodBody(content, methodStart);
      
      methods.push({
        name: methodName,
        returnType,
        parameters: this.parseParameters(parameters),
        body: methodBody,
        startLine: this.getLineNumber(content, match.index),
        modifiers: this.extractModifiersFromMatch(match[0]),
        annotations: this.extractMethodAnnotations(content, match.index)
      });
    }
    
    return methods;
  }

  /**
   * Extract import statements from source code
   * @param {string} content - Source content
   * @returns {Array} Import statements
   */
  extractImports(content) {
    const imports = [];
    const importPattern = /import\s+(static\s+)?([^;]+);/g;
    
    let match;
    while ((match = importPattern.exec(content)) !== null) {
      const isStatic = !!match[1];
      const packageName = match[2].trim();
      
      imports.push({
        text: match[0],
        isStatic,
        packageName,
        startLine: this.getLineNumber(content, match.index)
      });
    }
    
    return imports;
  }

  /**
   * Extract annotations from source code
   * @param {string} content - Source content
   * @returns {Array} Annotations
   */
  extractAnnotations(content) {
    const annotations = [];
    const annotationPattern = /@(\w+)(?:\(([^)]*)\))?/g;
    
    let match;
    while ((match = annotationPattern.exec(content)) !== null) {
      const name = match[1];
      const parameters = match[2] || '';
      
      annotations.push({
        name,
        parameters: this.parseAnnotationParameters(parameters),
        text: match[0],
        startLine: this.getLineNumber(content, match.index)
      });
    }
    
    return annotations;
  }

  /**
   * Extract variable declarations from source code
   * @param {string} content - Source content
   * @returns {Array} Variable declarations
   */
  extractVariables(content) {
    const variables = [];
    const variablePattern = /(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)(?:\s*=\s*([^;]+))?;/g;
    
    let match;
    while ((match = variablePattern.exec(content)) !== null) {
      const type = match[1];
      const name = match[2];
      const initializer = match[3] || null;
      
      variables.push({
        name,
        type,
        initializer,
        startLine: this.getLineNumber(content, match.index)
      });
    }
    
    return variables;
  }

  /**
   * Extract SQL queries from source code
   * @param {string} content - Source content
   * @returns {Array} SQL queries
   */
  extractSqlQueries(content) {
    const queries = [];
    
    // Look for string literals that contain SQL keywords
    const stringPattern = /"([^"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"]*)"/gi;
    
    let match;
    while ((match = stringPattern.exec(content)) !== null) {
      queries.push({
        query: match[1],
        startLine: this.getLineNumber(content, match.index),
        type: 'string_literal'
      });
    }
    
    // Look for method calls that suggest SQL operations
    const sqlMethodPattern = /(\w+)\.(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\(([^)]+)\)/g;
    
    while ((match = sqlMethodPattern.exec(content)) !== null) {
      queries.push({
        method: match[2],
        arguments: [match[3]],
        startLine: this.getLineNumber(content, match.index),
        type: 'method_call'
      });
    }
    
    return queries;
  }

  /**
   * Extract HTTP handlers from source code
   * @param {string} content - Source content
   * @returns {Array} HTTP handlers
   */
  extractHttpHandlers(content) {
    const handlers = [];
    const methods = this.extractMethods(content);
    
    for (const method of methods) {
      const httpAnnotations = method.annotations.filter(ann => 
        ['RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'PatchMapping']
          .some(mapping => ann.name.includes(mapping))
      );
      
      if (httpAnnotations.length > 0) {
        handlers.push({
          method: method.name,
          annotations: httpAnnotations,
          parameters: method.parameters,
          body: method.body,
          startLine: method.startLine
        });
      }
    }
    
    return handlers;
  }

  /**
   * Extract file operations from source code
   * @param {string} content - Source content
   * @returns {Array} File operations
   */
  extractFileOperations(content) {
    const operations = [];
    const fileOpPattern = /(new\s+File\s*\(|Files\.(read|write|copy|delete)|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(([^)]*)\)/g;
    
    let match;
    while ((match = fileOpPattern.exec(content)) !== null) {
      operations.push({
        method: match[1],
        arguments: match[3] ? [match[3]] : [],
        startLine: this.getLineNumber(content, match.index)
      });
    }
    
    return operations;
  }

  /**
   * Extract network calls from source code
   * @param {string} content - Source content
   * @returns {Array} Network calls
   */
  extractNetworkCalls(content) {
    const calls = [];
    const networkPattern = /(URL|HttpURLConnection|URLConnection|Socket|ServerSocket)\s*\(([^)]*)\)/g;
    
    let match;
    while ((match = networkPattern.exec(content)) !== null) {
      calls.push({
        method: match[1],
        arguments: match[2] ? [match[2]] : [],
        startLine: this.getLineNumber(content, match.index)
      });
    }
    
    return calls;
  }

  /**
   * Extract method body from source code
   * @param {string} content - Source content
   * @param {number} startIndex - Start index of method body
   * @returns {string} Method body
   */
  extractMethodBody(content, startIndex) {
    let braceCount = 1;
    let currentIndex = startIndex;
    
    while (currentIndex < content.length && braceCount > 0) {
      const char = content[currentIndex];
      if (char === '{') braceCount++;
      else if (char === '}') braceCount--;
      currentIndex++;
    }
    
    return content.substring(startIndex, currentIndex - 1);
  }

  /**
   * Parse method parameters
   * @param {string} parametersStr - Parameters string
   * @returns {Array} Parsed parameters
   */
  parseParameters(parametersStr) {
    if (!parametersStr.trim()) return [];
    
    const parameters = [];
    const paramParts = parametersStr.split(',');
    
    for (const part of paramParts) {
      const trimmed = part.trim();
      const lastSpace = trimmed.lastIndexOf(' ');
      
      if (lastSpace !== -1) {
        const type = trimmed.substring(0, lastSpace).trim();
        const name = trimmed.substring(lastSpace + 1).trim();
        parameters.push({ type, name });
      }
    }
    
    return parameters;
  }

  /**
   * Parse annotation parameters
   * @param {string} parametersStr - Parameters string
   * @returns {object} Parsed parameters
   */
  parseAnnotationParameters(parametersStr) {
    if (!parametersStr.trim()) return {};
    
    const params = {};
    const assignments = parametersStr.split(',');
    
    for (const assignment of assignments) {
      const [key, value] = assignment.split('=').map(s => s.trim());
      if (key && value) {
        params[key] = value.replace(/"/g, '');
      }
    }
    
    return params;
  }

  /**
   * Extract modifiers from a match
   * @param {string} matchStr - Match string
   * @returns {Array} Modifiers
   */
  extractModifiersFromMatch(matchStr) {
    const modifiers = [];
    const modifierPattern = /\b(public|private|protected|static|final|abstract|synchronized)\b/g;
    
    let match;
    while ((match = modifierPattern.exec(matchStr)) !== null) {
      modifiers.push(match[1]);
    }
    
    return modifiers;
  }

  /**
   * Extract annotations for a method
   * @param {string} content - Source content
   * @param {number} methodIndex - Method index
   * @returns {Array} Method annotations
   */
  extractMethodAnnotations(content, methodIndex) {
    const annotations = [];
    const beforeMethod = content.substring(0, methodIndex);
    const lines = beforeMethod.split('\n');
    
    // Look for annotations in the lines immediately before the method
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (line.startsWith('@')) {
        const annotationMatch = line.match(/@(\w+)(?:\(([^)]*)\))?/);
        if (annotationMatch) {
          annotations.unshift({
            name: annotationMatch[1],
            parameters: this.parseAnnotationParameters(annotationMatch[2] || ''),
            text: line
          });
        }
      } else if (line && !line.startsWith('//') && !line.startsWith('/*')) {
        // Stop if we hit a non-annotation, non-comment line
        break;
      }
    }
    
    return annotations;
  }

  /**
   * Get line number for a character index
   * @param {string} content - Source content
   * @param {number} index - Character index
   * @returns {number} Line number
   */
  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }
}