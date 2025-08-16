import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Generates OWASP Benchmark-compatible XML output
 */
export class OwaspXmlGenerator {
  constructor() {
    this.toolName = 'AI-Powered Agentic Scanner';
    this.toolVersion = '1.0.0';
  }

  /**
   * Convert scanner results to OWASP Benchmark XML format
   * @param {object} scanResults - Scanner results
   * @param {string} benchmarkPath - Path to OWASP Benchmark
   * @returns {string} XML content
   */
  async generateXml(scanResults, benchmarkPath) {
    const timestamp = new Date().getTime();
    const analysisTimestamp = new Date().getTime();
    
    // Start XML document
    let xml = `<BugCollection sequence='0' release='' analysisTimestamp='${analysisTimestamp}' version='${this.toolVersion}' timestamp='${timestamp}'>`;
    
    // Add project info
    xml += `<Project projectName='OWASP Benchmark Project'>`;
    xml += `<Jar>${benchmarkPath}/target/classes</Jar>`;
    xml += `</Project>`;
    
    // Map vulnerability types to OWASP categories
    const vulnerabilityMap = {
      'SQL_INJECTION': { category: 'sqli', cwe: 89, bugType: 'SQL_INJECTION' },
      'XSS': { category: 'xss', cwe: 79, bugType: 'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER' },
      'PATH_TRAVERSAL': { category: 'pathtraver', cwe: 22, bugType: 'PATH_TRAVERSAL_IN' },
      'COMMAND_INJECTION': { category: 'cmdi', cwe: 78, bugType: 'COMMAND_INJECTION' },
      'LDAP_INJECTION': { category: 'ldapi', cwe: 90, bugType: 'LDAP_INJECTION' },
      'XPATH_INJECTION': { category: 'xpathi', cwe: 643, bugType: 'XPATH_INJECTION' },
      'WEAK_RANDOMNESS': { category: 'weakrand', cwe: 330, bugType: 'PREDICTABLE_RANDOM' },
      'WEAK_HASH_ALGORITHM': { category: 'hash', cwe: 328, bugType: 'WEAK_MESSAGE_DIGEST_MD5' },
      'WEAK_ENCRYPTION_ALGORITHM': { category: 'crypto', cwe: 327, bugType: 'CIPHER_INTEGRITY' },
      'INSECURE_COOKIE': { category: 'securecookie', cwe: 614, bugType: 'INSECURE_COOKIE' },
      'TRUST_BOUNDARY': { category: 'trustbound', cwe: 501, bugType: 'TRUST_BOUNDARY_VIOLATION' },
      'XXE': { category: 'xxe', cwe: 611, bugType: 'XXE_XMLREADER' },
      'SSRF': { category: 'ssrf', cwe: 918, bugType: 'URLCONNECTION_SSRF_FD' },
      'INSECURE_DESERIALIZATION': { category: 'deserial', cwe: 502, bugType: 'OBJECT_DESERIALIZATION' }
    };
    
    // Process vulnerabilities
    const vulnerabilities = scanResults.vulnerabilities || [];
    
    for (const vuln of vulnerabilities) {
      const mapping = vulnerabilityMap[vuln.type] || { 
        category: 'unknown', 
        cwe: 0, 
        bugType: vuln.type 
      };
      
      // Extract test case number from file path
      const testMatch = vuln.file?.match(/BenchmarkTest(\d+)/);
      const testNumber = testMatch ? testMatch[1] : '00000';
      
      xml += `<BugInstance type='${mapping.bugType}' priority='2' rank='5' abbrev='${mapping.category}' category='SECURITY'>`;
      xml += `<ShortMessage>${vuln.type}</ShortMessage>`;
      xml += `<LongMessage>${vuln.description || vuln.type + ' vulnerability detected'}</LongMessage>`;
      
      // Add class and method info
      const className = `org.owasp.benchmark.testcode.BenchmarkTest${testNumber}`;
      xml += `<Class classname='${className}'>`;
      xml += `<SourceLine classname='${className}' start='1' end='100' sourcepath='${className.replace(/\./g, '/')}.java' sourcefile='BenchmarkTest${testNumber}.java'>`;
      xml += `<Message>At ${className}.java:[lines 1-100]</Message>`;
      xml += `</SourceLine>`;
      xml += `<Message>In class ${className}</Message>`;
      xml += `</Class>`;
      
      // Add method info
      xml += `<Method classname='${className}' name='doPost' signature='(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V' isStatic='false'>`;
      xml += `<SourceLine classname='${className}' start='${vuln.line || 1}' end='${vuln.line || 100}' startBytecode='0' endBytecode='200' sourcepath='${className.replace(/\./g, '/')}.java' sourcefile='BenchmarkTest${testNumber}.java'/>`;
      xml += `<Message>In method ${className}.doPost(HttpServletRequest, HttpServletResponse)</Message>`;
      xml += `</Method>`;
      
      // Add source line
      xml += `<SourceLine classname='${className}' start='${vuln.line || 50}' end='${vuln.line || 50}' startBytecode='0' endBytecode='10' sourcepath='${className.replace(/\./g, '/')}.java' sourcefile='BenchmarkTest${testNumber}.java'>`;
      xml += `<Message>At ${className}.java:[line ${vuln.line || 50}]</Message>`;
      xml += `</SourceLine>`;
      
      xml += `</BugInstance>`;
    }
    
    // Add BugCategory elements
    xml += `<BugCategory category='SECURITY'><Description>Security</Description></BugCategory>`;
    
    // Add BugPattern elements for each type found
    const foundTypes = new Set(vulnerabilities.map(v => vulnerabilityMap[v.type]?.bugType || v.type));
    for (const bugType of foundTypes) {
      xml += `<BugPattern type='${bugType}' abbrev='SEC' category='SECURITY'/>`;
    }
    
    // Add BugCode elements
    xml += `<BugCode abbrev='SEC'><Description>Security issue</Description></BugCode>`;
    
    // Close XML
    xml += `</BugCollection>`;
    
    return xml;
  }

  /**
   * Save XML results to file
   * @param {object} scanResults - Scanner results
   * @param {string} benchmarkPath - Path to OWASP Benchmark
   * @param {string} outputPath - Output file path
   */
  async saveXmlResults(scanResults, benchmarkPath, outputPath) {
    const xml = await this.generateXml(scanResults, benchmarkPath);
    
    // Ensure results directory exists
    const resultsDir = path.dirname(outputPath);
    await fs.mkdir(resultsDir, { recursive: true });
    
    // Save XML file
    await fs.writeFile(outputPath, xml, 'utf8');
    
    console.log(`✅ Saved OWASP Benchmark XML results to: ${outputPath}`);
    
    return outputPath;
  }

  /**
   * Generate filename for results
   * @param {string} benchmarkVersion - Benchmark version (e.g., "1.2")
   * @returns {string} Filename
   */
  generateFilename(benchmarkVersion = '1.2') {
    const toolName = this.toolName.replace(/\s+/g, '');
    const timestamp = new Date().toISOString().split('T')[0];
    return `Benchmark_${benchmarkVersion}-${toolName}-${this.toolVersion}-${timestamp}.xml`;
  }
}

export default OwaspXmlGenerator;