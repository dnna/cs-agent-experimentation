import { promises as fs } from 'fs';
import path from 'path';
import { parseString } from 'xml2js';

/**
 * Java dependency analyzer for detecting vulnerable dependencies
 */
export class JavaDependencyAnalyzer {
  constructor() {
    this.initialized = false;
    this.vulnerabilityDb = new Map();
  }

  /**
   * Initialize the dependency analyzer
   */
  async initialize() {
    if (this.initialized) return;

    // Load known vulnerability database (placeholder)
    await this.loadVulnerabilityDatabase();
    this.initialized = true;
  }

  /**
   * Analyze Java project dependencies
   * @param {string} projectPath - Path to the project root
   * @returns {Array} Array of dependency vulnerabilities
   */
  async analyze(projectPath) {
    if (!this.initialized) {
      await this.initialize();
    }

    const vulnerabilities = [];

    // Analyze Maven dependencies
    const mavenVulns = await this.analyzeMavenDependencies(projectPath);
    vulnerabilities.push(...mavenVulns);

    // Analyze Gradle dependencies
    const gradleVulns = await this.analyzeGradleDependencies(projectPath);
    vulnerabilities.push(...gradleVulns);

    return vulnerabilities;
  }

  /**
   * Analyze Maven dependencies from pom.xml
   * @param {string} projectPath - Project path
   * @returns {Array} Array of vulnerabilities
   */
  async analyzeMavenDependencies(projectPath) {
    const vulnerabilities = [];
    const pomPath = path.join(projectPath, 'pom.xml');

    try {
      await fs.access(pomPath);
      const pomContent = await fs.readFile(pomPath, 'utf8');
      const dependencies = await this.parseMavenDependencies(pomContent);

      for (const dependency of dependencies) {
        const vulns = await this.checkDependencyVulnerabilities(dependency, 'maven');
        vulnerabilities.push(...vulns);
      }
    } catch (error) {
      // pom.xml doesn't exist or can't be read
    }

    return vulnerabilities;
  }

  /**
   * Analyze Gradle dependencies from build.gradle
   * @param {string} projectPath - Project path
   * @returns {Array} Array of vulnerabilities
   */
  async analyzeGradleDependencies(projectPath) {
    const vulnerabilities = [];
    const gradlePath = path.join(projectPath, 'build.gradle');

    try {
      await fs.access(gradlePath);
      const gradleContent = await fs.readFile(gradlePath, 'utf8');
      const dependencies = await this.parseGradleDependencies(gradleContent);

      for (const dependency of dependencies) {
        const vulns = await this.checkDependencyVulnerabilities(dependency, 'gradle');
        vulnerabilities.push(...vulns);
      }
    } catch (error) {
      // build.gradle doesn't exist or can't be read
    }

    return vulnerabilities;
  }

  /**
   * Parse Maven dependencies from pom.xml content
   * @param {string} pomContent - POM file content
   * @returns {Array} Array of dependencies
   */
  async parseMavenDependencies(pomContent) {
    return new Promise((resolve, reject) => {
      parseString(pomContent, (err, result) => {
        if (err) {
          reject(err);
          return;
        }

        const dependencies = [];
        const project = result.project;

        if (project && project.dependencies && project.dependencies[0].dependency) {
          for (const dep of project.dependencies[0].dependency) {
            const dependency = {
              groupId: dep.groupId ? dep.groupId[0] : '',
              artifactId: dep.artifactId ? dep.artifactId[0] : '',
              version: dep.version ? dep.version[0] : '',
              scope: dep.scope ? dep.scope[0] : 'compile',
              type: 'maven'
            };

            dependencies.push(dependency);
          }
        }

        // Also check for parent dependencies
        if (project && project.parent && project.parent[0]) {
          const parent = project.parent[0];
          const parentDep = {
            groupId: parent.groupId ? parent.groupId[0] : '',
            artifactId: parent.artifactId ? parent.artifactId[0] : '',
            version: parent.version ? parent.version[0] : '',
            scope: 'parent',
            type: 'maven'
          };
          dependencies.push(parentDep);
        }

        resolve(dependencies);
      });
    });
  }

  /**
   * Parse Gradle dependencies from build.gradle content
   * @param {string} gradleContent - Gradle file content
   * @returns {Array} Array of dependencies
   */
  async parseGradleDependencies(gradleContent) {
    const dependencies = [];
    
    // Parse Gradle dependency declarations
    const dependencyPatterns = [
      /implementation\s+['"](.*?)['"]/g,
      /compile\s+['"](.*?)['"]/g,
      /api\s+['"](.*?)['"]/g,
      /runtime\s+['"](.*?)['"]/g,
      /testImplementation\s+['"](.*?)['"]/g,
      /testCompile\s+['"](.*?)['"]/g
    ];

    for (const pattern of dependencyPatterns) {
      let match;
      while ((match = pattern.exec(gradleContent)) !== null) {
        const depString = match[1];
        const parts = depString.split(':');
        
        if (parts.length >= 2) {
          const dependency = {
            groupId: parts[0],
            artifactId: parts[1],
            version: parts[2] || 'latest',
            scope: this.extractGradleScope(match[0]),
            type: 'gradle'
          };
          dependencies.push(dependency);
        }
      }
    }

    return dependencies;
  }

  /**
   * Extract scope from Gradle dependency declaration
   * @param {string} declaration - Gradle dependency declaration
   * @returns {string} Dependency scope
   */
  extractGradleScope(declaration) {
    if (declaration.includes('implementation')) return 'implementation';
    if (declaration.includes('compile')) return 'compile';
    if (declaration.includes('api')) return 'api';
    if (declaration.includes('runtime')) return 'runtime';
    if (declaration.includes('testImplementation')) return 'testImplementation';
    if (declaration.includes('testCompile')) return 'testCompile';
    return 'unknown';
  }

  /**
   * Check dependency for known vulnerabilities
   * @param {object} dependency - Dependency information
   * @param {string} buildSystem - Build system (maven/gradle)
   * @returns {Array} Array of vulnerabilities
   */
  async checkDependencyVulnerabilities(dependency, buildSystem) {
    const vulnerabilities = [];
    const depKey = `${dependency.groupId}:${dependency.artifactId}`;

    // Check against known vulnerability database
    if (this.vulnerabilityDb.has(depKey)) {
      const knownVulns = this.vulnerabilityDb.get(depKey);
      
      for (const vuln of knownVulns) {
        if (this.versionMatches(dependency.version, vuln.affectedVersions)) {
          vulnerabilities.push({
            type: 'VULNERABLE_DEPENDENCY',
            severity: vuln.severity,
            description: `Vulnerable dependency: ${depKey}:${dependency.version}`,
            cve: vuln.cve,
            cwe: vuln.cwe,
            dependency: {
              groupId: dependency.groupId,
              artifactId: dependency.artifactId,
              version: dependency.version,
              scope: dependency.scope,
              buildSystem
            },
            vulnerability: {
              id: vuln.id,
              description: vuln.description,
              references: vuln.references,
              publishedDate: vuln.publishedDate,
              lastModifiedDate: vuln.lastModifiedDate
            }
          });
        }
      }
    }

    // Check for known problematic dependencies
    const problematicDeps = this.getProblematicDependencies();
    if (problematicDeps.has(depKey)) {
      const issue = problematicDeps.get(depKey);
      vulnerabilities.push({
        type: 'PROBLEMATIC_DEPENDENCY',
        severity: issue.severity,
        description: `Problematic dependency: ${depKey} - ${issue.reason}`,
        dependency: {
          groupId: dependency.groupId,
          artifactId: dependency.artifactId,
          version: dependency.version,
          scope: dependency.scope,
          buildSystem
        },
        issue: {
          reason: issue.reason,
          recommendation: issue.recommendation
        }
      });
    }

    return vulnerabilities;
  }

  /**
   * Check if version matches affected versions
   * @param {string} version - Dependency version
   * @param {Array} affectedVersions - Array of affected version ranges
   * @returns {boolean} True if version is affected
   */
  versionMatches(version, affectedVersions) {
    // Simple version matching - should be enhanced with proper semantic versioning
    for (const affectedRange of affectedVersions) {
      if (affectedRange.includes('*') || version === affectedRange) {
        return true;
      }
      
      // Check version ranges (e.g., "<2.0.0", ">=1.0.0,<2.0.0")
      if (this.versionInRange(version, affectedRange)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Check if version is in a specific range
   * @param {string} version - Version to check
   * @param {string} range - Version range
   * @returns {boolean} True if version is in range
   */
  versionInRange(version, range) {
    // Placeholder for semantic version range checking
    // In a real implementation, use a library like semver
    return false;
  }

  /**
   * Load vulnerability database
   */
  async loadVulnerabilityDatabase() {
    // Placeholder for loading vulnerability database
    // In a real implementation, this would load from NVD, OSS Index, etc.
    
    // Example vulnerabilities
    this.vulnerabilityDb.set('org.apache.struts:struts2-core', [
      {
        id: 'CVE-2017-5638',
        severity: 'CRITICAL',
        description: 'Apache Struts 2 Remote Code Execution vulnerability',
        cve: 'CVE-2017-5638',
        cwe: 20,
        affectedVersions: ['2.3.5', '2.3.31', '2.5.10'],
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-5638'],
        publishedDate: '2017-03-10',
        lastModifiedDate: '2019-10-03'
      }
    ]);

    this.vulnerabilityDb.set('commons-collections:commons-collections', [
      {
        id: 'CVE-2015-6420',
        severity: 'HIGH',
        description: 'Apache Commons Collections deserialization vulnerability',
        cve: 'CVE-2015-6420',
        cwe: 502,
        affectedVersions: ['3.2.1', '4.0'],
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2015-6420'],
        publishedDate: '2015-11-07',
        lastModifiedDate: '2020-01-30'
      }
    ]);

    this.vulnerabilityDb.set('com.fasterxml.jackson.core:jackson-databind', [
      {
        id: 'CVE-2019-12384',
        severity: 'HIGH',
        description: 'Jackson Databind deserialization vulnerability',
        cve: 'CVE-2019-12384',
        cwe: 502,
        affectedVersions: ['2.9.9'],
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-12384'],
        publishedDate: '2019-06-24',
        lastModifiedDate: '2020-08-24'
      }
    ]);
  }

  /**
   * Get problematic dependencies that should be flagged
   * @returns {Map} Map of problematic dependencies
   */
  getProblematicDependencies() {
    const problematic = new Map();
    
    // Deprecated or abandoned libraries
    problematic.set('commons-logging:commons-logging', {
      severity: 'LOW',
      reason: 'Deprecated library, consider migrating to SLF4J',
      recommendation: 'Use org.slf4j:slf4j-api instead'
    });

    problematic.set('log4j:log4j', {
      severity: 'MEDIUM',
      reason: 'Log4j 1.x is end-of-life and has security issues',
      recommendation: 'Migrate to Log4j 2.x or Logback'
    });

    // Known vulnerable libraries
    problematic.set('org.apache.logging.log4j:log4j-core', {
      severity: 'HIGH',
      reason: 'Log4j 2.x versions before 2.15.0 have critical vulnerabilities',
      recommendation: 'Update to Log4j 2.15.0 or later'
    });

    return problematic;
  }

  /**
   * Get dependency statistics
   * @param {Array} dependencies - Array of dependencies
   * @returns {object} Dependency statistics
   */
  getDependencyStats(dependencies) {
    const stats = {
      total: dependencies.length,
      byScope: {},
      byType: {},
      uniqueGroupIds: new Set(),
      vulnerableCount: 0
    };

    for (const dep of dependencies) {
      // Count by scope
      stats.byScope[dep.scope] = (stats.byScope[dep.scope] || 0) + 1;
      
      // Count by type
      stats.byType[dep.type] = (stats.byType[dep.type] || 0) + 1;
      
      // Track unique group IDs
      stats.uniqueGroupIds.add(dep.groupId);
    }

    stats.uniqueGroupIds = stats.uniqueGroupIds.size;
    
    return stats;
  }

  /**
   * Generate dependency report
   * @param {Array} dependencies - Array of dependencies
   * @param {Array} vulnerabilities - Array of vulnerabilities
   * @returns {object} Dependency report
   */
  generateDependencyReport(dependencies, vulnerabilities) {
    const stats = this.getDependencyStats(dependencies);
    
    return {
      summary: {
        totalDependencies: dependencies.length,
        vulnerableDependencies: vulnerabilities.length,
        riskScore: this.calculateRiskScore(vulnerabilities)
      },
      statistics: stats,
      dependencies: dependencies.map(dep => ({
        ...dep,
        vulnerabilities: vulnerabilities.filter(v => 
          v.dependency && 
          v.dependency.groupId === dep.groupId && 
          v.dependency.artifactId === dep.artifactId
        )
      })),
      vulnerabilities: vulnerabilities.sort((a, b) => {
        const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      })
    };
  }

  /**
   * Calculate risk score based on vulnerabilities
   * @param {Array} vulnerabilities - Array of vulnerabilities
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore(vulnerabilities) {
    if (vulnerabilities.length === 0) return 0;
    
    const severityScores = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
    let totalScore = 0;
    
    for (const vuln of vulnerabilities) {
      totalScore += severityScores[vuln.severity] || 0;
    }
    
    // Normalize to 0-100 scale
    return Math.min(totalScore * 2, 100);
  }
}