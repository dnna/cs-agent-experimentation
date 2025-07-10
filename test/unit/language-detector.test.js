import { describe, it, expect, beforeEach } from '@jest/globals';
import { LanguageDetector } from '../../src/tools/language-detector.js';
import { promises as fs } from 'fs';
import path from 'path';
import { jest } from '@jest/globals';
import glob from 'fast-glob';

console.log(glob);

jest.mock('fast-glob', () => jest.fn());

describe('LanguageDetector', () => {
  let detector;
  
  beforeEach(() => {
    detector = new LanguageDetector();
    glob.mockClear();
  });

  describe('getSupportedLanguages', () => {
    it('should return array of supported languages', () => {
      const languages = detector.getSupportedLanguages();
      expect(languages).toBeInstanceOf(Array);
      expect(languages).toContain('java');
      expect(languages).toContain('javascript');
      expect(languages).toContain('python');
    });
  });

  describe('getLanguageRules', () => {
    it('should return rules for java', () => {
      const rules = detector.getLanguageRules('java');
      expect(rules).toBeDefined();
      expect(rules.files).toContain('pom.xml');
      expect(rules.extensions).toContain('.java');
      expect(rules.keywords).toContain('public class');
    });

    it('should return null for unknown language', () => {
      const rules = detector.getLanguageRules('unknown');
      expect(rules).toBeNull();
    });
  });

  describe('addLanguageRules', () => {
    it('should add new language rules', () => {
      const newRules = {
        files: ['test.config'],
        extensions: ['.test'],
        directories: ['test_dir'],
        keywords: ['test_keyword'],
        weight: { files: 0.4, extensions: 0.3, directories: 0.2, keywords: 0.1 }
      };

      detector.addLanguageRules('testlang', newRules);
      const retrievedRules = detector.getLanguageRules('testlang');
      expect(retrievedRules).toEqual(newRules);
    });

    it('should throw error for invalid rules', () => {
      expect(() => {
        detector.addLanguageRules('testlang', { extensions: [], directories: [], keywords: [], weight: {} });
      }).toThrow('Missing required field: files');
    });
  });

  describe('detectLanguages', () => {
    beforeEach(() => {
      jest.spyOn(fs, 'access').mockResolvedValue(undefined);
      jest.spyOn(fs, 'readFile').mockResolvedValue('public class Test {}');
    });

    it('should detect java project', async () => {
      const statIsDir = { isDirectory: () => true, size: 1024 };
      const statIsFile = { isDirectory: () => false, size: 1024 };
      
      jest.spyOn(fs, 'stat').mockImplementation(async (filePath) => {
        if (filePath.toString().includes('src/main/java')) {
          return statIsDir;
        }
        return statIsFile;
      });

      glob.mockImplementation(async (pattern) => {
        if (pattern.toString().includes('pom.xml')) return ['pom.xml'];
        if (pattern.toString().includes('.java')) return ['src/main/java/Test.java'];
        return [];
      });

      const result = await detector.detectLanguages('/fake/java/project');
      
      expect(result.primary).toBe('java');
      expect(result.confidence.java).toBeGreaterThan(0.5);
    });

    it('should handle non-existent directory', async () => {
      jest.spyOn(fs, 'access').mockRejectedValue(new Error('ENOENT'));

      await expect(detector.detectLanguages('/non/existent/path'))
        .rejects.toThrow('Repository path does not exist');
    });
  });
});