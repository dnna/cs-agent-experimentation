import { describe, it, expect, beforeEach } from '@jest/globals';
import { LanguageDetector } from '../../src/tools/language-detector.js';
import { promises as fs } from 'fs';
import path from 'path';
import { jest } from '@jest/globals';

describe('LanguageDetector', () => {
  let detector;
  let mockFs;
  
  beforeEach(() => {
    detector = new LanguageDetector();
    mockFs = jest.mocked(fs);
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
        detector.addLanguageRules('testlang', { files: 'invalid' });
      }).toThrow('Missing required field: extensions');
    });
  });

  describe('detectLanguages', () => {
    it('should detect java project', async () => {
      // Mock file system calls
      jest.spyOn(fs, 'access').mockResolvedValue(undefined);
      jest.spyOn(fs, 'stat').mockResolvedValue({
        isDirectory: () => true,
        size: 1024
      });

      // Mock glob results
      const mockGlob = jest.fn()
        .mockResolvedValueOnce(['pom.xml']) // files check
        .mockResolvedValueOnce(['src/main/java/Test.java']) // extensions check
        .mockResolvedValueOnce(['src/Test.java']); // keyword check

      jest.doMock('fast-glob', () => ({ default: mockGlob }));

      jest.spyOn(fs, 'readFile').mockResolvedValue('public class Test {}');

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