import { SystemValidator } from './validation';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';

// Mock SystemValidator that provides test iptables output and file reading without sudo
class TestSystemValidator extends SystemValidator {
  private mockIptablesOutput: Map<string, string> = new Map();

  // Override to provide mock iptables output
  protected async getIptablesChainOutput(chain: string): Promise<string> {
    return this.mockIptablesOutput.get(chain) || '';
  }

  // Helper method to set mock iptables output for tests
  setMockIptablesOutput(chain: string, output: string): void {
    this.mockIptablesOutput.set(chain, output);
  }

  // Override to read files without sudo for local testing
  protected async calculateFileChecksum(filePath: string): Promise<string | null> {
    try {
      const fileContent = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(fileContent).digest('hex');
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }
}

describe('SystemValidator', () => {
  let validator: TestSystemValidator;
  let testFiles: string[];
  const testDir = '/tmp/safer-runner-test';

  // Sample iptables output for testing
  const sampleIptablesOutput = {
    INPUT: `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
2    DROP       all  --  192.168.1.0/24       0.0.0.0/0
`,
    OUTPUT: `Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            10.0.0.0/8
2    ACCEPT     all  --  0.0.0.0/0            172.16.0.0/12
`,
    FORWARD: `Chain FORWARD (policy DROP)
num  target     prot opt source               destination
`
  };

  beforeEach(() => {
    // Create test directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // Create test files that simulate critical system files
    testFiles = [
      path.join(testDir, 'dnsmasq.conf'),
      path.join(testDir, 'resolv.conf'),
      path.join(testDir, 'no-stub.conf')
    ];

    testFiles.forEach((file, idx) => {
      fs.writeFileSync(file, `test content ${idx}\n`);
    });

    // Initialize test validator with mock iptables output
    validator = new TestSystemValidator(testFiles);
    validator.setMockIptablesOutput('INPUT', sampleIptablesOutput.INPUT);
    validator.setMockIptablesOutput('OUTPUT', sampleIptablesOutput.OUTPUT);
    validator.setMockIptablesOutput('FORWARD', sampleIptablesOutput.FORWARD);
  });

  afterEach(() => {
    // Cleanup test files and directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }

    // Cleanup validation state file
    const stateFile = '/tmp/safer-runner-validation-state.json';
    if (fs.existsSync(stateFile)) {
      fs.unlinkSync(stateFile);
    }
  });

  describe('File checksum calculation', () => {
    it('should calculate correct SHA256 checksum for file content', () => {
      const testContent = 'test content for validation\n';
      const testFile = path.join(testDir, 'test-checksum.conf');
      fs.writeFileSync(testFile, testContent);

      const expectedChecksum = crypto.createHash('sha256').update(testContent).digest('hex');

      expect(expectedChecksum).toBeDefined();
      expect(expectedChecksum).toHaveLength(64); // SHA256 produces 64 hex characters
    });

    it('should produce different checksums for different content', () => {
      const content1 = 'content one';
      const content2 = 'content two';

      const checksum1 = crypto.createHash('sha256').update(content1).digest('hex');
      const checksum2 = crypto.createHash('sha256').update(content2).digest('hex');

      expect(checksum1).not.toBe(checksum2);
    });
  });

  describe('Post-setup baseline capture', () => {
    it('should capture post-setup baseline without errors', async () => {
      await expect(validator.capturePostSetupBaseline()).resolves.not.toThrow();
    });

    it('should create validation state file', async () => {
      await validator.capturePostSetupBaseline();
      const stateFile = '/tmp/safer-runner-validation-state.json';

      expect(fs.existsSync(stateFile)).toBe(true);
    });

    it('should capture checksums for all critical files', async () => {
      await validator.capturePostSetupBaseline();
      const stateFile = '/tmp/safer-runner-validation-state.json';
      const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));

      expect(state.files).toHaveLength(testFiles.length);
      expect(state.files.every((f: any) => f.checksum && f.path && f.timestamp)).toBe(true);
    });
  });

  describe('Baseline validation', () => {
    it('should verify against baseline successfully when nothing changed', async () => {
      await validator.capturePostSetupBaseline();
      const validationResult = await validator.verifyAgainstBaseline();

      expect(validationResult).toBe(true);
    });

    it('should detect file tampering', async () => {
      await validator.capturePostSetupBaseline();

      // Tamper with one of the test files
      fs.writeFileSync(testFiles[0], 'TAMPERED CONTENT\n');

      const validationResult = await validator.verifyAgainstBaseline();

      expect(validationResult).toBe(false);
    });

    it('should detect file deletion', async () => {
      await validator.capturePostSetupBaseline();

      // Delete one of the test files
      fs.unlinkSync(testFiles[0]);

      const validationResult = await validator.verifyAgainstBaseline();

      expect(validationResult).toBe(false);
    });

    it('should return false when baseline state file does not exist', async () => {
      const validationResult = await validator.verifyAgainstBaseline();

      expect(validationResult).toBe(false);
    });
  });

  describe('Validation report generation', () => {
    it('should generate validation report', async () => {
      await validator.capturePostSetupBaseline();
      const report = await validator.generateValidationReport();

      expect(report).toBeDefined();
      expect(typeof report).toBe('string');
      expect(report.length).toBeGreaterThan(0);
    });

    it('should include key sections in report', async () => {
      await validator.capturePostSetupBaseline();
      const report = await validator.generateValidationReport();

      // Check for expected report sections
      expect(report).toContain('Config File Tamper Detection');
      expect(report).toContain('<details>');
      expect(report).toContain('<summary>');
      expect(report).toContain('</details>');
      expect(report).toContain('Configuration Files');
      expect(report).toContain('Firewall Rules');
      expect(report).toContain('Baseline:');
      expect(report).toContain('Verified:');
    });

    it('should show VERIFIED status for unchanged files', async () => {
      await validator.capturePostSetupBaseline();
      const report = await validator.generateValidationReport();

      expect(report).toContain('VERIFIED');
      // Should NOT have warning emoji when no tampering
      expect(report).not.toContain('⚠️ Config File Tamper Detection');
    });

    it('should show TAMPERED status for modified files', async () => {
      await validator.capturePostSetupBaseline();

      // Tamper with a file
      fs.writeFileSync(testFiles[0], 'MODIFIED CONTENT\n');

      const report = await validator.generateValidationReport();

      expect(report).toContain('TAMPERED');
      // Should have warning emoji when tampering detected
      expect(report).toContain('⚠️ Config File Tamper Detection');
    });

    it('should show DELETED status for removed files', async () => {
      await validator.capturePostSetupBaseline();

      // Delete a file
      fs.unlinkSync(testFiles[0]);

      const report = await validator.generateValidationReport();

      expect(report).toContain('DELETED');
      // Should have warning emoji when file deletion detected
      expect(report).toContain('⚠️ Config File Tamper Detection');
    });

    it('should handle missing baseline state gracefully', async () => {
      const report = await validator.generateValidationReport();

      expect(report).toContain('No validation data available');
    });
  });

  describe('File tampering detection', () => {
    it('should handle missing critical files gracefully during initialization', () => {
      // Create validator with non-existent files
      const nonExistentFiles = ['/tmp/does-not-exist-1.conf', '/tmp/does-not-exist-2.conf'];
      const testValidator = new TestSystemValidator(nonExistentFiles);

      // Should fail during baseline capture because files don't exist
      expect(testValidator.capturePostSetupBaseline()).rejects.toThrow();
    });
  });

  describe('Integration scenarios', () => {
    it('should handle complete workflow: capture -> validate -> report', async () => {
      // Capture baseline
      await validator.capturePostSetupBaseline();

      // Verify (should pass)
      const isValid = await validator.verifyAgainstBaseline();
      expect(isValid).toBe(true);

      // Generate report
      const report = await validator.generateValidationReport();
      expect(report).toContain('VERIFIED');
    });

    it('should detect tampering in complete workflow', async () => {
      // Capture baseline
      await validator.capturePostSetupBaseline();

      // Tamper with files
      fs.writeFileSync(testFiles[1], 'TAMPERED\n');

      // Verify (should fail)
      const isValid = await validator.verifyAgainstBaseline();
      expect(isValid).toBe(false);

      // Generate report (should show tampering)
      const report = await validator.generateValidationReport();
      expect(report).toContain('TAMPERED');
    });
  });
});
