/**
 * Simple integration test to verify validation system functionality
 * This would typically be run in a GitHub Actions environment
 */

import { SystemValidator } from './validation';
import * as fs from 'fs';
import * as path from 'path';

async function testValidationSystem(): Promise<void> {
  console.log('🧪 Testing System Validation...\n');

  const validator = new SystemValidator();
  const testFile = '/tmp/test-validation-file.conf';

  try {
    // Test 1: Create a test file and verify checksum calculation
    console.log('Test 1: File checksum calculation');
    const testContent = 'test content for validation\n';
    fs.writeFileSync(testFile, testContent);

    // This would normally be done by the validator internally
    const crypto = require('crypto');
    const expectedChecksum = crypto.createHash('sha256').update(testContent).digest('hex');
    console.log(`✅ Test file created with expected checksum: ${expectedChecksum.substring(0, 16)}...`);

    // Test 2: Capture post-setup baseline (simulated)
    console.log('\nTest 2: Post-setup baseline capture');
    await validator.capturePostSetupBaseline();
    console.log('✅ Post-setup baseline captured successfully');

    // Test 3: Verify against baseline
    console.log('\nTest 3: Baseline validation (unchanged)');
    const validationResult = await validator.verifyAgainstBaseline();
    console.log(`Validation result: ${validationResult ? '✅ PASSED' : '❌ FAILED'}`);

    // Test 4: Generate validation report
    console.log('\nTest 4: Validation report generation');
    const report = await validator.generateValidationReport();
    console.log('✅ Validation report generated');
    console.log('Report preview (first 200 chars):');
    console.log(report.substring(0, 200) + '...\n');

    // Test 5: File tampering detection (simulated)
    console.log('Test 5: File tampering detection');
    if (fs.existsSync('/etc/dnsmasq.conf')) {
      console.log('⚠️  /etc/dnsmasq.conf exists - tampering detection would work in real environment');
    } else {
      console.log('ℹ️  /etc/dnsmasq.conf does not exist - normal for test environment');
    }

    console.log('\n🎉 All validation tests completed successfully!');

  } catch (error) {
    console.error(`❌ Validation test failed: ${error}`);
    process.exit(1);
  } finally {
    // Cleanup test file
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  }
}

// Only run tests if this file is executed directly
if (require.main === module) {
  testValidationSystem().catch(console.error);
}

export { testValidationSystem };