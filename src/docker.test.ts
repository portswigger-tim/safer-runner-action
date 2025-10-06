/**
 * Tests for docker.ts
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { disableDockerForRunner, isRunnerInDockerGroup, RUNNER_USERNAME, DOCKER_GROUP } from './docker';

// Mock the modules
jest.mock('@actions/core');
jest.mock('@actions/exec');

describe('docker module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('disableDockerForRunner', () => {
    it('should remove runner from docker group and restrict socket permissions', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockResolvedValue(0);

      await disableDockerForRunner();

      // Should remove from docker group
      expect(mockExec).toHaveBeenCalledWith('sudo', ['gpasswd', '-d', RUNNER_USERNAME, DOCKER_GROUP]);

      // Should restrict docker socket permissions
      expect(mockExec).toHaveBeenCalledWith('sudo', ['chown', 'root:root', '/var/run/docker.sock']);
      expect(mockExec).toHaveBeenCalledWith('sudo', ['chmod', '600', '/var/run/docker.sock']);

      // Should log appropriate messages
      expect(core.info).toHaveBeenCalledWith('Disabling Docker access for runner user...');
      expect(core.info).toHaveBeenCalledWith(`✅ Removed ${RUNNER_USERNAME} from ${DOCKER_GROUP} group`);
      expect(core.info).toHaveBeenCalledWith('Restricting docker socket permissions...');
      expect(core.info).toHaveBeenCalledWith('✅ Docker socket access restricted to root only');
      expect(core.info).toHaveBeenCalledWith('🔒 Docker commands will no longer be available to the runner user');
      expect(core.info).toHaveBeenCalledWith('ℹ️  This prevents container escape attacks and docker socket abuse');
    });

    it('should handle errors gracefully', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockRejectedValue(new Error('Permission denied'));

      await disableDockerForRunner();

      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Could not fully disable Docker access'));
    });

    it('should use correct constants', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockResolvedValue(0);

      await disableDockerForRunner();

      expect(RUNNER_USERNAME).toBe('runner');
      expect(DOCKER_GROUP).toBe('docker');
      expect(mockExec).toHaveBeenCalledWith('sudo', ['gpasswd', '-d', 'runner', 'docker']);
    });
  });

  describe('isRunnerInDockerGroup', () => {
    it('should return true when runner is in docker group', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockImplementation(async (cmd, args, options) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('runner : runner adm cdrom sudo dip plugdev lxd docker'));
        }
        return 0;
      });

      const result = await isRunnerInDockerGroup();

      expect(result).toBe(true);
      expect(mockExec).toHaveBeenCalledWith('groups', [RUNNER_USERNAME], expect.any(Object));
    });

    it('should return false when runner is not in docker group', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockImplementation(async (cmd, args, options) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('runner : runner adm cdrom sudo dip plugdev lxd'));
        }
        return 0;
      });

      const result = await isRunnerInDockerGroup();

      expect(result).toBe(false);
      expect(mockExec).toHaveBeenCalledWith('groups', [RUNNER_USERNAME], expect.any(Object));
    });

    it('should handle command failure gracefully', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockRejectedValue(new Error('Command failed'));

      const result = await isRunnerInDockerGroup();

      expect(result).toBe(false);
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Could not check docker group membership'));
    });

    it('should handle empty output', async () => {
      const mockExec = exec.exec as jest.MockedFunction<typeof exec.exec>;
      mockExec.mockImplementation(async (cmd, args, options) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from(''));
        }
        return 0;
      });

      const result = await isRunnerInDockerGroup();

      expect(result).toBe(false);
    });
  });

  describe('constants', () => {
    it('should export correct constants', () => {
      expect(RUNNER_USERNAME).toBe('runner');
      expect(DOCKER_GROUP).toBe('docker');
    });
  });
});
