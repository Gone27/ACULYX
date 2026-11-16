import { spawnSync } from 'node:child_process';

const cmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const res = spawnSync(cmd, [
  'vitest',
  'run',
  'tests/security/content-script-syntax.test.ts',
  'tests/security/artifact-scan.test.ts',
], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, TEST_ARTIFACTS: '1', REQUIRE_BUILD_ARTIFACTS: 'true' },
});

process.exit(res.status ?? 0);
