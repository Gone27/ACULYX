import { spawnSync } from 'node:child_process';

const cmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const res = spawnSync(cmd, ['vitest', 'run', 'tests/security/content-script-syntax.test.ts'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, TEST_ARTIFACTS: '1' },
});

process.exit(res.status ?? 0);
