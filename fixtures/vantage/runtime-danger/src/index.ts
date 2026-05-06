import { rmSync } from 'node:fs';
import { execSync } from 'node:child_process';
const home = process.env.HOME;
const fn = new Function('return 1');
execSync(String(home));
rmSync('/tmp/example', { recursive: true, force: true });
export { fn };
