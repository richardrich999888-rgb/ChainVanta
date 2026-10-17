import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, readdirSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const { entries } = JSON.parse(
  readFileSync(resolve(root, 'docs/development/repository-structure.json'), 'utf8'),
);
// Leaf directories are extension points. Enumerated directory boundaries are closed.
const boundaries = new Map();
const errors = [];
for (const entry of entries) {
  const parent = dirname(entry.path);
  if (!boundaries.has(parent)) boundaries.set(parent, new Set());
  boundaries.get(parent).add(entry.path.split('/').at(-1));
  try {
    const stat = statSync(resolve(root, entry.path));
    if (entry.type === 'directory' ? !stat.isDirectory() : !stat.isFile())
      errors.push(`Wrong type: ${entry.path}`);
  } catch {
    errors.push(`Missing ${entry.type}: ${entry.path}`);
  }
}
// Next.js session/proxy handlers support the ten prescribed customer routes.
boundaries.get('apps/web-console/src/app').add('api');
// Dependency reproducibility requires pnpm's lockfile alongside package.json.
boundaries.get('.').add('pnpm-lock.yaml');
const sourcePaths = execFileSync(
  'git',
  ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
  {
    cwd: root,
    encoding: 'utf8',
  },
)
  .split('\0')
  .filter(Boolean);
const exactFiles = new Set(['.', '.github/workflows', 'docs/architecture']);
for (const file of sourcePaths) {
  const parts = file.split('/');
  let parent = '.';
  for (let i = 0; i < parts.length; i++) {
    const name = parts[i];
    const boundary = boundaries.get(parent);
    if (boundary && (i < parts.length - 1 || exactFiles.has(parent)) && !boundary.has(name)) {
      errors.push(`Unexpected source path: ${file} (outside ${parent})`);
      break;
    }
    parent = parent === '.' ? name : `${parent}/${name}`;
  }
}
// Check physical directories too, so empty unrecognized folders cannot drift unnoticed.
const generated = new Set([
  '.git',
  '.local',
  'node_modules',
  '.next',
  'dist',
  'coverage',
  'test-results',
  'playwright-report',
  '.pnpm-store',
  'target',
]);
for (const [parent, names] of boundaries) {
  const absolute = resolve(root, parent);
  let children;
  try {
    children = readdirSync(absolute, { withFileTypes: true });
  } catch {
    continue;
  }
  for (const child of children)
    if (child.isDirectory() && !generated.has(child.name) && !names.has(child.name))
      errors.push(`Unexpected directory: ${relative(root, resolve(absolute, child.name))}`);
}
if (errors.length) {
  console.error([...new Set(errors)].join('\n'));
  process.exitCode = 1;
} else {
  console.log(
    `Repository structure verified: ${entries.filter((entry) => entry.type === 'directory').length} required directories and ${entries.filter((entry) => entry.type === 'file').length} required files.`,
  );
}
