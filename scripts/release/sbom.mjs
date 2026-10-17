import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
// Inventory the installed pnpm production graph. No filesystem paths or environment values exported.
const result = spawnSync('pnpm', ['list', '-r', '--prod', '--depth', 'Infinity', '--json'], {
  encoding: 'utf8',
  maxBuffer: 32 * 1024 * 1024,
});
if (result.status !== 0) throw new Error('pnpm dependency inventory failed');
const components = new Map(),
  dependencies = new Map();
const ref = (name, version) => `pkg:npm/${name.replace('@', '%40')}@${version}`;
function visit(name, pkg) {
  const id = ref(name, pkg.version);
  if (!components.has(id))
    components.set(id, {
      type: 'library',
      name,
      version: pkg.version,
      purl: id,
      'bom-ref': id,
      scope: 'required',
    });
  if (dependencies.has(id)) return id;
  const deps = [];
  dependencies.set(id, { ref: id, dependsOn: deps });
  for (const [child, value] of Object.entries({ ...pkg.dependencies, ...pkg.optionalDependencies }))
    deps.push(visit(child, value));
  return id;
}
const roots = JSON.parse(result.stdout).map((pkg) => {
  const id = visit(pkg.name, pkg);
  components.get(id).type = 'application';
  return id;
});
mkdirSync('.local', { recursive: true });
const output = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    component: {
      type: 'application',
      name: 'chainvanta',
      version: '0.2.0',
      'bom-ref': 'chainvanta',
    },
    properties: [
      {
        name: 'chainvanta:scope',
        value:
          'Installed pnpm production dependency graph; excludes Go, container OS packages, licenses and artifact hashes.',
      },
    ],
  },
  components: [...components.values()],
  dependencies: [{ ref: 'chainvanta', dependsOn: roots }, ...dependencies.values()],
};
writeFileSync('.local/sbom.cdx.json', JSON.stringify(output, null, 2) + '\n');
console.log(`Wrote .local/sbom.cdx.json (${components.size} production components)`);
