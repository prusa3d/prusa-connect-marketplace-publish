// The fixture's bundle build: writes the release layout the builder expects,
// module.yaml at the root of dist/ and the bundle under dist/ui/.
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';

mkdirSync('ui/dist/ui', { recursive: true });
copyFileSync('module.yaml', 'ui/dist/module.yaml');
writeFileSync('ui/dist/ui/index.js', 'export default {};\n');
