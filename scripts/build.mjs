import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');
const extDir = path.join(rootDir, 'extension');
const releaseDir = path.join(rootDir, 'release');
const stagingDir = path.join(releaseDir, 'VerifyFirst');

console.log('--- VerifyFirst Production Build ---');

// 1. Run tsc
console.log('Compiling TypeScript...');
execSync('npm run build', { cwd: extDir, stdio: 'inherit' });

// 2. Prepare staging directory
console.log('Preparing staging directory...');
if (fs.existsSync(releaseDir)) {
  fs.rmSync(releaseDir, { recursive: true, force: true });
}
fs.mkdirSync(stagingDir, { recursive: true });

// 3. Copy files
console.log('Copying runtime files...');
const dirsToCopy = ['assets', 'background', 'content', 'shared'];
for (const dir of dirsToCopy) {
  const src = path.join(extDir, dir);
  const dest = path.join(stagingDir, dir);
  if (fs.existsSync(src)) {
    fs.cpSync(src, dest, { recursive: true });
  }
}

// Copy manifest.json
fs.copyFileSync(path.join(extDir, 'manifest.json'), path.join(stagingDir, 'manifest.json'));

// 4. Remove .ts files from staging
console.log('Cleaning up .ts files...');
function removeTsFiles(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      removeTsFiles(fullPath);
    } else if (fullPath.endsWith('.ts')) {
      fs.unlinkSync(fullPath);
    }
  }
}
removeTsFiles(stagingDir);

console.log('Build completed successfully. Staging directory: release/VerifyFirst');
