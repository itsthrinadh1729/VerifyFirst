import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');
const releaseDir = path.join(rootDir, 'release');
const stagingDir = path.join(releaseDir, 'VerifyFirst');
const zipFile = path.join(releaseDir, 'VerifyFirst.zip');

if (fs.existsSync(zipFile)) {
    fs.unlinkSync(zipFile);
}

console.log('Zipping release package...');
try {
  execSync(`powershell -Command "Compress-Archive -Path '${stagingDir}/*' -DestinationPath '${zipFile}' -Force"`, { stdio: 'inherit' });
} catch (e) {
  console.log('Using fallback tar command for zip...');
  execSync(`tar -a -c -f ${zipFile} -C ${stagingDir} .`, { stdio: 'inherit' });
}

console.log('Release package generated: release/VerifyFirst.zip');
