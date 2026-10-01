import fs from 'fs';
import path from 'path';

import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');
const extDir = path.join(rootDir, 'extension');
const stagingDir = path.join(rootDir, 'release', 'VerifyFirst');

let failed = false;

function error(msg) {
  console.error('❌ ' + msg);
  failed = true;
}

function success(msg) {
  console.log('✅ ' + msg);
}

console.log('--- VerifyFirst Release Check ---');

// 1. Manifest Checks
const manifestPath = path.join(stagingDir, 'manifest.json');
if (!fs.existsSync(manifestPath)) {
  error('manifest.json is missing');
} else {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  if (manifest.manifest_version !== 3) error('Manifest is not V3');
  else success('Manifest is V3');

  if (!manifest.version) error('Manifest version is missing');
  else success('Valid version found');

  if (!manifest.icons || !manifest.icons['16'] || !manifest.icons['48'] || !manifest.icons['128']) {
    error('Required icons missing from manifest');
  } else success('Required icons present in manifest');

  if (!manifest.action || !manifest.action.default_popup) {
    error('Popup missing in action');
  } else success('Popup present in action');

  if (!manifest.background || !manifest.background.service_worker) {
    error('Service worker missing');
  } else success('Service worker present in manifest');

  if (!manifest.content_scripts || manifest.content_scripts.length === 0) {
    error('Content scripts missing');
  } else success('Content scripts present');

  function checkExists(relPath) {
    if (relPath.includes('*')) return;
    if (!fs.existsSync(path.join(stagingDir, relPath))) {
      error(`Manifest reference missing: ${relPath}`);
    }
  }

  if (manifest.action.default_popup) checkExists(manifest.action.default_popup);
  if (manifest.background.service_worker) checkExists(manifest.background.service_worker);
  manifest.content_scripts.forEach(cs => {
    if (cs.css) cs.css.forEach(checkExists);
    if (cs.js) cs.js.forEach(checkExists);
  });
}

// 2. Scan Code for Issues and Runtime References
function scanDirectory(dir) {
  if (!fs.existsSync(dir)) return;
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      if (['node_modules', '.git', 'tests', 'evaluation'].includes(file)) continue;
      scanDirectory(fullPath);
    } else {
      if (file.endsWith('.js') || file.endsWith('.html') || file.endsWith('.json') || file.endsWith('.css')) {
        const content = fs.readFileSync(fullPath, 'utf8');
        
        const isManifest = file === 'manifest.json';
        const isPackageLock = file === 'package-lock.json';
        const isPackageJson = file === 'package.json';
        const isScript = file.endsWith('.js');
        const isHtml = file.endsWith('.html');
        const isCss = file.endsWith('.css');
        
        if (!isPackageLock && !isPackageJson) {
            if (content.includes('localhost')) error(`localhost found in ${fullPath}`);
            if (content.includes('127.0.0.1')) error(`127.0.0.1 found in ${fullPath}`);
            
            // Check for API Keys / Secrets
            if (/(API_KEY|SECRET=|PRIVATE_KEY|TOKEN=)/i.test(content) && !isManifest) {
                if (!content.includes('css-tokenizer')) {
                    error(`Potential secret found in ${fullPath}`);
                }
            }

            // Reject placeholders in all code to ensure production URL is set
            if (content.includes('example.com') || content.includes('YOUR_API_DOMAIN_HERE')) {
                error(`Placeholder domain found in ${fullPath}. Replace with production domain.`);
            }
            
            // Check for eval / remote code execution patterns
            if (isScript && /(eval\(|new Function\()/.test(content)) {
                error(`Potential remote code execution pattern found in ${fullPath}`);
            }

            // --- Runtime Reference Audit ---
            function checkRef(refPath) {
                if (refPath.startsWith('http://') || refPath.startsWith('https://') || refPath.startsWith('data:')) return;
                
                // If it starts with / or is absolute in chrome extension terms, it's relative to stagingDir
                // Otherwise it's relative to the file's directory
                let resolvedPath;
                if (refPath.startsWith('/')) {
                    resolvedPath = path.join(stagingDir, refPath.substring(1));
                } else if (isScript && (content.includes(`chrome.runtime.getURL("${refPath}")`) || content.includes(`chrome.runtime.getURL('${refPath}')`))) {
                    // getURL usually takes a path relative to extension root
                    resolvedPath = path.join(stagingDir, refPath);
                } else {
                    resolvedPath = path.join(dir, refPath);
                }

                // Handle query parameters or hashes
                resolvedPath = resolvedPath.split('?')[0].split('#')[0];

                if (!fs.existsSync(resolvedPath)) {
                    error(`Broken runtime reference found in ${file}: ${refPath}`);
                }
            }

            if (isHtml) {
                const srcRegex = /src=["']([^"']+)["']/g;
                const hrefRegex = /href=["']([^"']+)["']/g;
                let match;
                while ((match = srcRegex.exec(content)) !== null) checkRef(match[1]);
                while ((match = hrefRegex.exec(content)) !== null) checkRef(match[1]);
            }

            if (isCss) {
                const urlRegex = /url\(['"]?([^'"()]+)['"]?\)/g;
                let match;
                while ((match = urlRegex.exec(content)) !== null) checkRef(match[1]);
            }

            if (isScript) {
                const importRegex = /(?:import|export).*?from\s+['"]([^'"]+)['"]/g;
                const importOnlyRegex = /(?:import)\s*['"]([^'"]+)['"]/g;
                const getUrlRegex = /chrome\.runtime\.getURL\(['"]([^'"]+)['"]\)/g;
                
                let match;
                while ((match = importRegex.exec(content)) !== null) checkRef(match[1]);
                while ((match = importOnlyRegex.exec(content)) !== null) checkRef(match[1]);
                while ((match = getUrlRegex.exec(content)) !== null) checkRef(match[1]);
            }
        }
      }
    }
  }
}

scanDirectory(stagingDir);

if (failed) {
  console.error('\n❌ Release checks failed. Please fix the issues above.');
  process.exit(1);
} else {
  console.log('\n🎉 All release checks passed!');
}
