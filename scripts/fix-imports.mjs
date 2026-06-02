import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, relative, sep } from 'path';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');
const SRC = join(ROOT, 'src');

function fixImports(dir) {
  const entries = readdirSync(dir);
  for (const f of entries) {
    const full = join(dir, f);
    if (f === 'node_modules' || f === 'dist' || f === '.git') continue;
    if (statSync(full).isDirectory()) { fixImports(full); continue; }
    if (!f.endsWith('.ts') && !f.endsWith('.tsx')) continue;

    let content = readFileSync(full, 'utf8');
    const orig = content;

    // Match: import ... from './...' or '../...'
    content = content.replace(
      /^(import .+ from\s+['"])(\.\.?\/[^'"]+)(['"])/gm,
      (match, prefix, importPath, suffix) => {
        if (importPath.endsWith('.js')) return match;

        // Check if it's a directory import
        const resolved = join(dir, importPath);
        if (existsSync(resolved) && statSync(resolved).isDirectory()) {
          return prefix + importPath + '/index.js' + suffix;
        }
        return prefix + importPath + '.js' + suffix;
      }
    );

    if (content !== orig) {
      writeFileSync(full, content, 'utf8');
      console.log('Fixed:', relative(ROOT, full).replace(/\\/g, '/'));
    }
  }
}

fixImports(SRC);
console.log('Done');
