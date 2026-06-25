const { loadConfig } = require('./dist/config.js');
const { DatabaseStore } = require('./dist/storage/database.js');
const { GitHubClient } = require('./dist/github/client.js');
const { analyzePR } = require('./dist/ai/analyzer.js');
const { initHmacKey } = require('./dist/crypto/signing.js');
const { setDefaultResultOrder } = require('dns');
setDefaultResultOrder('ipv4first');

async function main() {
  console.log('=== AI ANALYSIS FULL TEST ===\n');

  const config = loadConfig();
  console.log('Config:');
  console.log('  aiModel:', config.aiModel);
  console.log('  aiEnabled:', config.aiEnabled);
  console.log('  repo:', config.githubOwner + '/' + config.githubRepo);

  const db = new DatabaseStore(config.dataDir, config.encryptionKey);
  initHmacKey(config.hmacSeed);

  const pr = db.getPRByNumber(2);
  if (!pr) {
    console.log('\n❌ PR #2 not found in DB');
    console.log('Available:', db.getPendingPRs().map(p => p.prNumber));
    db.close();
    return;
  }
  console.log('\nPR #2:', pr.title, 'by', pr.author);
  console.log('  sha:', pr.sha);

  const hasApp = !!config.githubAppId && !!config.githubInstallationId && !!config.githubPrivateKeyPath;
  const tokenOrConfig = hasApp
    ? { appId: config.githubAppId, installationId: config.githubInstallationId, privateKeyPath: config.githubPrivateKeyPath }
    : config.githubToken;
  const client = new GitHubClient(tokenOrConfig, config.githubOwner, config.githubRepo, config.githubStatusContext);
  const valid = await client.verifyToken();
  console.log('\nGitHub auth:', valid ? '✅' : '❌', `(${client.authMode})`);
  if (!valid) { db.close(); return; }

  console.log('\nFetching files for PR #2...');
  const files = await client.getPRFiles(2);
  console.log(`Got ${files.length} files`);
  files.forEach(f => console.log(`  ${f.status}: ${f.filename} (${f.additions}+ ${f.deletions}-)`));
  if (files.length === 0) { db.close(); return; }

  console.log('\n=== Calling analyzePR (this will try Ollama) ===');
  console.log('Model:', config.aiModel);
  console.time('ai-analysis');

  try {
    const result = await analyzePR(
      2, pr.title, pr.author, pr.body || '', '', pr.sha,
      files, pr.sha, db, config.aiModel || 'auto',
    );
    console.timeEnd('ai-analysis');

    console.log('\n=== RESULT ===');
    console.log('Model used:', result.modelName);
    console.log('Priority:', JSON.stringify(result.priority));
    console.log('\nExecutive Summary:');
    result.executiveSummary.forEach(s => console.log('  •', s));

    if (result.securityRelevantChanges?.length) {
      console.log('\nSecurity Relevant:');
      result.securityRelevantChanges.forEach(s => console.log('  •', s.title));
    }
    console.log('\nHotspots:');
    result.reviewHotspots.forEach(h => console.log('  •', h.file, '-', h.reason));
    console.log('\nNotes:');
    result.reviewerNotes.forEach(n => console.log('  •', n));

    const isFallback = result.executiveSummary.length <= 1 &&
      result.executiveSummary[0]?.includes('file(s) changed');

    if (result.modelName === config.aiModel) {
      console.log('\n✅ Ollama WAS USED');
    } else if (isFallback || result.modelName === 'sentinel-ai-engine') {
      console.log('\n❌ DETERMINISTIC FALLBACK used');
      console.log('  Ollama returned null (timeout/parse error)');
    } else {
      console.log('\n⚠ Model:', result.modelName);
    }
  } catch (err) {
    console.timeEnd('ai-analysis');
    console.log('\n❌ Error:', err.message);
  }

  db.close();
  console.log('\n=== DONE ===');
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
