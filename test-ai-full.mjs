import { loadConfig } from './dist/config.js';
import { DatabaseStore } from './dist/storage/database.js';
import { GitHubClient } from './dist/github/client.js';
import { analyzePR } from './dist/ai/analyzer.js';
import { initHmacKey } from './dist/crypto/signing.js';
import { setDefaultResultOrder } from 'dns';
setDefaultResultOrder('ipv4first');

async function main() {
  console.log('=== AI ANALYSIS FULL TEST ===\n');

  // 1. Load config
  const config = loadConfig();
  console.log('Config loaded:');
  console.log('  aiModel:', config.aiModel);
  console.log('  aiEnabled:', config.aiEnabled);
  console.log('  repo:', config.githubOwner + '/' + config.githubRepo);

  // 2. Init database
  const db = new DatabaseStore(config.dataDir, config.encryptionKey);
  initHmacKey(config.hmacSeed);

  // 3. Get PR #2 from DB
  const pr = db.getPRByNumber(2);
  if (!pr) {
    console.log('\n❌ PR #2 not found in DB');
    console.log('Available PRs:', db.getPendingPRs().map(p => p.prNumber));
    db.close();
    return;
  }
  console.log('\nPR #2:', pr.title, 'by', pr.author);
  console.log('  sha:', pr.sha);
  console.log('  status:', pr.sentinelStatus, '/', pr.authStatus);

  // 4. Init GitHub client
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && !!config.githubPrivateKeyPath;
  const tokenOrConfig = hasApp
    ? { appId: config.githubAppId, installationId: config.githubInstallationId, privateKeyPath: config.githubPrivateKeyPath }
    : config.githubToken;
  const client = new GitHubClient(tokenOrConfig, config.githubOwner, config.githubRepo, config.githubStatusContext);
  const valid = await client.verifyToken();
  console.log('\nGitHub auth:', valid ? '✅' : '❌', `(${client.authMode})`);

  if (!valid) {
    console.log('Cannot proceed without GitHub auth');
    db.close();
    return;
  }

  // 5. Get PR files from GitHub
  console.log('\nFetching files for PR #2...');
  const files = await client.getPRFiles(2);
  console.log(`Got ${files.length} files`);
  files.forEach(f => console.log(`  ${f.status}: ${f.filename} (${f.additions}+ ${f.deletions}-)`));

  if (files.length === 0) {
    console.log('No files — cannot analyze');
    db.close();
    return;
  }

  // 6. Run AI analysis (this will call Ollama!)
  console.log('\n=== Calling analyzePR (Ollama) ===');
  console.log('Model:', config.aiModel);
  console.time('ai-analysis');

  try {
    const result = await analyzePR(
      2,
      pr.title,
      pr.author,
      pr.body || '',
      '',
      pr.sha,
      files,
      pr.sha,
      db,
      config.aiModel || 'auto',
    );
    console.timeEnd('ai-analysis');

    console.log('\n=== ANALYSIS RESULT ===');
    console.log('Model used:', result.modelName);
    console.log('Priority:', JSON.stringify(result.priority));

    console.log('\nExecutive Summary:');
    result.executiveSummary.forEach(s => console.log('  •', s));

    if (result.architecturalChanges?.length > 0) {
      console.log('\nArchitectural Changes:');
      result.architecturalChanges.forEach(a => console.log('  •', a.title, '-', a.description));
    }

    if (result.securityRelevantChanges?.length > 0) {
      console.log('\nSecurity Relevant Changes:');
      result.securityRelevantChanges.forEach(s => console.log('  •', s.title));
    }

    console.log('\nReview Hotspots:');
    result.reviewHotspots.forEach(h => console.log('  •', h.file, '-', h.reason));

    console.log('\nReviewer Notes:');
    result.reviewerNotes.forEach(n => console.log('  •', n));

    if (result.instructionManipulation?.length > 0) {
      console.log('\n⚠ Instruction Manipulation detected:');
      result.instructionManipulation.forEach(i => console.log('  •', i.type, '-', i.severity));
    }

    console.log('\nScanner Correlation:');
    console.log('  Risk Score:', result.scannerCorrelation.riskScore);
    console.log('  Findings:', result.scannerCorrelation.findings);

    const isFallback = result.executiveSummary.length === 1 &&
      result.executiveSummary[0].includes('file(s) changed') &&
      !result.executiveSummary[0].includes('add');
    
    if (result.modelName === config.aiModel) {
      console.log('\n✅ AI MODEL WAS USED (model:', result.modelName + ')');
    } else if (result.modelName === 'sentinel-ai-engine' || isFallback) {
      console.log('\n❌ DETERMINISTIC FALLBACK WAS USED');
      console.log('  Ollama returned null or errored');
    } else {
      console.log('\n⚠ Model name in result:', result.modelName);
    }
  } catch (err) {
    console.timeEnd('ai-analysis');
    console.log('\n❌ Error:', err.message);
    console.log(err.stack);
  }

  db.close();
  console.log('\n=== DONE ===');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
