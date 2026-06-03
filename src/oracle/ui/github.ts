import * as readline from 'readline';
import { execFileSync } from 'child_process';
import pc from 'picocolors';

function hasGh(): boolean {
  try {
    execFileSync('gh', ['--version'], { encoding: 'utf-8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function getGhUsername(): string | null {
  try {
    const out = execFileSync('gh', ['auth', 'status'], { encoding: 'utf-8', stdio: 'pipe' });
    const match = out.match(/Logged in to github\.com(?: as ([^\s]+))?/);
    return match ? (match[1] || 'authenticated') : null;
  } catch {
    return null;
  }
}

export async function checkGitHubLogin(): Promise<boolean> {
  if (!hasGh()) {
    console.log(`  ${pc.dim(pc.gray('  gh CLI not detected — skipping GitHub check'))}\n`);
    return false;
  }

  const username = getGhUsername();
  if (username) {
    console.log(`  ${pc.green('✓')} ${pc.dim('GitHub:')} ${pc.bold(pc.white(`@${username}`))} ${pc.dim('authenticated')}\n`);
    return true;
  }

  const W = 54;
  const top = `${pc.cyan('┌')}${pc.cyan('─'.repeat(W))}${pc.cyan('┐')}`;
  const title = `${pc.cyan('│')}  ${pc.white(pc.bold('GitHub authentication recommended'))}${' '.repeat(W - 37)}${pc.cyan('│')}`;
  const blank = `${pc.cyan('│')}${' '.repeat(W + 2)}${pc.cyan('│')}`;
  const line1 = `${pc.cyan('│')}  ${pc.dim('• PR analysis')}${' '.repeat(W - 15)}${pc.cyan('│')}`;
  const line2 = `${pc.cyan('│')}  ${pc.dim('• repository scanning')}${' '.repeat(W - 24)}${pc.cyan('│')}`;
  const line3 = `${pc.cyan('│')}  ${pc.dim('• issue creation')}${' '.repeat(W - 19)}${pc.cyan('│')}`;
  const bot = `${pc.cyan('└')}${pc.cyan('─'.repeat(W))}${pc.cyan('┘')}`;

  console.log(`  ${top}`);
  console.log(`  ${title}`);
  console.log(`  ${blank}`);
  console.log(`  ${line1}`);
  console.log(`  ${line2}`);
  console.log(`  ${line3}`);
  console.log(`  ${blank}`);
  console.log(`  ${pc.cyan('│')}  ${pc.cyan('[1]')} ${pc.white('Login with GitHub CLI')}${' '.repeat(W - 28)}${pc.cyan('│')}`);
  console.log(`  ${pc.cyan('│')}  ${pc.cyan('[2]')} ${pc.white('Skip (limited functionality)')}${' '.repeat(W - 34)}${pc.cyan('│')}`);
  console.log(`  ${bot}`);
  console.log();

  const answer = await new Promise<string>((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(`  ${pc.cyan('Select option')} ${pc.dim('(1-2)')}: `, (a) => {
      rl.close();
      resolve(a.trim());
    });
  });

  if (answer === '1') {
    console.log(`  ${pc.dim('Opening browser for GitHub authentication...')}\n`);
    try {
      execFileSync('gh', ['auth', 'login', '-w', '-p', 'https'], {
        encoding: 'utf-8',
        stdio: 'inherit',
        timeout: 120000,
      });
      const loggedIn = getGhUsername();
      if (loggedIn) {
        console.log(`\n  ${pc.green('✓')} ${pc.bold(pc.white(`GitHub authenticated as @${loggedIn}`))}\n`);
        return true;
      }
      console.log(`\n  ${pc.yellow('GitHub authentication incomplete. Run /gh-login later.\n')}`);
      return false;
    } catch {
      console.log(`\n  ${pc.red('GitHub login failed. You can retry later with /gh-login.\n')}`);
      return false;
    }
  }

  console.log(`  ${pc.yellow('Skipping GitHub setup. Some features limited.')}\n`);
  return false;
}
