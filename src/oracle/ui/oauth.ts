import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as pc from 'picocolors';

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  provider: string;
}

export interface ProviderOAuthConfig {
  clientId: string;
  authorizationUrl: string;
  tokenUrl: string;
  scopes: string[];
  redirectPort?: number;
}

export const PROVIDER_OAUTH_CONFIGS: Record<string, ProviderOAuthConfig> = {
  gemini: {
    clientId: 'SENTINEL_GEMINI_CLIENT_ID',
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scopes: ['https://www.googleapis.com/auth/generative-language'],
    redirectPort: 8742,
  },
  claude: {
    clientId: 'SENTINEL_CLAUDE_CLIENT_ID',
    authorizationUrl: 'https://id.anthropic.com/authorize',
    tokenUrl: 'https://id.anthropic.com/token',
    scopes: ['openid', 'profile', 'email'],
    redirectPort: 8743,
  },
  openai: {
    clientId: 'SENTINEL_OPENAI_CLIENT_ID',
    authorizationUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopes: ['openai_api_keys:read'],
    redirectPort: 8744,
  },
};

const SENTINEL_DIR = path.join(os.homedir(), '.sentinel');
const CREDENTIALS_FILE = path.join(SENTINEL_DIR, 'credentials.enc');
const OAUTH_TIMEOUT = 5 * 60 * 1000;

function base64URLEncode(buf: Buffer): string {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function getSentinelDir(): string {
  if (!fs.existsSync(SENTINEL_DIR)) {
    fs.mkdirSync(SENTINEL_DIR, { recursive: true });
    try {
      if (process.platform !== 'win32') {
        fs.chmodSync(SENTINEL_DIR, 0o700);
      }
    } catch {
      // non-fatal
    }
  }
  return SENTINEL_DIR;
}

function getMachineKey(): string {
  let username = 'unknown';
  try {
    username = os.userInfo().username;
  } catch {
    // fallback in restricted environments
  }
  return `${os.hostname()}-${username}-sentinel-oracle`;
}

function setSecurePermissions(filePath: string): void {
  try {
    if (process.platform !== 'win32') {
      fs.chmodSync(filePath, 0o600);
    }
  } catch {
    // non-fatal
  }
}

function httpsPost(url: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: string) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function getDeviceAuthUrl(authorizationUrl: string): string {
  const known: Record<string, string> = {
    'https://accounts.google.com/o/oauth2/v2/auth': 'https://oauth2.googleapis.com/device/code',
    'https://github.com/login/oauth/authorize': 'https://github.com/login/device/code',
  };
  if (known[authorizationUrl]) return known[authorizationUrl];
  return authorizationUrl
    .replace(/\/auth(?:\/|$)/, '/device/code')
    .replace(/\/authorize(?:\/|$)/, '/device/code');
}

export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = base64URLEncode(crypto.randomBytes(32));
  const hash = crypto.createHash('sha256').update(verifier).digest();
  const challenge = base64URLEncode(hash);
  return { verifier, challenge };
}

export function startLocalhostServer(
  port: number,
  redirectPath?: string
): Promise<{ code: string; state: string }> {
  const cbPath = `/${redirectPath || 'callback'}`;

  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const reqUrl = req.url || '/';
      if (!reqUrl.startsWith(cbPath)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }

      const idx = reqUrl.indexOf('?');
      const search = idx >= 0 ? reqUrl.slice(idx) : '';
      const params = new URLSearchParams(search);
      const code = params.get('code');
      const state = params.get('state');

      if (code && state) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(
          '<html><body style="font-family:sans-serif;display:flex;align-items:center;'
          + 'justify-content:center;height:100vh;margin:0;background:#f5f5f5">'
          + '<div style="text-align:center;padding:2rem;background:white;'
          + 'border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1)">'
          + '<h2 style="color:#22c55e">✓ Authentication successful</h2>'
          + '<p style="color:#666">You may close this window and return to the terminal.</p>'
          + '</div></body></html>'
        );
        server.close();
        clearTimeout(timer);
        resolve({ code, state });
      } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(
          '<html><body><h2>Authentication failed</h2>'
          + '<p>Missing code or state parameter.</p></body></html>'
        );
        server.close();
        clearTimeout(timer);
        reject(new Error('Missing code or state in callback'));
      }
    });

    server.listen(port, '127.0.0.1');
    server.unref();

    const timer = setTimeout(() => {
      server.close();
      reject(new Error('OAuth callback timeout'));
    }, OAUTH_TIMEOUT);

    timer.unref();
  });
}

export function openBrowser(url: string): Promise<void> {
  const platform = process.platform;

  return new Promise((resolve, reject) => {
    if (platform === 'win32') {
      execFile('cmd', ['/c', 'start', '""', url], (err) => {
        if (err) reject(err);
        else resolve();
      });
    } else if (platform === 'darwin') {
      execFile('open', [url], (err) => {
        if (err) reject(err);
        else resolve();
      });
    } else {
      execFile('xdg-open', [url], (err) => {
        if (err) reject(err);
        else resolve();
      });
    }
  });
}

export async function exchangeCodeForTokens(
  tokenUrl: string,
  clientId: string,
  code: string,
  codeVerifier: string,
  redirectUri: string
): Promise<{ accessToken: string; refreshToken?: string }> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
  }).toString();

  const response = await httpsPost(tokenUrl, body);

  try {
    const json = JSON.parse(response);
    if (json.access_token) {
      return {
        accessToken: json.access_token,
        refreshToken: json.refresh_token,
      };
    }
    if (json.error) {
      throw new Error(
        `Token exchange failed: ${json.error_description || json.error}`
      );
    }
  } catch (e: any) {
    if (e.message && e.message.startsWith('Token exchange failed')) throw e;
  }

  const params = new URLSearchParams(response);
  const accessToken = params.get('access_token');
  if (accessToken) {
    return {
      accessToken,
      refreshToken: params.get('refresh_token') || undefined,
    };
  }

  throw new Error('Token exchange failed: no access token in response');
}

export async function oauthLogin(
  provider: string,
  config?: ProviderOAuthConfig
): Promise<string | null> {
  const cfg = config || PROVIDER_OAUTH_CONFIGS[provider];
  if (!cfg) {
    console.error(`  ${pc.red(`No OAuth configuration for provider "${provider}"`)}`);
    return null;
  }

  const pkce = generatePKCE();
  const port = cfg.redirectPort || 8742;
  const redirectPath = 'callback';
  const redirectUri = `http://127.0.0.1:${port}/${redirectPath}`;
  const state = crypto.randomBytes(16).toString('hex');

  let resolvedClientId = cfg.clientId;
  if (resolvedClientId.startsWith('SENTINEL_')) {
    const envVar = process.env[resolvedClientId];
    if (envVar) resolvedClientId = envVar;
  }

  try {
    const serverPromise = startLocalhostServer(port, redirectPath);

    const authUrl = new URL(cfg.authorizationUrl);
    authUrl.searchParams.set('client_id', resolvedClientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', cfg.scopes.join(' '));
    authUrl.searchParams.set('code_challenge', pkce.challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');

    console.log(`  ${pc.dim('Opening browser for')} ${pc.bold(provider)} ${pc.dim('authentication...')}`);
    await openBrowser(authUrl.toString());

    const callback = await serverPromise;

    if (callback.state !== state) {
      console.error(`  ${pc.red('State mismatch - possible CSRF attack')}`);
      return null;
    }

    const tokens = await exchangeCodeForTokens(
      cfg.tokenUrl,
      resolvedClientId,
      callback.code,
      pkce.verifier,
      redirectUri
    );

    await storeTokenInKeychain('sentinel-oracle', provider, tokens.accessToken);

    console.log(`  ${pc.green('✓')} ${pc.bold(provider)} ${pc.green('authenticated successfully')}`);
    return tokens.accessToken;
  } catch (err: any) {
    if (err.message === 'OAuth callback timeout') {
      console.error(`  ${pc.yellow('Authentication timed out. Please try again.')}`);
    } else if (err.message && err.message.startsWith('Token exchange failed')) {
      console.error(`  ${pc.red(err.message)}`);
    } else if (err.message !== 'Missing code or state in callback') {
      console.error(`  ${pc.red(`Authentication failed: ${err.message || 'Unknown error'}`)}`);
    }
    return null;
  }
}

function credentialsFilePath(): string {
  getSentinelDir();
  return CREDENTIALS_FILE;
}

function readCredentialsFile(): Record<string, string> {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE)) return {};
    const encrypted = fs.readFileSync(CREDENTIALS_FILE, 'utf-8').trim();
    if (!encrypted) return {};
    const decrypted = decryptData(encrypted, getMachineKey());
    if (!decrypted) return {};
    return JSON.parse(decrypted);
  } catch {
    return {};
  }
}

function writeCredentialsFile(data: Record<string, string>): void {
  getSentinelDir();
  const json = JSON.stringify(data);
  const encrypted = encryptData(json, getMachineKey());
  fs.writeFileSync(CREDENTIALS_FILE, encrypted, 'utf-8');
  setSecurePermissions(CREDENTIALS_FILE);
}

function credentialKey(service: string, account: string): string {
  return `${service}:${account}`;
}

export async function storeTokenInKeychain(
  service: string,
  account: string,
  token: string
): Promise<boolean> {
  try {
    const keytar = require('keytar');
    await keytar.setPassword(service, account, token);
    return true;
  } catch {
    // keytar unavailable — fall through to encrypted file
  }

  try {
    const creds = readCredentialsFile();
    creds[credentialKey(service, account)] = token;
    writeCredentialsFile(creds);
    return true;
  } catch {
    return false;
  }
}

export async function getTokenFromKeychain(
  service: string,
  account: string
): Promise<string | null> {
  try {
    const keytar = require('keytar');
    const pw = await keytar.getPassword(service, account);
    if (pw) return pw;
  } catch {
    // fallback
  }

  try {
    const creds = readCredentialsFile();
    return creds[credentialKey(service, account)] || null;
  } catch {
    return null;
  }
}

export async function removeTokenFromKeychain(
  service: string,
  account: string
): Promise<boolean> {
  try {
    const keytar = require('keytar');
    await keytar.deletePassword(service, account);
    return true;
  } catch {
    // fallback
  }

  try {
    const creds = readCredentialsFile();
    const key = credentialKey(service, account);
    if (key in creds) {
      delete creds[key];
      if (Object.keys(creds).length === 0) {
        try {
          fs.unlinkSync(CREDENTIALS_FILE);
        } catch {
          // file may not exist
        }
      } else {
        writeCredentialsFile(creds);
      }
    }
    return true;
  } catch {
    return false;
  }
}

export function encryptData(data: string, key: string): string {
  const keyBuf = crypto.createHash('sha256').update(key).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  let encrypted = cipher.update(data, 'utf-8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
}

export function decryptData(encrypted: string, key: string): string | null {
  try {
    const parts = encrypted.split(':');
    if (parts.length !== 3) return null;
    const [ivB64, tagB64, ciphertext] = parts;
    const keyBuf = crypto.createHash('sha256').update(key).digest();
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(ciphertext, 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
  } catch {
    return null;
  }
}

export async function deviceCodeFlow(
  provider: string,
  config: ProviderOAuthConfig
): Promise<string | null> {
  const deviceAuthUrl = getDeviceAuthUrl(config.authorizationUrl);

  let resolvedClientId = config.clientId;
  if (resolvedClientId.startsWith('SENTINEL_')) {
    const envVar = process.env[resolvedClientId];
    if (envVar) resolvedClientId = envVar;
  }

  try {
    const deviceBody = new URLSearchParams({
      client_id: resolvedClientId,
      scope: config.scopes.join(' '),
    }).toString();

    const deviceResponse = await httpsPost(deviceAuthUrl, deviceBody);
    let deviceData: any;
    try {
      deviceData = JSON.parse(deviceResponse);
    } catch {
      const params = new URLSearchParams(deviceResponse);
      deviceData = Object.fromEntries(params);
    }

    if (!deviceData.device_code || !deviceData.user_code) {
      console.error(`  ${pc.red('Device code registration failed')}`);
      return null;
    }

    console.log(`\n  ${pc.cyan('═'.repeat(50))}`);
    console.log(`  ${pc.bold('Device Authentication')}`);
    console.log(`  ${pc.cyan('═'.repeat(50))}`);
    console.log(`\n  ${pc.dim('Open the following URL in any browser:')}`);
    console.log(
      `  ${pc.bold(pc.cyan(deviceData.verification_uri_complete || deviceData.verification_uri))}`
    );
    console.log(`\n  ${pc.dim('Or enter the code manually:')}`);
    console.log(`  ${pc.bold('Code:')} ${pc.bold(pc.bgCyan(pc.black(` ${deviceData.user_code} `)))}\n`);
    console.log(`  ${pc.dim('Waiting for authorization...')}\n`);

    const interval = (deviceData.interval || 5) * 1000;
    const expiresIn = (deviceData.expires_in || 300) * 1000;
    const startTime = Date.now();

    while (Date.now() - startTime < expiresIn) {
      await new Promise((resolve) => setTimeout(resolve, interval));

      const pollBody = new URLSearchParams({
        client_id: resolvedClientId,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceData.device_code,
      }).toString();

      try {
        const pollResponse = await httpsPost(config.tokenUrl, pollBody);
        const pollData = JSON.parse(pollResponse);

        if (pollData.access_token) {
          await storeTokenInKeychain('sentinel-oracle', provider, pollData.access_token);
          console.log(`  ${pc.green('✓')} ${pc.bold(provider)} ${pc.green('authenticated successfully')}\n`);
          return pollData.access_token;
        }

        if (pollData.error === 'authorization_pending') continue;
        if (pollData.error === 'slow_down') {
          await new Promise((resolve) => setTimeout(resolve, 5000));
          continue;
        }
        if (pollData.error === 'access_denied') {
          console.error(`  ${pc.yellow('Authorization denied by user.')}`);
          return null;
        }
        if (pollData.error === 'expired_token') {
          console.error(`  ${pc.yellow('Device code expired. Please try again.')}`);
          return null;
        }
      } catch {
        return null;
      }
    }

    console.error(`  ${pc.yellow('Authentication timed out.')}`);
    return null;
  } catch (err: any) {
    console.error(
      `  ${pc.red(`Device code flow failed: ${err.message || 'Unknown error'}`)}`
    );
    return null;
  }
}
