import type { PRFile } from '../rules'
import type { CapabilityIntel, IntelRisk } from './types'

const FILESYSTEM_PATTERNS = [
  /\bfs\./, /\bfsPromises\./, /\bFile\.(read|write|create)/, /\baccessSync\b/, /\breadFileSync\b/,
  /\bwriteFileSync\b/, /\bcreateReadStream\b/, /\bcreateWriteStream\b/, /\bunlinkSync\b/,
  /\brmdirSync\b/, /\bmkdirSync\b/, /\bcopyFileSync\b/, /\brenameSync\b/, /\bchmodSync\b/,
  /\bchownSync\b/, /\bstatSync\b/, /\blstatSync\b/, /\bfstatSync\b/, /\bexistsSync\b/,
  /\brealpathSync\b/, /\bfilesystem\b/, /\bDirectory\b/, /\bPath\.(getFileName|getDirectoryName)\b/,
  /\bFile\.(Read|Write|Append)/, /\bos\.(open|read|write|close)\b/,
  /\bstd::fs\b/, /\bimport\s+.*fs/, /\bimport\s+.*path/,
]

const NETWORK_PATTERNS = [
  /\bfetch\s*\(/, /\baxios\b/, /\bhttp\.(get|post|request)\b/, /\bhttps\.(get|post|request)\b/,
  /\bnet\.(connect|createConnection)\b/, /\bdgram\.(createSocket|send)\b/,
  /\bXMLHttpRequest\b/, /\bsocket\.(emit|on)\b/, /\bws\b/, /\bWebSocket\b/,
  /\brequest\s*\(/, /\bgRPC\b/, /\bsocket\.io\b/, /\bnode-fetch\b/, /\bgot\b/,
  /\bsuperagent\b/, /\bneedle\b/, /\bunirest\b/, /\bcurl\b/,
  /\bHttpClient\b/, /\bRestTemplate\b/, /\bWebClient\b/,
  /\brequests\.(get|post|put|delete)\b/, /\bhttpx\b/, /\baiohttp\b/,
  /\bnet\.http\b/, /\bhttp\.Client\b/, /\bioutil\b/,
  /\bcurl_easy\b/, /\bstd::net\b/,
]

const SHELL_PATTERNS = [
  /\bexec\s*\(/, /\bspawn\s*\(/, /\bfork\s*\(/, /\bexecSync\b/, /\bspawnSync\b/,
  /\bexecFile\b/, /\bexecFileSync\b/, /\bchild_process\b/, /\brun\b\s*\(/,
  /\bsubprocess\b/, /\bPopen\b/, /\bcheck_call\b/, /\bcheck_output\b/,
  /\bsystem\s*\(/, /\bShellExecute\b/, /\bCreateProcess\b/, /\bcmd\.(exec|run|start)\b/,
  /\bos\.system\b/, /\bos\.popen\b/, /\bsubprocess\.(call|run|Popen)\b/,
  /\bstd::process::Command\b/, /\bRuntime\.getRuntime\(\)\.exec\b/,
  /\bProcessBuilder\b/, /\bexecve\b/, /\bshell_exec\b/,
  /\b`[^`]*\$\{[^}]+\}[^`]*`/, /\b`[^`]*\$\([^)]+\)[^`]*`/,
]

const DYNAMIC_CODE_PATTERNS = [
  /\beval\s*\(/, /\bFunction\s*\(/, /\bsetTimeout\s*\(/, /\bsetInterval\s*\(/, /\bnew Function\b/,
  /\brequire\s*\(/, /\bimport\s*\(/, /\bdynamic\s+import\b/,
  /\bexecScript\b/, /\bcompileScript\b/, /\brunScript\b/,
  /\bScript\.(run|compile|eval)\b/, /\bsetImmediate\b/,
  /\bvm\.(runInThisContext|runInNewContext|compileFunction)\b/,
  /\bbuiltins\.exec\b/, /\b__import__\b/,
  /\beval\(/,
  /\breflection\b/, /\bMethod\.(invoke|newInstance)\b/, /\bClass\.(forName|newInstance)\b/,
  /\bunsafe\b/, /\bpointer\b/,
  /\bmacro\s*!/, /\bcompile!\b/, /\bcpp!\b/,
]

const DATABASE_PATTERNS = [
  /\bdb\./, /\bquery\s*\(/, /\bexecute\s*\(/, /\bsql\b/,
  /\bSELECT\b/, /\bINSERT\b/, /\bUPDATE\b/, /\bDELETE\b/, /\bCREATE TABLE\b/,
  /\bALTER TABLE\b/, /\bDROP TABLE\b/, /\bWHERE\b/i,
  /\bfind\s*\(/, /\bfindOne\s*\(/, /\bfindById\s*\(/, /\binsertOne\b/, /\binsertMany\b/,
  /\bupdateOne\b/, /\bupdateMany\b/, /\bdeleteOne\b/, /\bdeleteMany\b/,
  /\baggregate\b/, /\b$match\b/, /\b$group\b/,
  /\bfrom\s+['"][^'"]*['"]\s*,\b/,
  /\bconnection\.(query|execute)\b/, /\bpool\.query\b/,
  /\bsequelize\b/, /\btypeorm\b/, /\bprisma\b/, /\bdrizzle\b/,
  /\bmongodb\b/, /\bmongoose\b/, /\bredis\b/,
  /\bsqlite3\b/, /\bbetter-sqlite3\b/,
  /\bpg\b/, /\bmysql2\b/, /\bmariadb\b/,
  /\bimport\s+.*sql/, /\bfrom\s+['"].*sql/,
  /\bfirestore\b/, /\brealtime database\b/,
  /\bContext\.(exec|query)/, /\bdatabase\.sql\b/,
]

const CRYPTO_PATTERNS = [
  /\bcrypto\b/, /\bjwt\b/, /\bbcyrpt\b/, /\bbscrypt\b/, /\bargon2\b/,
  /\bencrypt\b/, /\bdecrypt\b/, /\bcipher\b/, /\bdecipher\b/,
  /\bhash\b/, /\bdigest\b/, /\bHMAC\b/, /\bPBKDF2\b/, /\bscrypt\b/,
  /\bCryptoJS\b/, /\bnode:crypto\b/, /\bcreateHash\b/, /\bcreateCipher\b/,
  /\bcreateDecipher\b/, /\bcreateHmac\b/, /\brandomBytes\b/,
  /\bgenerateKeyPair\b/, /\bsign\b/, /\bverify\b/,
  /\bAES\b/, /\bRSA\b/, /\bECC\b/, /\bDSA\b/, /\bECDSA\b/, /\bEd25519\b/,
  /\bTLS\b/, /\bSSL\b/, /\bCertificate\b/, /\bX509\b/,
  /\bopenssl\b/, /\bOpenSSL\b/,
  /\bKeyPair\b/, /\bPrivateKey\b/, /\bPublicKey\b/,
  /\bcrypto\.(createHash|createHmac|randomBytes|createCipher|createDecipher)/,
  /\bhkdf\b/, /\bpassword_hash\b/, /\bpassword_verify\b/,
  /\bcrypt\.hash\b/, /\bcrypt\.compare\b/,
  /\bbn\.js\b/, /\btweetnacl\b/, /\blibsodium\b/,
]

function countCodeLines(patch: string): string[] {
  return patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('++')).map(l => l.slice(1))
}

export function analyzeCapabilities(files: PRFile[]): CapabilityIntel | undefined {
  const filesystem: string[] = []
  const network: string[] = []
  const shell: string[] = []
  const dynamicCode: string[] = []
  const database: string[] = []
  const crypto: string[] = []

  for (const file of files) {
    const codeLines = countCodeLines(file.patch || '')
    for (const line of codeLines) {
      if (FILESYSTEM_PATTERNS.some(p => p.test(line))) filesystem.push(file.filename)
      if (NETWORK_PATTERNS.some(p => p.test(line))) network.push(file.filename)
      if (SHELL_PATTERNS.some(p => p.test(line))) shell.push(file.filename)
      if (DYNAMIC_CODE_PATTERNS.some(p => p.test(line))) dynamicCode.push(file.filename)
      if (DATABASE_PATTERNS.some(p => p.test(line))) database.push(file.filename)
      if (CRYPTO_PATTERNS.some(p => p.test(line))) crypto.push(file.filename)
    }
  }

  const unique = (arr: string[]) => [...new Set(arr)]
  const hasAny = filesystem.length > 0 || network.length > 0 || shell.length > 0 ||
    dynamicCode.length > 0 || database.length > 0 || crypto.length > 0

  if (!hasAny) return undefined

  let risk: IntelRisk = 'low'
  if (shell.length > 0) risk = 'critical'
  else if (filesystem.length > 0 && network.length > 0) risk = 'high'
  else if (network.length > 0 || filesystem.length > 0) risk = 'medium'

  return {
    summary: `FS:${filesystem.length > 0 ? 'Yes' : 'No'} Net:${network.length > 0 ? 'Yes' : 'No'} Shell:${shell.length > 0 ? 'Yes' : 'No'} Code:${dynamicCode.length > 0 ? 'Yes' : 'No'} DB:${database.length > 0 ? 'Yes' : 'No'} Crypto:${crypto.length > 0 ? 'Yes' : 'No'}`,
    filesystem: unique(filesystem),
    network: unique(network),
    shell: unique(shell),
    dynamicCode: unique(dynamicCode),
    database: unique(database),
    crypto: unique(crypto),
    risk,
  }
}
