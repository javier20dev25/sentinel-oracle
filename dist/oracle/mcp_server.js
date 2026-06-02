import * as readline from 'readline';
import * as http from 'http';
import { runTool } from './tools.js';
import { correlateFindings, getThreatsByAuthor } from './threat_db.js';
const toolDefs = [
    {
        name: 'scan',
        description: 'Scan a directory or file for security threats using LiteScanner (30 SAST rules including secrets, eval, network, env access)',
        inputSchema: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'File or directory path to scan (default: current dir)' },
            },
            required: [],
        },
    },
    {
        name: 'verify-pkg',
        description: 'Audit an npm package via npm pack (zero-install) — detects typosquatting, secret leaks, hardcoded credentials, and supply chain threats in the tarball',
        inputSchema: {
            type: 'object',
            properties: {
                package: { type: 'string', description: 'npm package name to audit (e.g. axios, lodash)' },
            },
            required: ['package'],
        },
    },
    {
        name: 'doctor',
        description: 'System health check for npm dependencies in a project — scans for known vulnerabilities, capability risks, and outdated packages',
        inputSchema: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Project path to scan (default: current dir)' },
                deep: { type: 'string', enum: ['--deep', ''], description: 'Pass --deep for full dependency tree scan' },
            },
            required: [],
        },
    },
    {
        name: 'check-classified',
        description: 'Check staged files in a git repo against the classified documents database. Blocks commits when classified files are staged.',
        inputSchema: {
            type: 'object',
            properties: {
                path: { type: 'string', description: 'Git repository path (default: current dir)' },
            },
            required: [],
        },
    },
    {
        name: 'integrity',
        description: 'Verify Sentinel host integrity — checks code hash, PATH poisoning, vault integrity, clock anomalies, signed manifest, and persistent integrity chain',
        inputSchema: {
            type: 'object',
            properties: {},
            required: [],
        },
    },
    {
        name: 'memory',
        description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history',
        inputSchema: {
            type: 'object',
            properties: {
                action: { type: 'string', description: 'Action like --findings, --sessions, --threats' },
                query: { type: 'string', description: 'Optional search term' },
            },
            required: [],
        },
    },
    {
        name: 'threat-query',
        description: 'Query the threat intelligence database by author name — returns all known threats associated with that author',
        inputSchema: {
            type: 'object',
            properties: {
                author: { type: 'string', description: 'Author name to query' },
            },
            required: ['author'],
        },
    },
    {
        name: 'threat-correlate',
        description: 'Correlate findings with the threat database — checks author reputation, diff hash matches, and known threat patterns',
        inputSchema: {
            type: 'object',
            properties: {
                author: { type: 'string', description: 'Author name to correlate' },
                findings: { type: 'string', description: 'Findings text to match against known patterns' },
                diffHash: { type: 'string', description: 'Diff hash to check for previous sightings' },
            },
            required: [],
        },
    },
    {
        name: 'gh-pr-list',
        description: 'List open pull requests in the current GitHub repository. Returns PR number, title, author, and status.',
        inputSchema: {
            type: 'object',
            properties: {
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
                limit: { type: 'string', description: 'Max PRs to return (default: 10)' },
                state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state filter' },
            },
            required: [],
        },
    },
    {
        name: 'gh-pr-view',
        description: 'View detailed information about a specific pull request: diff stats, changed files, labels, reviewers, and CI status.',
        inputSchema: {
            type: 'object',
            properties: {
                number: { type: 'string', description: 'PR number to view' },
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
            },
            required: ['number'],
        },
    },
    {
        name: 'gh-pr-diff',
        description: 'Get the full diff of a pull request. Returns the raw diff output which can be piped directly into sentinel scan for SAST analysis.',
        inputSchema: {
            type: 'object',
            properties: {
                number: { type: 'string', description: 'PR number to get diff from' },
                repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
            },
            required: ['number'],
        },
    },
    {
        name: 'gh-repo-list',
        description: 'List GitHub repositories for the authenticated user or organization. Shows name, visibility, and description.',
        inputSchema: {
            type: 'object',
            properties: {
                owner: { type: 'string', description: 'User or organization name (default: authenticated user)' },
                limit: { type: 'string', description: 'Max repos to return (default: 20)' },
            },
            required: [],
        },
    },
];
function handleMcpMessage(msg) {
    if (msg.id === undefined || msg.id === null) {
        return null;
    }
    switch (msg.method) {
        case 'list_tools': {
            return {
                jsonrpc: '2.0',
                id: msg.id,
                result: { tools: toolDefs },
            };
        }
        case 'call_tool': {
            const { name, arguments: args } = msg.params;
            const toolArgs = args || {};
            try {
                let text;
                switch (name) {
                    case 'threat-query': {
                        const threats = getThreatsByAuthor(toolArgs.author || '');
                        text = JSON.stringify(threats.length > 0 ? threats : { message: 'No threats found for this author', author: toolArgs.author }, null, 2);
                        break;
                    }
                    case 'threat-correlate': {
                        const corr = correlateFindings(toolArgs.author || undefined, toolArgs.findings || undefined, toolArgs.diffHash || undefined);
                        text = JSON.stringify(corr, null, 2);
                        break;
                    }
                    default: {
                        text = runTool(name, toolArgs);
                        break;
                    }
                }
                return {
                    jsonrpc: '2.0',
                    id: msg.id,
                    result: { content: [{ type: 'text', text }] },
                };
            }
            catch (e) {
                return {
                    jsonrpc: '2.0',
                    id: msg.id,
                    result: { content: [{ type: 'text', text: `Error: ${e.message}` }] },
                };
            }
        }
        default: {
            return {
                jsonrpc: '2.0',
                id: msg.id,
                error: { code: -32601, message: `Method not found: ${msg.method}` },
            };
        }
    }
}
export function startMcpServer(port = 3003) {
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => {
        var _a;
        const trimmed = line.trim();
        if (!trimmed)
            return;
        let msg;
        try {
            msg = JSON.parse(trimmed);
        }
        catch (e) {
            const errResp = {
                jsonrpc: '2.0',
                id: null,
                error: { code: -32700, message: `Parse error: ${e.message}` },
            };
            process.stdout.write(JSON.stringify(errResp) + '\n');
            return;
        }
        try {
            const response = handleMcpMessage(msg);
            if (response) {
                process.stdout.write(JSON.stringify(response) + '\n');
            }
        }
        catch (e) {
            const errResp = {
                jsonrpc: '2.0',
                id: (_a = msg.id) !== null && _a !== void 0 ? _a : null,
                error: { code: -32603, message: `Internal error: ${e.message}` },
            };
            process.stdout.write(JSON.stringify(errResp) + '\n');
        }
    });
    rl.on('close', () => {
        process.exit(0);
    });
    console.error(`MCP server running (stdio mode, port ${port})`);
    console.error('Connect any MCP client (Claude Desktop, Cursor, Cline) to this process.');
}
export function startMcpHttpServer(port = 3003) {
    const server = http.createServer((req, res) => {
        const { method, headers } = req;
        if (method === 'POST') {
            let body = '';
            req.on('data', (chunk) => { body += chunk.toString(); });
            req.on('end', () => {
                var _a;
                let msg;
                try {
                    msg = JSON.parse(body);
                }
                catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        jsonrpc: '2.0',
                        id: null,
                        error: { code: -32700, message: `Parse error: ${e.message}` },
                    }));
                    return;
                }
                try {
                    const response = handleMcpMessage(msg);
                    if (response) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(response));
                    }
                    else {
                        res.writeHead(204);
                        res.end();
                    }
                }
                catch (e) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        jsonrpc: '2.0',
                        id: (_a = msg.id) !== null && _a !== void 0 ? _a : null,
                        error: { code: -32603, message: `Internal error: ${e.message}` },
                    }));
                }
            });
        }
        else if (method === 'GET' && headers.accept === 'text/event-stream') {
            res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            });
            res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'connected', params: {} })}\n\n`);
        }
        else {
            res.writeHead(405, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Method not allowed' }));
        }
    });
    server.listen(port, () => {
        console.error(`MCP HTTP server listening on http://localhost:${port}`);
        console.error('Connect via SSE at http://localhost:' + port);
    });
}
