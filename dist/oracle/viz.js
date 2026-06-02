/**
 * Visualization module — behavior maps, attack chains, severity charts
 * No emojis — pure ASCII/Unicode + terminal colors.
 */
import pc from 'picocolors';
// ─── Severity colors ──────────────────────────────────────────
export function sevColor(sev) {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL')
        return pc.red(sev);
    if (s === 'HIGH')
        return pc.yellow(sev);
    if (s === 'MEDIUM')
        return pc.cyan(sev);
    if (s === 'LOW')
        return pc.gray(sev);
    return sev;
}
export function sevColorFn(sev) {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL')
        return pc.red;
    if (s === 'HIGH')
        return pc.yellow;
    if (s === 'MEDIUM')
        return pc.cyan;
    if (s === 'LOW')
        return pc.gray;
    return (x) => x;
}
// ─── Attack Chain Visualizer ──────────────────────────────────
const CAPABILITY_TAGS = {
    UNSAFE_EVAL: '[EVAL]',
    OS_CAPABILITY: '[OS]',
    NETWORK_ACTIVITY: '[NET]',
    ENV_ACCESS: '[ENV]',
    POTENTIAL_SECRET: '[SEC]',
    DOM_INJECTION: '[DOM]',
    SANDBOX_ESCAPE: '[SBOX]',
    SECRET_AWS_KEY_ID: '[AWS]',
    SECRET_AWS_SECRET: '[AWS]',
    SECRET_GITHUB_TOKEN: '[GH]',
    SECRET_STRIPE_KEY: '[STR]',
    SECRET_SENDGRID_KEY: '[SG]',
    SECRET_SSH_KEY: '[SSH]',
    SECRET_SLACK_TOKEN: '[SLK]',
    SECRET_SLACK_WEBHOOK: '[WH]',
    SECRET_JWT: '[JWT]',
    SECRET_DB_PASSWORD: '[DB]',
    SECRET_ENCRYPTION_KEY: '[ENC]',
    SECRET_API_KEY: '[API]',
    DARKNET_ADDRESS: '[DARK]',
    SECRET_HARDCODED_PASSWORD: '[PWD]',
    SECRET_HARDCODED_TOKEN: '[TOK]',
    TYPOSQUAT_DEPENDENCY: '[TYPO]',
    PHANTOM_DEPENDENCY: '[PHNT]',
    EXFILTRATION_CHAIN: '[EXFIL]',
    RCE_CHAIN: '[RCE]',
    SUPPLY_CHAIN_EXECUTION: '[SC]',
};
export function capabilityTag(type) {
    return CAPABILITY_TAGS[type] || '[?]';
}
/**
 * Build an attack chain visualization.
 * Example:
 *   [ENV] ENV_ACCESS [CRITICAL] ──→ [NET] NETWORK_ACTIVITY [HIGH] ──→ [EXFIL] EXFILTRATION_CHAIN [CRITICAL]
 */
export function attackChain(nodes) {
    if (nodes.length === 0)
        return '';
    const parts = nodes.map(n => {
        const tag = capabilityTag(n.type);
        const sev = sevColor(n.severity);
        return `${tag} ${pc.bold(n.type)} [${sev}]`;
    });
    return parts.join(pc.gray(' ──→ '));
}
/**
 * Horizontal bar chart of capabilities sorted by count.
 * █ blocks represent relative frequency.
 */
export function capabilityBars(caps, maxWidth = 30) {
    if (caps.length === 0)
        return ['(no capabilities detected)'];
    const maxCount = Math.max(...caps.map(c => c.count), 1);
    return caps.map(c => {
        const barLen = Math.max(1, Math.round((c.count / maxCount) * maxWidth));
        const tag = capabilityTag(c.type);
        const bar = pc.gray('\u2588'.repeat(barLen));
        const sev = sevColor(c.severity);
        return `  ${tag} ${pc.bold(c.type.padEnd(25))} ${bar} ${pc.white(String(c.count))} [${sev}]`;
    });
}
// ─── Severity Distribution ────────────────────────────────────
export function severityPie(severities) {
    const total = Object.values(severities).reduce((a, b) => a + b, 0);
    if (total === 0)
        return ['(no findings)'];
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const lines = ['  Severity Distribution:'];
    for (const s of order) {
        const count = severities[s] || 0;
        if (count === 0)
            continue;
        const pct = ((count / total) * 100).toFixed(0);
        const barLen = Math.max(1, Math.round((count / total) * 20));
        const barFn = s === 'CRITICAL' ? pc.red : s === 'HIGH' ? pc.yellow : s === 'MEDIUM' ? pc.cyan : pc.gray;
        const bar = barFn('\u2588'.repeat(barLen));
        const sevDisplay = sevColorFn(s)(s);
        lines.push(`  ${sevDisplay}  ${bar} ${String(count).padStart(4)} (${pct}%)`);
    }
    return lines;
}
export function fileHeatmap(files, maxRows = 10) {
    if (files.length === 0)
        return ['(no files with findings)'];
    const sorted = [...files].sort((a, b) => b.count - a.count).slice(0, maxRows);
    const maxCount = Math.max(...sorted.map(f => f.count), 1);
    return sorted.map(f => {
        const barLen = Math.max(1, Math.round((f.count / maxCount) * 15));
        const sevFn = f.severity === 'CRITICAL' ? pc.red : f.severity === 'HIGH' ? pc.yellow : pc.gray;
        const bar = sevFn('\u2588'.repeat(barLen));
        const fileShort = f.file.length > 50 ? '...' + f.file.slice(-47) : f.file;
        return `  ${bar} ${pc.bold(String(f.count).padStart(3))} ${pc.gray(fileShort)}`;
    });
}
export function summaryBox(summary) {
    const width = 56;
    const line = pc.gray('\u2500'.repeat(width));
    const verdictStr = ` ${summary.verdict} `;
    const verdictColor = summary.verdict === 'MALICIOUS' ? pc.bgRed(verdictStr) :
        summary.verdict === 'SUSPICIOUS' ? pc.bgYellow(verdictStr) :
            pc.bgGreen(verdictStr);
    const lines = [
        '',
        pc.bold('  [ SCAN SUMMARY ]'),
        `  ${line}`,
        `  ${pc.bold('Verdict:')}      ${verdictColor}`,
        `  ${pc.bold('Findings:')}     ${pc.white(String(summary.totalFindings))}`,
    ];
    for (const [sev, count] of Object.entries(summary.severities)) {
        if (count > 0) {
            lines.push(`  ${pc.bold(sev.padEnd(14))} ${sevColorFn(sev)(String(count))}`);
        }
    }
    if (summary.topTypes.length > 0) {
        lines.push(`  ${pc.bold('Top types:')}    ${summary.topTypes.slice(0, 4).join(', ')}`);
    }
    if (summary.scanTimeMs)
        lines.push(`  ${pc.bold('Scan time:')}    ${summary.scanTimeMs}ms`);
    if (summary.memoryMB)
        lines.push(`  ${pc.bold('Memory:')}       ${summary.memoryMB.toFixed(1)} MB`);
    if (summary.filesScanned)
        lines.push(`  ${pc.bold('Files:')}       ${summary.filesScanned}`);
    lines.push(`  ${line}`, '');
    return lines.join('\n');
}
// ─── Welcome Banner ───────────────────────────────────────────
export function welcomeBanner(provider, model) {
    const banner = `
${pc.cyan('\u2554' + '\u2550'.repeat(52) + '\u2557')}
${pc.cyan('\u2551')}  ${pc.bold('[ Sentinel Oracle Core ]')} ${pc.gray('AI Security Assistant')}  ${pc.cyan('\u2551')}
${pc.cyan('\u2551')}  ${pc.gray('CLI 2  ·  Multi-Provider  ·  Tool-Orchestrated')}  ${pc.cyan('\u2551')}
${pc.cyan('\u255A' + '\u2550'.repeat(52) + '\u255D')}`;
    const info = provider
        ? `  ${pc.gray('Provider:')} ${pc.bold(provider)} ${pc.gray('| Model:')} ${pc.bold(model || 'default')}`
        : `  ${pc.yellow('[!] No provider configured. Run: sentinel oracle auth set <provider> <key>')}`;
    return `${banner}\n\n${info}`;
}
// ─── Tool Execution Card ──────────────────────────────────────
export function toolCard(name, params, status) {
    const icon = status === 'running' ? pc.cyan('\u27F3')
        : status === 'done' ? pc.green('\u2713')
            : status === 'error' ? pc.red('\u2717')
                : pc.yellow('\u2298');
    const statusText = status === 'running' ? pc.cyan('Running...')
        : status === 'done' ? pc.green('Done')
            : status === 'error' ? pc.red('Error')
                : pc.yellow('Denied');
    return `  ${icon} ${pc.bold(name)} ${pc.gray(params)} ${statusText}`;
}
// ─── Insight Callout ──────────────────────────────────────────
export function insight(type, title, body) {
    const labels = { tip: '[i]', warning: '[!]', danger: '[!!!]', info: '(i)' };
    const colors = { tip: pc.cyan, warning: pc.yellow, danger: pc.red, info: pc.gray };
    return [
        `  ${colors[type](labels[type])} ${colors[type](pc.bold(title))}`,
        `    ${colors[type](body)}`,
    ].join('\n');
}
// ─── Permission Banner ────────────────────────────────────────
export function permissionBannerText(toolName, params, mode) {
    const w = 56;
    const top = pc.cyan('\u250C' + '\u2500'.repeat(w) + '\u2510');
    const mid = pc.cyan('\u2502') + '  ' + pc.bold(toolName) + '  ' + pc.gray(params.length > 48 ? params.slice(0, 45) + '...' : params) + ' '.repeat(Math.max(1, w - 6 - toolName.length - Math.min(params.length, 48))) + pc.cyan('\u2502');
    const sep = pc.cyan('\u251C' + '\u2500'.repeat(w) + '\u2524');
    const keys = pc.cyan('\u2502') + '  ' + pc.green('Enter') + ' Allow    ' + pc.red('Esc') + ' Deny    ' + pc.cyan('A') + ' Auto-approve  '.padEnd(22) + pc.cyan('\u2502');
    const bot = pc.cyan('\u2514' + '\u2500'.repeat(w) + '\u2518');
    return ['', top, mid, sep, keys, bot, ''].join('\n');
}
// ─── Findings Box ────────────────────────────────────────────
export function findingsBox(title, lines, severity) {
    const w = 58;
    const sevColor = !severity ? pc.green
        : severity === 'CRITICAL' ? pc.red
            : severity === 'HIGH' ? pc.yellow
                : severity === 'MEDIUM' ? pc.cyan
                    : pc.gray;
    const top = sevColor('\u250C' + '\u2500'.repeat(w) + '\u2510');
    const header = sevColor('\u2502') + '  ' + pc.bold(title) + ' '.repeat(Math.max(1, w - 2 - title.length)) + sevColor('\u2502');
    const sep = sevColor('\u251C' + '\u2500'.repeat(w) + '\u2524');
    const contents = lines.slice(0, 20).map(l => {
        const display = l.length > w - 2 ? l.slice(0, w - 5) + '...' : l;
        return sevColor('\u2502') + ' ' + display + ' '.repeat(Math.max(1, w - 1 - display.length)) + sevColor('\u2502');
    });
    const bot = sevColor('\u2514' + '\u2500'.repeat(w) + '\u2518');
    return ['', top, header, sep, ...contents, bot, ''].join('\n');
}
// ─── Mode Indicator ──────────────────────────────────────────
export function modeBanner(mode) {
    const labels = {
        execute: 'Execute — AI runs tools, you approve each',
        plan: 'Plan — AI suggests tools, you decide',
        auto: 'Auto — AI runs everything without approval',
    };
    const modeColor = mode === 'execute' ? pc.green
        : mode === 'plan' ? pc.cyan
            : pc.yellow;
    return `  ${modeColor('\u25B8')} ${pc.bold(modeColor(`Mode: ${mode.toUpperCase()}`))}  ${pc.gray(labels[mode])}`;
}
