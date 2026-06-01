/**
 * Visualization module — behavior maps, attack chains, severity charts
 * No emojis — pure ASCII/Unicode + terminal colors.
 */
export declare function sevColor(sev: string): string;
export declare function sevColorFn(sev: string): (s: string) => string;
export declare function capabilityTag(type: string): string;
export interface ChainNode {
    type: string;
    severity: string;
    description: string;
}
/**
 * Build an attack chain visualization.
 * Example:
 *   [ENV] ENV_ACCESS [CRITICAL] ──→ [NET] NETWORK_ACTIVITY [HIGH] ──→ [EXFIL] EXFILTRATION_CHAIN [CRITICAL]
 */
export declare function attackChain(nodes: ChainNode[]): string;
export interface CapabilityCount {
    type: string;
    count: number;
    severity: string;
}
/**
 * Horizontal bar chart of capabilities sorted by count.
 * █ blocks represent relative frequency.
 */
export declare function capabilityBars(caps: CapabilityCount[], maxWidth?: number): string[];
export declare function severityPie(severities: Record<string, number>): string[];
export interface FileFinding {
    file: string;
    count: number;
    severity: string;
}
export declare function fileHeatmap(files: FileFinding[], maxRows?: number): string[];
export interface ReportSummary {
    verdict: string;
    totalFindings: number;
    severities: Record<string, number>;
    topTypes: string[];
    scanTimeMs?: number;
    memoryMB?: number;
    filesScanned?: number;
}
export declare function summaryBox(summary: ReportSummary): string;
export declare function welcomeBanner(provider?: string, model?: string): string;
export declare function toolCard(name: string, params: string, status: 'running' | 'done' | 'error' | 'denied'): string;
export declare function insight(type: 'tip' | 'warning' | 'danger' | 'info', title: string, body: string): string;
export declare function permissionBannerText(toolName: string, params: string, mode: 'execute' | 'plan'): string;
export declare function findingsBox(title: string, lines: string[], severity?: string): string;
export declare function modeBanner(mode: 'execute' | 'plan' | 'auto'): string;
