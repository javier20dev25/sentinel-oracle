/**
 * Report generation — Markdown and JSON output.
 * Used by /report command and automatically by the engine.
 */
export interface ReportData {
    title: string;
    date: string;
    provider?: string;
    model?: string;
    findings: ReportFinding[];
    summary: {
        totalFindings: number;
        severities: Record<string, number>;
        verdict: string;
    };
    conversation?: {
        role: string;
        content: string;
    }[];
}
export interface ReportFinding {
    type: string;
    severity: string;
    description: string;
    evidence: string;
    context?: string;
    remediation?: string;
}
export declare function generateMarkdown(data: ReportData): string;
export declare function generateJSON(data: ReportData): string;
export declare function saveReport(content: string, filename: string): string;
export declare function parseFindingsFromOutput(output: string, type: string): ReportFinding[];
