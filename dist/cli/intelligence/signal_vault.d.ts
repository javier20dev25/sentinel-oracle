/**
 * Sentinel Signal Vault (v1.0)
 *
 * Local persistence for security signals to enable temporal drift detection
 * and historical correlation without cloud dependency.
 */
export interface ScanSignal {
    repo: string;
    author: string;
    signal_type: string;
    weight: number;
    file_path: string;
    source_scan: string;
}
export declare class SignalVault {
    private db;
    constructor();
    private getDbPath;
    private initSchema;
    recordScan(scan: {
        id: string;
        repo: string;
        pr: number;
        author: string;
        score: number;
        band: string;
    }): void;
    recordSignal(signal: ScanSignal): void;
    getHistoricalSignals(author: string, daysLookback?: number): ScanSignal[];
    getCorrelations(author: string, currentSignals: string[]): ScanSignal[];
    purgeRepo(repoName: string): void;
    getStats(): {
        totalScans: number;
        totalSignals: number;
        totalFindings: number;
        repos: number;
        authors: number;
    };
    /**
     * Ingest a cloud audit report from Sentinel SaaS JSON format.
     * Returns the scan ID that was created.
     */
    ingestCloudReport(report: {
        id: string;
        repo_hash?: string;
        event_hash?: string;
        risk_score?: number;
        category?: string;
        pattern?: string;
        confidence?: number;
        metadata?: {
            github_repo_url?: string;
            pr_number?: number;
            filesScanned?: number;
            topAlerts?: Array<{
                type: string;
                _file: string;
                snippet: string;
                severity: string;
                riskLevel: number;
                description: string;
                line_number: number;
            }>;
            author?: {
                login: string;
            };
        };
        created_at?: string;
    }): string;
    /**
     * Threshold-based drift detection.
     * Returns repos that have accumulated enough signals to warrant attention.
     */
    /**
     * Returns signals grouped by repo+author+type for multi-author correlation.
     */
    getMultiAuthorSignals(): Array<{
        repo: string;
        author: string;
        signal_type: string;
    }>;
    getThresholdAnalysis(threshold?: number): Array<{
        repo: string;
        signalCount: number;
        uniqueTypes: string[];
        riskTrend: string;
        lastSignal: string;
    }>;
    /**
     * Get historical signals for a specific repo, ordered by time.
     * Useful for temporal drift charts.
     */
    getRepoSignalTimeline(repo: string, limit?: number): Array<{
        type: string;
        weight: number;
        file: string;
        date: string;
    }>;
    wipe(): void;
}
