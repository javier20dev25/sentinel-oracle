/**
 * Sentinel Lite Engine (v2.0)
 *
 * "Intentionally Degraded" version of the Oracle Engine for CLI distribution.
 * Provides high-utility local scanning while protecting proprietary Reasoning IP.
 *
 * v2.0 adds SECRET_DETECTION rules for credential exfiltration.
 */
import { ScanSignal } from '../../cli/intelligence/signal_vault';
export interface LiteFinding {
    type: string;
    intent: string;
    file: string;
    line: number;
    severity: string;
    description: string;
    snippet: string;
}
export declare class LiteScanner {
    private vault;
    constructor();
    /**
     * Performs a local scan of a file patch.
     * Uses the same deterministic SAST rules as the Pro version.
     */
    scanPatch(filename: string, patch: string): LiteFinding[];
    /**
     * Orchestrates the local scan, persists signals to the Vault,
     * and performs basic temporal correlation.
     */
    auditPR(repo: string, pr: number, author: string, files: {
        filename: string;
        patch: string;
    }[]): Promise<{
        scanId: string;
        findings: LiteFinding[];
        correlations: ScanSignal[];
        verdict: {
            band: string;
            decision: string;
            correlationCount: number;
        };
        cta: string | null;
    }>;
}
