/**
 * Sentinel Integrity Manager (v1.0)
 *
 * Ensures the CLI and its environment are not tampered with.
 * Levels: TRUSTED | SUSPECT | COMPROMISED
 */
import { IntegrityChain } from './integrity_chain.js';
export type IntegrityLevel = 'TRUSTED' | 'SUSPECT' | 'COMPROMISED';
export declare class IntegrityManager {
    private cliRoot;
    private vaultPath;
    private chain;
    constructor();
    calculateRulesHash(): string;
    getChain(): IntegrityChain;
    /**
     * Performs a full system integrity audit.
     */
    checkIntegrity(): Promise<{
        level: IntegrityLevel;
        reasons: string[];
    }>;
    private verifySignedManifest;
    report(level: IntegrityLevel, reasons: string[], showChain?: boolean): void;
    reportChain(): void;
}
