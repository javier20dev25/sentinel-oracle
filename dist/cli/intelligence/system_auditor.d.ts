/**
 * Sentinel System Auditor (v2.0)
 *
 * The 'doctor' command.
 * Scans local node_modules using real LiteScanner for actual threat detection.
 */
export declare class SystemAuditor {
    private scanner;
    constructor();
    runDoctor(deep?: boolean): Promise<void>;
    private reportResults;
}
