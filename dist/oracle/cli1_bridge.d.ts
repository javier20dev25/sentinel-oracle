/**
 * CLI 1 bridge — coordinates with Sentinel CLI v1 data.
 * Reads config, classified DB, vault, and scan history from v1.
 */
interface Cli1Data {
    found: boolean;
    configPath: string;
    dataDir: string;
    config: Record<string, any>;
    classifiedCount: number;
    vaultDbPath: string;
    version?: string;
}
export declare function detectCli1(): Cli1Data;
export declare function importCli1Classified(): {
    imported: number;
    files: string[];
};
export declare function formatCli1Report(data: Cli1Data): string;
export {};
