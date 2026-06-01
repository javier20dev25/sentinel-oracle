export interface ChainLink {
    id: number;
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    link_hash: string;
    started_at: string;
    accumulated_seconds: number;
    created_at: string;
    [key: string]: unknown;
}
export interface ChainStatus {
    status: 'INTACT' | 'BROKEN' | 'EMPTY';
    totalLinks: number;
    currentCodeHash: string;
    lastLink: ChainLink | null;
    accumulatedSeconds: number;
    sessionSeconds: number;
    chainStart: string;
    lastVerified: string;
}
export declare class IntegrityChain {
    private db;
    private cliRoot;
    private sessionId;
    private sessionStart;
    constructor();
    private initSchema;
    recordBoot(codeHash: string): {
        chainStatus: ChainStatus;
    };
    getStatus(): ChainStatus;
    private getLastLink;
    private getAllLinks;
    private getTotalLinks;
    private hashLink;
    private hashObject;
    formatDuration(totalSeconds: number): string;
}
