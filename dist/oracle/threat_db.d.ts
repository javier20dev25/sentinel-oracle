export interface ThreatRecord {
    id?: number;
    type: 'pr' | 'package' | 'author' | 'pattern';
    source: string;
    author?: string;
    authorEmail?: string;
    title?: string;
    severity?: string;
    findings?: string;
    signature?: string;
    diffHash?: string;
    notes?: string;
    detected_at?: string;
}
export declare function addThreat(t: ThreatRecord): number;
export declare function getThreatsByAuthor(author: string): ThreatRecord[];
export declare function getThreatsBySignature(sig: string): ThreatRecord[];
export declare function getRecentThreats(limit?: number): ThreatRecord[];
export interface ThreatAuthor {
    author: string;
    email?: string;
    first_seen: string;
    last_seen: string;
    threat_count: number;
    patterns: string;
    risk_level: string;
    repos: string;
}
export declare function getThreatAuthor(author: string): ThreatAuthor | null;
export declare function getHighRiskAuthors(): ThreatAuthor[];
export declare function setAuthorRiskLevel(author: string, level: string): void;
export declare function addThreatPattern(pattern: string, description: string, severity?: string): void;
export declare function getThreatPatterns(severity?: string): any[];
export interface CorrelationResult {
    threatCount: number;
    knownAuthor: boolean;
    authorThreats: ThreatRecord[];
    authorRiskLevel: string;
    patternMatches: any[];
}
export declare function correlateFindings(author?: string, findings?: string, diffHash?: string): CorrelationResult;
export declare function closeDb(): void;
