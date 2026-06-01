interface Rule {
    name: string;
    instruction: string;
    enabled: boolean;
    createdAt: string;
}
export declare function addRule(name: string, instruction: string): void;
export declare function removeRule(name: string): boolean;
export declare function toggleRule(name: string, enabled: boolean): boolean;
export declare function listRules(): Rule[];
export declare function getActiveRulesText(): string;
export declare function getDefaultRules(): Rule[];
export declare function ensureDefaultRules(): void;
export {};
