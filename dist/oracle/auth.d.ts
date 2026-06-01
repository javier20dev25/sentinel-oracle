export declare function getApiKey(provider: string): string;
export declare function setApiKey(provider: string, key: string): void;
export declare function removeApiKey(provider: string): void;
export declare function listProviders(): string[];
export declare function getConfig(): {
    provider?: string;
    model?: string;
};
export declare function setConfig(provider: string, model?: string): void;
