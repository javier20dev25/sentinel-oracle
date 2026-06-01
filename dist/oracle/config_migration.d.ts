export interface ConfigExport {
    version: string;
    exportedAt: string;
    provider?: string;
    model?: string;
    tone: string;
    agent: string;
    rules: {
        name: string;
        instruction: string;
        enabled: boolean;
    }[];
    hasKeys: boolean;
}
export declare function exportConfig(): ConfigExport;
export declare function importConfig(config: ConfigExport): {
    success: boolean;
    warnings: string[];
};
export declare function exportConfigToFile(filePath?: string): string;
export declare function importConfigFromFile(filePath: string): {
    success: boolean;
    warnings: string[];
};
