export interface WizardResult {
    provider: string;
    apiKey: string;
}
export declare function providerWizard(): Promise<WizardResult | null>;
