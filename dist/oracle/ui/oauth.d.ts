export interface OAuthTokens {
    accessToken: string;
    refreshToken?: string;
    expiresAt?: number;
    provider: string;
}
export interface ProviderOAuthConfig {
    clientId: string;
    authorizationUrl: string;
    tokenUrl: string;
    scopes: string[];
    redirectPort?: number;
}
export declare const PROVIDER_OAUTH_CONFIGS: Record<string, ProviderOAuthConfig>;
export declare function generatePKCE(): {
    verifier: string;
    challenge: string;
};
export declare function startLocalhostServer(port: number, redirectPath?: string): Promise<{
    code: string;
    state: string;
}>;
export declare function openBrowser(url: string): Promise<void>;
export declare function exchangeCodeForTokens(tokenUrl: string, clientId: string, code: string, codeVerifier: string, redirectUri: string): Promise<{
    accessToken: string;
    refreshToken?: string;
}>;
export declare function oauthLogin(provider: string, config?: ProviderOAuthConfig): Promise<string | null>;
export declare function storeTokenInKeychain(service: string, account: string, token: string): Promise<boolean>;
export declare function getTokenFromKeychain(service: string, account: string): Promise<string | null>;
export declare function removeTokenFromKeychain(service: string, account: string): Promise<boolean>;
export declare function encryptData(data: string, key: string): string;
export declare function decryptData(encrypted: string, key: string): string | null;
export declare function deviceCodeFlow(provider: string, config: ProviderOAuthConfig): Promise<string | null>;
