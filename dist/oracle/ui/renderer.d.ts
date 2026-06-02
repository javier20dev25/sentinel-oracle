export interface RenderOptions {
    provider?: string;
    onExit?: () => void;
}
export declare function startUI(options?: RenderOptions): {
    waitUntilExit: Promise<void>;
};
