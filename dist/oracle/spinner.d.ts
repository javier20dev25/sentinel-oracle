/**
 * Terminal spinner with different animation patterns.
 */
export type SpinnerType = 'thinking' | 'executing' | 'processing';
export declare class Spinner {
    private frame;
    private interval;
    private message;
    private running;
    private type;
    start(message: string, type?: SpinnerType): void;
    update(message: string, type?: SpinnerType): void;
    stop(): void;
    private color;
}
