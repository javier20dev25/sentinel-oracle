/**
 * Tone/Mood system for AI responses.
 * Includes a terminal modal selector (arrow keys + Enter).
 */
export interface Tone {
    id: string;
    label: string;
    description: string;
    systemInstruction: string;
}
export declare const TONES: Tone[];
export declare function getCurrentTone(): Tone;
export declare function setTone(id: string): boolean;
export declare function getToneSystemPrompt(): string;
/**
 * Renders an interactive selector in the terminal.
 * Arrow keys to move, Enter to select, Esc to cancel.
 * Returns the selected tone id, or null if cancelled.
 */
export declare function selectToneModal(): Promise<string | null>;
