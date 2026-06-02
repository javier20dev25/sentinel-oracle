export declare const BORDERS: {
    header: {
        tl: string;
        tr: string;
        bl: string;
        br: string;
        h: string;
        v: string;
    };
    box: {
        tl: string;
        tr: string;
        bl: string;
        br: string;
        h: string;
        v: string;
    };
    chat: {
        tl: string;
        tr: string;
        bl: string;
        br: string;
        h: string;
        v: string;
    };
};
export declare const COLORS: {
    accent: import("picocolors/types.js").Formatter;
    accentDim: import("picocolors/types.js").Formatter;
    surface: import("picocolors/types.js").Formatter;
    surface2: import("picocolors/types.js").Formatter;
    text: import("picocolors/types.js").Formatter;
    textDim: import("picocolors/types.js").Formatter;
    user: import("picocolors/types.js").Formatter;
    assistant: import("picocolors/types.js").Formatter;
    tool: import("picocolors/types.js").Formatter;
    error: import("picocolors/types.js").Formatter;
    success: import("picocolors/types.js").Formatter;
    warning: import("picocolors/types.js").Formatter;
    info: import("picocolors/types.js").Formatter;
};
export declare const SPACING: {
    padX: number;
    padY: number;
    contentWidth: number;
};
export declare function dim(text: string): string;
export declare function accent(text: string): string;
export declare function success(text: string): string;
export declare function error(text: string): string;
export declare function warning(text: string): string;
export declare function info(text: string): string;
export declare function userColor(text: string): string;
export declare function assistantColor(text: string): string;
export declare function toolColor(text: string): string;
export declare function muted(text: string): string;
export declare function borderBox(width: number, title?: string): {
    top: string;
    bottom: string;
};
export declare function divider(char?: string, width?: number): string;
export declare function pad(text: string, width?: number): string;
