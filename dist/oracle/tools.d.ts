import { ToolDef } from './providers/base';
export interface Tool {
    name: string;
    description: string;
    parameters: ToolDef['parameters'];
    run: (args: Record<string, string>) => string;
}
export declare const tools: Tool[];
export declare function getToolDefs(): ToolDef[];
export declare function runTool(name: string, args: Record<string, string>): string;
