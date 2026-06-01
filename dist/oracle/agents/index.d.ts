/**
 * Agent definitions — Blue Team, Red Team, Auditor, Default.
 * Each agent modifies the system prompt and tool preferences.
 */
export interface Agent {
    id: string;
    name: string;
    icon: string;
    description: string;
    systemPromptAddendum: string;
}
export declare const AGENTS: Agent[];
export declare function getCurrentAgent(): Agent;
export declare function setAgent(id: string): boolean;
export declare function getAgentSystemPrompt(): string;
