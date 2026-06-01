export interface Message {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_call_id?: string;
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, string>;
}

export interface ChatResponse {
  content: string;
  toolCalls?: ToolCall[];
}

export interface ChatChunk {
  content?: string;
  toolCalls?: ToolCall[];
  done: boolean;
}

export interface ToolParameterProperty {
  type: string;
  description?: string;
  enum?: string[];
}

export interface ToolDef {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, ToolParameterProperty>;
    required?: string[];
  };
}

export abstract class BaseProvider {
  constructor(
    public readonly name: string,
    public readonly model: string,
    protected apiKey: string
  ) {}

  abstract chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>;
  abstract stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>;

  validateConfig(): boolean {
    return !!this.apiKey;
  }
}
