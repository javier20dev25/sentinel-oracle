import Anthropic from '@anthropic-ai/sdk';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

function toClaudeTools(tools?: ToolDef[]) {
  if (!tools || tools.length === 0) return undefined;
  return tools.map(t => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters,
  }));
}

export class ClaudeProvider extends BaseProvider {
  private client: Anthropic;

  constructor(apiKey: string, model = 'claude-sonnet-4-20250514') {
    super('claude', model, apiKey);
    this.client = new Anthropic({ apiKey });
  }

  async chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse> {
    const systemMsg = messages.find(m => m.role === 'system');
    const chatMessages = messages
      .filter(m => m.role !== 'system')
      .map(m => {
        if (m.role === 'tool') {
          return {
            role: 'user' as const,
            content: [{ type: 'tool_result' as const, tool_use_id: m.tool_call_id || '', content: m.content }],
          };
        }
        return { role: m.role as 'user' | 'assistant', content: m.content };
      });

    const msg = await this.client.messages.create({
      model: this.model,
      max_tokens: 4096,
      system: systemMsg?.content || undefined,
      messages: chatMessages as any,
      tools: toClaudeTools(tools) as any,
    });

    const toolCalls: ToolCall[] = [];
    let text = '';

    for (const block of msg.content) {
      if (block.type === 'text') {
        text += block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id,
          name: block.name,
          arguments: block.input as Record<string, string>,
        });
      }
    }

    if (toolCalls.length > 0) {
      return { content: text, toolCalls };
    }

    return { content: text };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    const systemMsg = messages.find(m => m.role === 'system');
    const chatMessages = messages
      .filter(m => m.role !== 'system')
      .map(m => {
        if (m.role === 'tool') {
          return {
            role: 'user' as const,
            content: [{ type: 'tool_result' as const, tool_use_id: m.tool_call_id || '', content: m.content }],
          };
        }
        return { role: m.role as 'user' | 'assistant', content: m.content };
      });

    const stream = await this.client.messages.create({
      model: this.model,
      max_tokens: 4096,
      system: systemMsg?.content || undefined,
      messages: chatMessages as any,
      tools: toClaudeTools(tools) as any,
      stream: true,
    });

    const toolCallAccum: Record<string, { id: string; name: string; input: string }> = {};

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
        yield { content: event.delta.text, done: false };
      }
      if (event.type === 'content_block_start' && event.content_block?.type === 'tool_use') {
        const idx = event.index ?? 0;
        toolCallAccum[idx] = {
          id: event.content_block.id,
          name: event.content_block.name,
          input: '',
        };
      }
      if (event.type === 'content_block_delta' && event.delta?.type === 'input_json_delta') {
        const idx = event.index ?? 0;
        if (toolCallAccum[idx]) {
          toolCallAccum[idx].input += event.delta.partial_json || '';
        }
      }
    }

    const toolCalls = Object.values(toolCallAccum).map(tc => ({
      id: tc.id,
      name: tc.name,
      arguments: (() => { try { return JSON.parse(tc.input); } catch { return {}; } })(),
    }));

    if (toolCalls.length > 0) {
      yield { toolCalls, done: true };
    } else {
      yield { done: true };
    }
  }
}
