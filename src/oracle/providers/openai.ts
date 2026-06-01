import OpenAI from 'openai';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base';

function toOpenAITools(tools?: ToolDef[]) {
  if (!tools || tools.length === 0) return undefined;
  return tools.map(t => ({
    type: 'function' as const,
    function: {
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    },
  }));
}

export class OpenAIProvider extends BaseProvider {
  protected client: OpenAI;

  constructor(apiKey: string, model = 'gpt-4o', baseURL?: string) {
    super('openai', model, apiKey);
    this.client = new OpenAI({ apiKey, baseURL });
  }

  async chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: messages as any,
      max_tokens: 4096,
      tools: toOpenAITools(tools),
    });

    const choice = response.choices[0];
    const msg = choice?.message;
    if (!msg) return { content: '' };

    if (msg.tool_calls && msg.tool_calls.length > 0) {
      const toolCalls: ToolCall[] = msg.tool_calls.map(tc => {
        const fn = (tc as any).function || { name: '', arguments: '{}' };
        return {
          id: tc.id,
          name: fn.name,
          arguments: (() => {
            try { return JSON.parse(fn.arguments); } catch { return {}; }
          })(),
        };
      });
      return { content: msg.content || '', toolCalls };
    }

    return { content: msg.content || '' };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    const stream = await this.client.chat.completions.create({
      model: this.model,
      messages: messages as any,
      max_tokens: 4096,
      tools: toOpenAITools(tools),
      stream: true,
    });

    const toolCallAccum: Record<number, { id: string; name: string; args: string }> = {};

    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta;
      if (!delta) continue;

      if (delta.content) {
        yield { content: delta.content, done: false };
      }

      if (delta.tool_calls) {
        for (const tc of delta.tool_calls) {
          const index = tc.index;
          if (!toolCallAccum[index]) {
            toolCallAccum[index] = { id: tc.id || '', name: tc.function?.name || '', args: '' };
          }
          if (tc.id) toolCallAccum[index].id = tc.id;
          if (tc.function?.name) toolCallAccum[index].name += tc.function.name;
          if (tc.function?.arguments) toolCallAccum[index].args += tc.function.arguments;
        }
      }
    }

    const toolCalls = Object.values(toolCallAccum).map(tc => ({
      id: tc.id,
      name: tc.name,
      arguments: (() => { try { return JSON.parse(tc.args); } catch { return {}; } })(),
    }));

    if (toolCalls.length > 0) {
      yield { toolCalls, done: true };
    } else {
      yield { done: true };
    }
  }
}
