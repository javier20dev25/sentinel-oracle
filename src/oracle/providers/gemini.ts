import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

function toGeminiTools(tools?: ToolDef[]) {
  if (!tools || tools.length === 0) return undefined;
  return tools.map(t => ({
    functionDeclarations: [{
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    }],
  }));
}

function toRole(role: string): string {
  if (role === 'assistant') return 'model';
  if (role === 'tool') return 'function';
  return 'user';
}

function extractToolCalls(parts: any[]): ToolCall[] | undefined {
  const calls: ToolCall[] = [];
  for (const p of parts) {
    if (p.functionCall) {
      calls.push({
        id: p.functionCall.name,
        name: p.functionCall.name,
        arguments: (() => {
          try {
            const obj: Record<string, string> = {};
            if (p.functionCall.args) {
              for (const [k, v] of Object.entries(p.functionCall.args)) {
                obj[k] = String(v);
              }
            }
            return obj;
          } catch { return {}; }
        })(),
      });
    }
  }
  return calls.length > 0 ? calls : undefined;
}

export class GeminiProvider extends BaseProvider {
  private client: GoogleGenerativeAI;
  private modelInst: GenerativeModel;

  constructor(apiKey: string, model = 'gemini-2.0-flash') {
    super('gemini', model, apiKey);
    this.client = new GoogleGenerativeAI(apiKey);
    this.modelInst = this.client.getGenerativeModel({ model });
  }

  async chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse> {
    const history = messages.slice(0, -1).map(m => ({
      role: toRole(m.role),
      parts: [{ text: m.content }],
    }));
    const lastMsg = messages[messages.length - 1];

    const chat = this.modelInst.startChat({
      history,
      tools: toGeminiTools(tools) as any,
    });

    const result = await chat.sendMessage(lastMsg.content);
    const response = result.response;
    const parts = response.candidates?.[0]?.content?.parts || [];

    const toolCalls = extractToolCalls(parts);
    if (toolCalls) {
      return { content: '', toolCalls };
    }

    return { content: response.text() };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    const history = messages.slice(0, -1).map(m => ({
      role: toRole(m.role),
      parts: [{ text: m.content }],
    }));
    const lastMsg = messages[messages.length - 1];

    const chat = this.modelInst.startChat({
      history,
      tools: toGeminiTools(tools) as any,
    });

    const result = await chat.sendMessageStream(lastMsg.content);

    for await (const chunk of result.stream) {
      const textChunk = chunk.text();
      if (textChunk) {
        yield { content: textChunk, done: false };
      }
    }

    const response = await result.response;
    const parts = response.candidates?.[0]?.content?.parts || [];

    const toolCalls = extractToolCalls(parts);
    if (toolCalls) {
      yield { toolCalls, done: true };
      return;
    }

    yield { done: true };
  }
}
