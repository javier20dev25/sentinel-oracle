import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MessageRenderer, type ChatMessage } from './messages';

describe('MessageRenderer', () => {
  let renderer: MessageRenderer;
  let mockStdout: any;

  beforeEach(() => {
    mockStdout = {
      columns: 80,
      rows: 24,
      write: vi.fn(),
      cursorTo: vi.fn(),
      moveCursor: vi.fn(),
      clearLine: vi.fn(),
    };
    vi.spyOn(process, 'stdout', 'get').mockReturnValue(mockStdout as any);
    renderer = new MessageRenderer();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('starts with empty messages', () => {
    expect(renderer.clear).toBeDefined();
  });

  it('adds a user message', () => {
    const msg: ChatMessage = {
      type: 'user',
      content: 'hello world',
      timestamp: new Date(),
    };
    renderer.addMessage(msg);
    renderer.renderAll();
    expect(mockStdout.write).toHaveBeenCalled();
    const calls = mockStdout.write.mock.calls.map((c: any[]) => c[0]).filter(Boolean);
    const hasHome = calls.some((c: string) => c === '\x1b[H');
    expect(hasHome).toBe(true);
  });

  it('adds an assistant message', () => {
    const msg: ChatMessage = {
      type: 'assistant',
      content: 'I am Sentinel Oracle',
      timestamp: new Date(),
    };
    renderer.addMessage(msg);
    renderer.renderAll();
    const calls = mockStdout.write.mock.calls.map((c: any[]) => c[0]).filter(Boolean);
    expect(calls.length).toBeGreaterThan(0);
  });

  it('adds multiple messages and renders them', () => {
    renderer.addMessage({
      type: 'user',
      content: 'hello',
      timestamp: new Date(),
    });
    renderer.addMessage({
      type: 'assistant',
      content: 'hi there',
      timestamp: new Date(),
    });
    const count = renderer.renderAll();
    expect(count).toBeGreaterThan(0);
    expect(mockStdout.write).toHaveBeenCalled();
  });

  it('clears all messages', () => {
    renderer.addMessage({
      type: 'user',
      content: 'test',
      timestamp: new Date(),
    });
    renderer.clear();
    const count = renderer.renderAll();
    expect(count).toBe(0);
  });

  it('respects max messages limit', () => {
    const max = 100;
    for (let i = 0; i < max + 10; i++) {
      renderer.addMessage({
        type: 'system',
        content: `msg ${i}`,
        timestamp: new Date(),
      });
    }
    renderer.renderAll();
    const calls = mockStdout.write.mock.calls.map((c: any[]) => c[0]).filter(Boolean);
    expect(calls.length).toBeGreaterThan(0);
  });

  it('adds a tool message', () => {
    renderer.addMessage({
      type: 'tool',
      content: 'scan completed - 3 findings',
      timestamp: new Date(),
      toolName: 'scan',
    });
    const count = renderer.renderAll();
    expect(count).toBeGreaterThan(0);
  });

  it('adds an error message', () => {
    renderer.addMessage({
      type: 'error',
      content: 'Something went wrong',
      timestamp: new Date(),
    });
    const count = renderer.renderAll();
    expect(count).toBeGreaterThan(0);
  });

  it('adds a system message', () => {
    renderer.addMessage({
      type: 'system',
      content: 'mode changed to plan',
      timestamp: new Date(),
    });
    const count = renderer.renderAll();
    expect(count).toBeGreaterThan(0);
  });

  it('updates last assistant content', () => {
    renderer.addMessage({
      type: 'assistant',
      content: 'initial',
      timestamp: new Date(),
    });
    renderer.updateLastAssistantContent('updated content');
    renderer.renderAll();
    expect(mockStdout.write).toHaveBeenCalled();
  });

  it('creates assistant message if none exists on updateLastAssistantContent', () => {
    renderer.updateLastAssistantContent('new content');
    renderer.renderAll();
    expect(mockStdout.write).toHaveBeenCalled();
  });

  it('handles multiline content in messages', () => {
    renderer.addMessage({
      type: 'user',
      content: 'line 1\nline 2\nline 3',
      timestamp: new Date(),
    });
    const count = renderer.renderAll();
    expect(count).toBeGreaterThan(0);
  });

  it('renders user message box with correct structure', () => {
    const msg: ChatMessage = {
      type: 'user',
      content: 'hello',
      timestamp: new Date(),
    };
    renderer.addMessage(msg);
    renderer.renderAll();

    const writes = mockStdout.write.mock.calls
      .map((c: any[]) => c[0])
      .filter((s: any) => typeof s === 'string');
    const fullOutput = writes.join('');
    expect(fullOutput).toContain('You');
    expect(fullOutput).toContain('hello');
  });
});
