import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ChatInput } from './chat-input';

interface MockKeyEvent {
  name?: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
}

function makeKey(name: string, extra: Partial<MockKeyEvent> = {}): MockKeyEvent {
  return { name, ctrl: false, meta: false, shift: false, ...extra };
}

describe('ChatInput', () => {
  let onSubmit: ReturnType<typeof vi.fn>;
  let chatInput: ChatInput;
  let mockStdin: any;
  let mockStdout: any;

  beforeEach(() => {
    onSubmit = vi.fn();
    mockStdin = {
      isRaw: false,
      resume: vi.fn(),
      pause: vi.fn(),
      setRawMode: vi.fn(),
      on: vi.fn(),
      removeListener: vi.fn(),
      once: vi.fn(),
      listenerCount: vi.fn(() => 0),
    };
    mockStdout = {
      columns: 80,
      rows: 24,
      write: vi.fn(),
      cursorTo: vi.fn(),
      moveCursor: vi.fn(),
      clearLine: vi.fn(),
      on: vi.fn(),
      removeListener: vi.fn(),
    };
    chatInput = new ChatInput({
      onSubmit,
      stdin: mockStdin as any,
      stdout: mockStdout as any,
    });
  });

  afterEach(() => {
    chatInput.stop();
  });

  it('starts with empty input', () => {
    expect(chatInput.lines).toEqual(['']);
    expect(chatInput.cursorX).toBe(0);
    expect(chatInput.cursorY).toBe(0);
    expect(chatInput.getText()).toBe('');
  });

  it('inserts characters at cursor position', () => {
    chatInput.start();
    expect(mockStdin.setRawMode).toHaveBeenCalledWith(true);
    expect(mockStdin.resume).toHaveBeenCalled();
  });

  it('inserts a single character', () => {
    (chatInput as any).insertChar('a');
    expect(chatInput.lines).toEqual(['a']);
    expect(chatInput.cursorX).toBe(1);
    expect(chatInput.cursorY).toBe(0);
  });

  it('inserts multiple characters', () => {
    (chatInput as any).insertChar('h');
    (chatInput as any).insertChar('e');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('o');
    expect(chatInput.lines).toEqual(['hello']);
    expect(chatInput.cursorX).toBe(5);
    expect(chatInput.getText()).toBe('hello');
  });

  it('inserts character in the middle of a line', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveLeft();
    (chatInput as any).insertChar('b');
    expect(chatInput.lines).toEqual(['abc']);
    expect(chatInput.cursorX).toBe(2);
  });

  it('deletes character left of cursor with backspace', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).deleteChar();
    expect(chatInput.lines).toEqual(['ab']);
    expect(chatInput.cursorX).toBe(2);
  });

  it('does nothing on backspace at start of line', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).moveHome();
    (chatInput as any).deleteChar();
    expect(chatInput.lines).toEqual(['a']);
    expect(chatInput.cursorX).toBe(0);
  });

  it('supports multiline input with enter', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).newLine();
    expect(chatInput.lines).toEqual(['a', '']);
    expect(chatInput.cursorY).toBe(1);
    expect(chatInput.cursorX).toBe(0);
  });

  it('splits line at cursor on newline', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveLeft();
    (chatInput as any).newLine();
    expect(chatInput.lines).toEqual(['ab', 'c']);
    expect(chatInput.cursorY).toBe(1);
    expect(chatInput.cursorX).toBe(0);
  });

  it('navigates between lines with left/right', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).newLine();
    (chatInput as any).insertChar('b');
    expect(chatInput.lines).toEqual(['a', 'b']);
    expect(chatInput.cursorY).toBe(1);
    expect(chatInput.cursorX).toBe(1);

    (chatInput as any).moveLeft();
    expect(chatInput.cursorX).toBe(0);
    expect(chatInput.cursorY).toBe(1);

    (chatInput as any).moveLeft();
    expect(chatInput.cursorX).toBe(1);
    expect(chatInput.cursorY).toBe(0);

    (chatInput as any).moveRight();
    expect(chatInput.cursorX).toBe(0);
    expect(chatInput.cursorY).toBe(1);
  });

  it('joins lines with backspace at start of non-first line', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).newLine();
    (chatInput as any).insertChar('b');
    (chatInput as any).moveLeft();
    (chatInput as any).deleteChar();
    expect(chatInput.lines).toEqual(['ab']);
    expect(chatInput.cursorY).toBe(0);
    expect(chatInput.cursorX).toBe(1);
  });

  it('submits text on sendLine, adds to history, and clears', () => {
    (chatInput as any).insertChar('h');
    (chatInput as any).insertChar('i');
    (chatInput as any).sendLine();
    expect(onSubmit).toHaveBeenCalledWith('hi');
    expect(chatInput.lines).toEqual(['']);
    expect(chatInput.cursorX).toBe(0);
    expect(chatInput.cursorY).toBe(0);
  });

  it('does not submit empty text', () => {
    (chatInput as any).sendLine();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('does not submit whitespace-only text', () => {
    (chatInput as any).insertChar(' ');
    (chatInput as any).insertChar(' ');
    (chatInput as any).sendLine();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('navigates history with up/down', () => {
    (chatInput as any).insertChar('f');
    (chatInput as any).insertChar('i');
    (chatInput as any).insertChar('r');
    (chatInput as any).insertChar('s');
    (chatInput as any).insertChar('t');
    (chatInput as any).sendLine();

    (chatInput as any).insertChar('s');
    (chatInput as any).insertChar('e');
    (chatInput as any).insertChar('c');
    (chatInput as any).insertChar('o');
    (chatInput as any).insertChar('n');
    (chatInput as any).insertChar('d');
    (chatInput as any).sendLine();

    (chatInput as any).historyUp();
    expect(chatInput.getText()).toBe('second');

    (chatInput as any).historyUp();
    expect(chatInput.getText()).toBe('first');

    (chatInput as any).historyDown();
    expect(chatInput.getText()).toBe('second');

    (chatInput as any).historyDown();
    expect(chatInput.getText()).toBe('');
  });

  it('handles home and end navigation', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveHome();
    expect(chatInput.cursorX).toBe(0);
    (chatInput as any).moveEnd();
    expect(chatInput.cursorX).toBe(3);
  });

  it('clears line with Ctrl+U', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).clearLine();
    expect(chatInput.lines).toEqual(['']);
    expect(chatInput.cursorX).toBe(0);
  });

  it('deletes to end with Ctrl+K', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveHome();
    (chatInput as any).deleteToEnd();
    expect(chatInput.lines).toEqual(['']);
    expect(chatInput.cursorX).toBe(0);
  });

  it('deletes word backwards with Ctrl+W', () => {
    (chatInput as any).insertChar('h');
    (chatInput as any).insertChar('e');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('o');
    (chatInput as any).insertChar(' ');
    (chatInput as any).insertChar('w');
    (chatInput as any).insertChar('o');
    (chatInput as any).insertChar('r');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('d');
    (chatInput as any).deleteWordBackward();
    expect(chatInput.getText()).toBe('hello ');
    expect(chatInput.cursorX).toBe(6);

    (chatInput as any).deleteWordBackward();
    expect(chatInput.getText()).toBe('');
    expect(chatInput.cursorX).toBe(0);
  });

  it('inserts two spaces on tab', () => {
    (chatInput as any).handleKeypress('\t', makeKey('tab'));
    expect(chatInput.lines).toEqual(['  ']);
    expect(chatInput.cursorX).toBe(2);
  });

  it('deletes forward with delete key', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveHome();
    (chatInput as any).deleteForward();
    expect(chatInput.lines).toEqual(['bc']);
    expect(chatInput.cursorX).toBe(0);
  });

  it('handles cursor up/down within lines', () => {
    (chatInput as any).insertChar('a');
    (chatInput as any).newLine();
    (chatInput as any).insertChar('b');
    (chatInput as any).insertChar('c');
    (chatInput as any).moveUp();
    expect(chatInput.cursorY).toBe(0);
    expect(chatInput.cursorX).toBe(1);
    (chatInput as any).moveDown();
    expect(chatInput.cursorY).toBe(1);
    expect(chatInput.cursorX).toBe(1);
  });

  it('does nothing on cursor up when at first line', () => {
    (chatInput as any).moveUp();
    expect(chatInput.cursorY).toBe(0);
  });

  it('does nothing on cursor down when at last line', () => {
    (chatInput as any).moveDown();
    expect(chatInput.cursorY).toBe(0);
  });

  it('clamps cursor to line length when moving up', () => {
    (chatInput as any).insertChar('s');
    (chatInput as any).insertChar('h');
    (chatInput as any).insertChar('o');
    (chatInput as any).insertChar('r');
    (chatInput as any).insertChar('t');
    (chatInput as any).newLine();
    (chatInput as any).insertChar('v');
    (chatInput as any).insertChar('e');
    (chatInput as any).insertChar('r');
    (chatInput as any).insertChar('y');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('o');
    (chatInput as any).insertChar('n');
    (chatInput as any).insertChar('g');
    (chatInput as any).insertChar('l');
    (chatInput as any).insertChar('i');
    (chatInput as any).insertChar('n');
    (chatInput as any).insertChar('e');
    (chatInput as any).moveEnd();
    (chatInput as any).moveUp();
    expect(chatInput.cursorX).toBe(5);
    expect(chatInput.cursorY).toBe(0);
  });

  it('triggers cancel callback on Ctrl+C', () => {
    const onCancel = vi.fn();
    const ci = new ChatInput({
      onSubmit: vi.fn(),
      onCancel,
      stdin: mockStdin as any,
      stdout: mockStdout as any,
    });
    ci.start();
    (ci as any).handleKeypress('\x03', makeKey('c', { ctrl: true }));
    expect(onCancel).toHaveBeenCalled();
    ci.stop();
  });

  it('handles ctrl+enter submission', () => {
    (chatInput as any).insertChar('t');
    (chatInput as any).insertChar('e');
    (chatInput as any).insertChar('s');
    (chatInput as any).insertChar('t');
    (chatInput as any).handleKeypress(undefined, makeKey('enter', { ctrl: true }));
    expect(onSubmit).toHaveBeenCalledWith('test');
  });

  it('handles ctrl+L to clear screen', () => {
    chatInput.start();
    (chatInput as any).handleKeypress(undefined, makeKey('l', { ctrl: true }));
    expect(mockStdout.write).toHaveBeenCalledWith('\x1Bc');
  });

  it('start sets up keypress listener', () => {
    chatInput.start();
    expect(mockStdin.on).toHaveBeenCalledWith('keypress', expect.any(Function));
  });

  it('stop cleans up listeners', () => {
    chatInput.start();
    chatInput.stop();
    expect(mockStdin.removeListener).toHaveBeenCalledWith('keypress', expect.any(Function));
    expect(mockStdin.setRawMode).toHaveBeenCalledWith(false);
  });

  it('renders on start', () => {
    const renderSpy = vi.spyOn(chatInput as any, 'renderInput');
    chatInput.start();
    expect(renderSpy).toHaveBeenCalled();
  });
});
