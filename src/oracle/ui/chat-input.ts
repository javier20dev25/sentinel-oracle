import * as readline from 'readline';
import * as pc from 'picocolors';
import { BORDERS, muted } from './styles.js';

const CHAT_BORDER_CHARS = BORDERS.chat;

export interface ChatInputOptions {
  placeholder?: string;
  onSubmit: (text: string) => void;
  onCancel?: () => void;
  maxVisibleLines?: number;
  stdin?: NodeJS.ReadStream;
  stdout?: NodeJS.WriteStream;
}

export class ChatInput {
  public lines: string[] = [''];
  public cursorX: number = 0;
  public cursorY: number = 0;
  private history: string[] = [];
  private historyIndex: number = -1;
  private active: boolean = false;
  private onSubmit: (text: string) => void;
  private onCancel?: () => void;
  private stdin: NodeJS.ReadStream;
  private stdout: NodeJS.WriteStream;
  private placeholder: string;
  private maxVisibleLines: number;
  private scrollTop: number = 0;
  private scrollLeft: number = 0;
  private messageLineCount: number = 0;
  private _previousRenderedHeight: number = 0;

  constructor(options: ChatInputOptions) {
    this.stdin = options.stdin || process.stdin;
    this.stdout = options.stdout || process.stdout;
    this.onSubmit = options.onSubmit;
    this.onCancel = options.onCancel;
    this.placeholder = options.placeholder || '';
    this.maxVisibleLines = options.maxVisibleLines || 8;
  }

  setMessageLineCount(count: number): void {
    this.messageLineCount = count;
  }

  get renderedHeight(): number {
    return Math.min(this.lines.length, this.maxVisibleLines) + 2;
  }

  start(): void {
    if (this.active) return;
    this.active = true;
    try { this.stdin.setRawMode(true); } catch {}
    this.stdin.resume();
    readline.emitKeypressEvents(this.stdin);
    this.stdin.on('keypress', this.handleKeypressEvent);
    this.stdout.on('resize', this.handleResize);
    this.render();
  }

  stop(): void {
    if (!this.active) return;
    this.active = false;
    this.stdin.removeListener('keypress', this.handleKeypressEvent);
    this.stdout.removeListener('resize', this.handleResize);
    try { this.stdin.setRawMode(false); } catch {}
    this.stdin.pause();
  }

  private handleKeypressEvent = (str: string | undefined, key: readline.Key): void => {
    if (!this.active) return;
    this.handleKeypress(str, key);
  };

  private handleResize = (): void => {
    if (!this.active) return;
    this.renderInput();
  };

  render(): void {
    this.renderInput();
  }

  private handleKeypress(key: string | undefined, info: readline.Key): void {
    if (info.ctrl && (info.name === 'c' || key === '\x03')) {
      if (this.onCancel) {
        this.onCancel();
      } else {
        this.stop();
        process.exit(0);
      }
      return;
    }

    if (info.ctrl && info.name === 'l') {
      this.stdout.write('\x1Bc');
      return;
    }

    if (info.ctrl && (info.name === 'return' || info.name === 'enter')) {
      this.sendLine();
      return;
    }

    if (info.name === 'tab') {
      this.insertChar(' ');
      this.insertChar(' ');
      return;
    }

    if (info.name === 'enter' || info.name === 'return') {
      this.newLine();
      return;
    }

    if (info.name === 'backspace') {
      this.deleteChar();
      return;
    }

    if (info.name === 'delete') {
      this.deleteForward();
      return;
    }

    if (info.name === 'up') {
      this.historyUp();
      return;
    }

    if (info.name === 'down') {
      this.historyDown();
      return;
    }

    if (info.name === 'left') {
      this.moveLeft();
      return;
    }

    if (info.name === 'right') {
      this.moveRight();
      return;
    }

    if (info.name === 'home') {
      this.moveHome();
      return;
    }

    if (info.name === 'end') {
      this.moveEnd();
      return;
    }

    if (info.ctrl && info.name === 'u') {
      this.clearLine();
      return;
    }

    if (info.ctrl && info.name === 'k') {
      this.deleteToEnd();
      return;
    }

    if (info.ctrl && info.name === 'w') {
      this.deleteWordBackward();
      return;
    }

    if (key && key.length === 1 && key.charCodeAt(0) >= 32) {
      this.insertChar(key);
      return;
    }
  }

  getText(): string {
    return this.lines.join('\n');
  }

  private insertChar(ch: string): void {
    const line = this.lines[this.cursorY];
    this.lines[this.cursorY] = line.slice(0, this.cursorX) + ch + line.slice(this.cursorX);
    this.cursorX++;
    this.ensureCursorVisible();
    this.renderInput();
  }

  private deleteChar(): void {
    if (this.cursorX > 0) {
      const line = this.lines[this.cursorY];
      this.lines[this.cursorY] = line.slice(0, this.cursorX - 1) + line.slice(this.cursorX);
      this.cursorX--;
      this.ensureCursorVisible();
      this.renderInput();
    } else if (this.cursorY > 0) {
      const prevLine = this.lines[this.cursorY - 1];
      const curLine = this.lines[this.cursorY];
      this.cursorX = prevLine.length;
      this.lines[this.cursorY - 1] = prevLine + curLine;
      this.lines.splice(this.cursorY, 1);
      this.cursorY--;
      this.ensureCursorVisible();
      this.renderInput();
    }
  }

  private deleteForward(): void {
    const line = this.lines[this.cursorY];
    if (this.cursorX < line.length) {
      this.lines[this.cursorY] = line.slice(0, this.cursorX) + line.slice(this.cursorX + 1);
      this.renderInput();
    } else if (this.cursorY < this.lines.length - 1) {
      const nextLine = this.lines[this.cursorY + 1];
      this.lines[this.cursorY] = line + nextLine;
      this.lines.splice(this.cursorY + 1, 1);
      this.renderInput();
    }
  }

  private newLine(): void {
    const line = this.lines[this.cursorY];
    const before = line.slice(0, this.cursorX);
    const after = line.slice(this.cursorX);
    this.lines[this.cursorY] = before;
    this.cursorY++;
    this.cursorX = 0;
    this.lines.splice(this.cursorY, 0, after);

    if (this.cursorY >= this.scrollTop + this.maxVisibleLines) {
      this.scrollTop = this.cursorY - this.maxVisibleLines + 1;
    }

    this.renderInput();
  }

  private sendLine(): void {
    const text = this.getText().trim();
    if (!text) return;

    this.history.push(text);
    this.historyIndex = -1;

    this.lines = [''];
    this.cursorX = 0;
    this.cursorY = 0;
    this.scrollTop = 0;
    this.scrollLeft = 0;

    this.renderInput();
    this.onSubmit(text);
  }

  private historyUp(): void {
    if (this.history.length === 0) return;
    if (this.historyIndex < this.history.length - 1) {
      this.historyIndex++;
      this.loadHistoryItem();
    }
  }

  private historyDown(): void {
    if (this.historyIndex === -1) return;
    this.historyIndex--;
    if (this.historyIndex >= 0) {
      this.loadHistoryItem();
    } else {
      this.lines = [''];
      this.cursorX = 0;
      this.cursorY = 0;
      this.scrollTop = 0;
      this.scrollLeft = 0;
      this.renderInput();
    }
  }

  private loadHistoryItem(): void {
    const text = this.history[this.history.length - 1 - this.historyIndex];
    const newLines = text.split('\n');
    this.lines = newLines.length === 0 ? [''] : newLines;
    this.cursorY = this.lines.length - 1;
    this.cursorX = this.lines[this.cursorY].length;
    this.scrollTop = Math.max(0, this.lines.length - this.maxVisibleLines);
    this.scrollLeft = 0;
    this.renderInput();
  }

  private moveLeft(): void {
    if (this.cursorX > 0) {
      this.cursorX--;
    } else if (this.cursorY > 0) {
      this.cursorY--;
      this.cursorX = this.lines[this.cursorY].length;
    }
    this.ensureCursorVisible();
    this.renderInput();
  }

  private moveRight(): void {
    const line = this.lines[this.cursorY];
    if (this.cursorX < line.length) {
      this.cursorX++;
    } else if (this.cursorY < this.lines.length - 1) {
      this.cursorY++;
      this.cursorX = 0;
    }
    this.ensureCursorVisible();
    this.renderInput();
  }

  private moveUp(): void {
    if (this.cursorY > 0) {
      const prevLineLen = this.lines[this.cursorY - 1].length;
      this.cursorY--;
      this.cursorX = Math.min(this.cursorX, prevLineLen);
    }
    this.ensureCursorVisible();
    this.renderInput();
  }

  private moveDown(): void {
    if (this.cursorY < this.lines.length - 1) {
      const nextLineLen = this.lines[this.cursorY + 1].length;
      this.cursorY++;
      this.cursorX = Math.min(this.cursorX, nextLineLen);
    }
    this.ensureCursorVisible();
    this.renderInput();
  }

  private moveHome(): void {
    this.cursorX = 0;
    this.renderInput();
  }

  private moveEnd(): void {
    this.cursorX = this.lines[this.cursorY].length;
    this.renderInput();
  }

  private clearLine(): void {
    this.lines[this.cursorY] = '';
    this.cursorX = 0;
    this.renderInput();
  }

  private deleteToEnd(): void {
    const line = this.lines[this.cursorY];
    this.lines[this.cursorY] = line.slice(0, this.cursorX);
    this.renderInput();
  }

  private deleteWordBackward(): void {
    const line = this.lines[this.cursorY];
    const before = line.slice(0, this.cursorX);
    const after = line.slice(this.cursorX);
    const trimmed = before.trimEnd();
    if (trimmed.length === 0) {
      this.lines[this.cursorY] = after;
      this.cursorX = 0;
    } else {
      const lastSpace = trimmed.lastIndexOf(' ');
      const wordStart = lastSpace === -1 ? 0 : lastSpace + 1;
      this.lines[this.cursorY] = before.slice(0, wordStart) + after;
      this.cursorX = wordStart;
    }
    this.renderInput();
  }

  private ensureCursorVisible(): void {
    const cols = this.stdout.columns || 80;
    const contentWidth = Math.min(cols - 4, 100) - 4;

    if (this.cursorY < this.scrollTop) {
      this.scrollTop = this.cursorY;
    } else if (this.cursorY >= this.scrollTop + this.maxVisibleLines) {
      this.scrollTop = this.cursorY - this.maxVisibleLines + 1;
    }

    if (this.cursorX < this.scrollLeft) {
      this.scrollLeft = this.cursorX;
    } else if (this.cursorX >= this.scrollLeft + contentWidth) {
      this.scrollLeft = this.cursorX - contentWidth + 1;
    }
  }

  private renderInput(): void {
    if (!this.active) return;

    const cols = this.stdout.columns || 80;
    const boxWidth = Math.min(cols - 4, 100);
    const contentWidth = boxWidth - 4;

    const actualVisibleLines = Math.min(this.lines.length, this.maxVisibleLines);

    try {
      this.stdout.cursorTo(0, this.messageLineCount);
    } catch {}
    this.stdout.write('\x1b[J');

    let topLabel = '';
    if (this.lines.length === 1 && this.lines[0] === '' && this.placeholder) {
      topLabel = muted(` ${this.placeholder} `);
    }
    const topBorderLine = `${pc.cyan(CHAT_BORDER_CHARS.tl)}${topLabel}${pc.cyan(CHAT_BORDER_CHARS.h.repeat(Math.max(1, boxWidth - 2 - topLabel.length)))}${pc.cyan(CHAT_BORDER_CHARS.tr)}`;
    this.stdout.write(topBorderLine + '\n');

    for (let i = 0; i < actualVisibleLines; i++) {
      const lineIndex = this.scrollTop + i;
      let rawLine = '';
      if (lineIndex < this.lines.length) {
        rawLine = this.lines[lineIndex];
      }

      const displayLine = rawLine.slice(this.scrollLeft, this.scrollLeft + contentWidth);
      const paddedLine = displayLine + ' '.repeat(Math.max(0, contentWidth - displayLine.length));
      const content = ` ${paddedLine} `;
      this.stdout.write(`${pc.cyan(CHAT_BORDER_CHARS.v)}${content}${pc.cyan(CHAT_BORDER_CHARS.v)}` + '\n');
    }

    const bottomBorderLine = `${pc.cyan(CHAT_BORDER_CHARS.bl)}${pc.cyan(CHAT_BORDER_CHARS.h.repeat(boxWidth - 2))}${pc.cyan(CHAT_BORDER_CHARS.br)}`;
    this.stdout.write(bottomBorderLine + '\n');

    const cursorRow = this.messageLineCount + 1 + (this.cursorY - this.scrollTop);
    const cursorCol = 3 + (this.cursorX - this.scrollLeft);
    const safeRow = Math.max(0, cursorRow);
    const safeCol = Math.max(0, Math.min(cursorCol, (this.stdout.columns || 80) - 1));
    try {
      this.stdout.cursorTo(safeCol, safeRow);
    } catch {}
  }
}
