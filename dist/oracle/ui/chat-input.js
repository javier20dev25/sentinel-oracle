"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChatInput = void 0;
const readline = __importStar(require("readline"));
const pc = __importStar(require("picocolors"));
const styles_1 = require("./styles");
const CHAT_BORDER_CHARS = styles_1.BORDERS.chat;
class ChatInput {
    constructor(options) {
        this.lines = [''];
        this.cursorX = 0;
        this.cursorY = 0;
        this.history = [];
        this.historyIndex = -1;
        this.active = false;
        this.scrollTop = 0;
        this.scrollLeft = 0;
        this.messageLineCount = 0;
        this._previousRenderedHeight = 0;
        this.handleKeypressEvent = (str, key) => {
            if (!this.active)
                return;
            this.handleKeypress(str, key);
        };
        this.handleResize = () => {
            if (!this.active)
                return;
            this.renderInput();
        };
        this.stdin = options.stdin || process.stdin;
        this.stdout = options.stdout || process.stdout;
        this.onSubmit = options.onSubmit;
        this.onCancel = options.onCancel;
        this.placeholder = options.placeholder || '';
        this.maxVisibleLines = options.maxVisibleLines || 8;
    }
    setMessageLineCount(count) {
        this.messageLineCount = count;
    }
    get renderedHeight() {
        return Math.min(this.lines.length, this.maxVisibleLines) + 2;
    }
    start() {
        if (this.active)
            return;
        this.active = true;
        try {
            this.stdin.setRawMode(true);
        }
        catch (_a) { }
        this.stdin.resume();
        readline.emitKeypressEvents(this.stdin);
        this.stdin.on('keypress', this.handleKeypressEvent);
        this.stdout.on('resize', this.handleResize);
        this.render();
    }
    stop() {
        if (!this.active)
            return;
        this.active = false;
        this.stdin.removeListener('keypress', this.handleKeypressEvent);
        this.stdout.removeListener('resize', this.handleResize);
        try {
            this.stdin.setRawMode(false);
        }
        catch (_a) { }
        this.stdin.pause();
    }
    render() {
        this.renderInput();
    }
    handleKeypress(key, info) {
        if (info.ctrl && (info.name === 'c' || key === '\x03')) {
            if (this.onCancel) {
                this.onCancel();
            }
            else {
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
    getText() {
        return this.lines.join('\n');
    }
    insertChar(ch) {
        const line = this.lines[this.cursorY];
        this.lines[this.cursorY] = line.slice(0, this.cursorX) + ch + line.slice(this.cursorX);
        this.cursorX++;
        this.ensureCursorVisible();
        this.renderInput();
    }
    deleteChar() {
        if (this.cursorX > 0) {
            const line = this.lines[this.cursorY];
            this.lines[this.cursorY] = line.slice(0, this.cursorX - 1) + line.slice(this.cursorX);
            this.cursorX--;
            this.ensureCursorVisible();
            this.renderInput();
        }
        else if (this.cursorY > 0) {
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
    deleteForward() {
        const line = this.lines[this.cursorY];
        if (this.cursorX < line.length) {
            this.lines[this.cursorY] = line.slice(0, this.cursorX) + line.slice(this.cursorX + 1);
            this.renderInput();
        }
        else if (this.cursorY < this.lines.length - 1) {
            const nextLine = this.lines[this.cursorY + 1];
            this.lines[this.cursorY] = line + nextLine;
            this.lines.splice(this.cursorY + 1, 1);
            this.renderInput();
        }
    }
    newLine() {
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
    sendLine() {
        const text = this.getText().trim();
        if (!text)
            return;
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
    historyUp() {
        if (this.history.length === 0)
            return;
        if (this.historyIndex < this.history.length - 1) {
            this.historyIndex++;
            this.loadHistoryItem();
        }
    }
    historyDown() {
        if (this.historyIndex === -1)
            return;
        this.historyIndex--;
        if (this.historyIndex >= 0) {
            this.loadHistoryItem();
        }
        else {
            this.lines = [''];
            this.cursorX = 0;
            this.cursorY = 0;
            this.scrollTop = 0;
            this.scrollLeft = 0;
            this.renderInput();
        }
    }
    loadHistoryItem() {
        const text = this.history[this.history.length - 1 - this.historyIndex];
        const newLines = text.split('\n');
        this.lines = newLines.length === 0 ? [''] : newLines;
        this.cursorY = this.lines.length - 1;
        this.cursorX = this.lines[this.cursorY].length;
        this.scrollTop = Math.max(0, this.lines.length - this.maxVisibleLines);
        this.scrollLeft = 0;
        this.renderInput();
    }
    moveLeft() {
        if (this.cursorX > 0) {
            this.cursorX--;
        }
        else if (this.cursorY > 0) {
            this.cursorY--;
            this.cursorX = this.lines[this.cursorY].length;
        }
        this.ensureCursorVisible();
        this.renderInput();
    }
    moveRight() {
        const line = this.lines[this.cursorY];
        if (this.cursorX < line.length) {
            this.cursorX++;
        }
        else if (this.cursorY < this.lines.length - 1) {
            this.cursorY++;
            this.cursorX = 0;
        }
        this.ensureCursorVisible();
        this.renderInput();
    }
    moveUp() {
        if (this.cursorY > 0) {
            const prevLineLen = this.lines[this.cursorY - 1].length;
            this.cursorY--;
            this.cursorX = Math.min(this.cursorX, prevLineLen);
        }
        this.ensureCursorVisible();
        this.renderInput();
    }
    moveDown() {
        if (this.cursorY < this.lines.length - 1) {
            const nextLineLen = this.lines[this.cursorY + 1].length;
            this.cursorY++;
            this.cursorX = Math.min(this.cursorX, nextLineLen);
        }
        this.ensureCursorVisible();
        this.renderInput();
    }
    moveHome() {
        this.cursorX = 0;
        this.renderInput();
    }
    moveEnd() {
        this.cursorX = this.lines[this.cursorY].length;
        this.renderInput();
    }
    clearLine() {
        this.lines[this.cursorY] = '';
        this.cursorX = 0;
        this.renderInput();
    }
    deleteToEnd() {
        const line = this.lines[this.cursorY];
        this.lines[this.cursorY] = line.slice(0, this.cursorX);
        this.renderInput();
    }
    deleteWordBackward() {
        const line = this.lines[this.cursorY];
        const before = line.slice(0, this.cursorX);
        const after = line.slice(this.cursorX);
        const trimmed = before.trimEnd();
        if (trimmed.length === 0) {
            this.lines[this.cursorY] = after;
            this.cursorX = 0;
        }
        else {
            const lastSpace = trimmed.lastIndexOf(' ');
            const wordStart = lastSpace === -1 ? 0 : lastSpace + 1;
            this.lines[this.cursorY] = before.slice(0, wordStart) + after;
            this.cursorX = wordStart;
        }
        this.renderInput();
    }
    ensureCursorVisible() {
        const cols = this.stdout.columns || 80;
        const contentWidth = Math.min(cols - 4, 100) - 4;
        if (this.cursorY < this.scrollTop) {
            this.scrollTop = this.cursorY;
        }
        else if (this.cursorY >= this.scrollTop + this.maxVisibleLines) {
            this.scrollTop = this.cursorY - this.maxVisibleLines + 1;
        }
        if (this.cursorX < this.scrollLeft) {
            this.scrollLeft = this.cursorX;
        }
        else if (this.cursorX >= this.scrollLeft + contentWidth) {
            this.scrollLeft = this.cursorX - contentWidth + 1;
        }
    }
    renderInput() {
        if (!this.active)
            return;
        const cols = this.stdout.columns || 80;
        const boxWidth = Math.min(cols - 4, 100);
        const contentWidth = boxWidth - 4;
        const actualVisibleLines = Math.min(this.lines.length, this.maxVisibleLines);
        try {
            this.stdout.cursorTo(0, this.messageLineCount);
        }
        catch (_a) { }
        this.stdout.write('\x1b[J');
        let topLabel = '';
        if (this.lines.length === 1 && this.lines[0] === '' && this.placeholder) {
            topLabel = (0, styles_1.muted)(` ${this.placeholder} `);
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
        }
        catch (_b) { }
    }
}
exports.ChatInput = ChatInput;
