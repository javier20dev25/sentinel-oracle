import pc from 'picocolors';
import { BORDERS, COLORS } from './styles.js';
function wordWrap(text, width) {
    const lines = [];
    const paragraphs = text.split('\n');
    for (const para of paragraphs) {
        if (para.length === 0) {
            lines.push('');
            continue;
        }
        let remaining = para;
        while (remaining.length > width) {
            let breakPos = remaining.lastIndexOf(' ', width);
            if (breakPos <= 0)
                breakPos = width;
            lines.push(remaining.slice(0, breakPos));
            remaining = remaining.slice(breakPos).trimStart();
        }
        if (remaining.length > 0) {
            lines.push(remaining);
        }
        else if (para.length === 0) {
            lines.push('');
        }
    }
    return lines;
}
function boxedContent(opts) {
    var _a;
    const indentStr = ' '.repeat((_a = opts.indent) !== null && _a !== void 0 ? _a : 0);
    const innerWidth = opts.boxWidth - 4;
    const b = BORDERS.chat;
    const result = [];
    const titleStr = opts.titleColor(` ${opts.title} `);
    const hFillCount = Math.max(1, opts.boxWidth - 2 - titleStr.length);
    result.push(`${indentStr}${opts.borderColor(b.tl)}${titleStr}${opts.borderColor(b.h.repeat(hFillCount))}${opts.borderColor(b.tr)}`);
    for (const line of opts.lines) {
        const lines = line.length === 0 ? [''] : wordWrap(line, innerWidth);
        for (const wrapped of lines) {
            const display = wrapped.length > innerWidth ? wrapped.slice(0, innerWidth - 1) + '\u2026' : wrapped;
            const pad = ' '.repeat(Math.max(0, innerWidth - display.length));
            result.push(`${indentStr}${opts.borderColor(b.v)} ${pc.white(display)}${pad} ${opts.borderColor(b.v)}`);
        }
    }
    result.push(`${indentStr}${opts.borderColor(b.bl)}${opts.borderColor(b.h.repeat(opts.boxWidth - 2))}${opts.borderColor(b.br)}`);
    return result;
}
function centerText(text, width) {
    const visible = text.replace(/\x1b\[[0-9;]*m/g, '');
    const padTotal = Math.max(0, width - visible.length);
    const leftPad = Math.floor(padTotal / 2);
    const rightPad = padTotal - leftPad;
    return ' '.repeat(leftPad) + text + ' '.repeat(rightPad);
}
export class MessageRenderer {
    constructor() {
        this.messages = [];
        this.maxMessages = 100;
        this._renderedLineCount = 0;
    }
    get renderedLineCount() {
        return this._renderedLineCount;
    }
    addMessage(msg) {
        this.messages.push(msg);
        if (this.messages.length > this.maxMessages) {
            this.messages.shift();
        }
    }
    updateLastAssistantContent(content) {
        for (let i = this.messages.length - 1; i >= 0; i--) {
            if (this.messages[i].type === 'assistant') {
                this.messages[i].content = content;
                return;
            }
        }
        this.addMessage({ type: 'assistant', content, timestamp: new Date() });
    }
    clear() {
        this.messages = [];
        this._renderedLineCount = 0;
    }
    renderAll() {
        const lines = [];
        for (const msg of this.messages) {
            lines.push(...this.renderMessage(msg));
        }
        this.stdout.write('\x1b[H');
        for (const line of lines) {
            this.stdout.write('\r\x1b[K');
            this.stdout.write(line + '\n');
        }
        if (this._renderedLineCount > lines.length) {
            const diff = this._renderedLineCount - lines.length;
            for (let i = 0; i < diff; i++) {
                this.stdout.write('\r\x1b[K');
                this.stdout.write('\n');
            }
        }
        this._renderedLineCount = lines.length;
        return lines.length;
    }
    get stdout() {
        return process.stdout;
    }
    getBoxWidth() {
        const cols = process.stdout.columns || 80;
        return Math.min(cols - 4, 80);
    }
    renderMessage(msg) {
        switch (msg.type) {
            case 'user':
                return this.renderUserMessage(msg);
            case 'assistant':
                return this.renderAssistantMessage(msg);
            case 'tool':
                return this.renderToolMessage(msg);
            case 'system':
                return this.renderSystemMessage(msg);
            case 'error':
                return this.renderErrorMessage(msg);
            default:
                return [];
        }
    }
    renderUserMessage(msg) {
        const bw = this.getBoxWidth();
        const contentLines = msg.content.split('\n');
        return boxedContent({
            lines: contentLines,
            boxWidth: bw,
            borderColor: COLORS.user,
            title: 'You',
            titleColor: COLORS.user,
        });
    }
    renderAssistantMessage(msg) {
        const bw = this.getBoxWidth();
        const contentLines = msg.content.split('\n');
        const rendered = boxedContent({
            lines: contentLines,
            boxWidth: bw,
            borderColor: COLORS.assistant,
            title: '\u2726 Sentinel',
            titleColor: COLORS.assistant,
        });
        return rendered.map(l => `  ${l}`);
    }
    renderToolMessage(msg) {
        const bw = this.getBoxWidth() - 2;
        const toolName = msg.toolName || 'tool';
        const collapsed = msg.collapsed !== false;
        const contentLines = collapsed
            ? [`${pc.green('\u2713')} completed`]
            : msg.content.split('\n');
        const rendered = boxedContent({
            lines: contentLines,
            boxWidth: bw,
            borderColor: COLORS.tool,
            title: `\uD83D\uDD27 ${toolName}`,
            titleColor: COLORS.tool,
        });
        return rendered.map(l => `  ${l}`);
    }
    renderSystemMessage(msg) {
        const bw = this.getBoxWidth();
        const text = ` ${msg.content} `;
        const line = COLORS.textDim('\u2500'.repeat(Math.max(1, Math.floor((bw - 2 - text.length) / 2))));
        const lineEnd = COLORS.textDim('\u2500'.repeat(Math.max(1, bw - 2 - text.length - line.length)));
        return [`  ${line}${text}${lineEnd}`];
    }
    renderErrorMessage(msg) {
        const bw = this.getBoxWidth();
        const contentLines = msg.content.split('\n');
        const b = BORDERS.box;
        const color = COLORS.error;
        const indentStr = '  ';
        const innerWidth = bw - 4;
        const result = [];
        const titleStr = color(' Error ');
        const hFill = color(b.h.repeat(Math.max(1, bw - 2 - titleStr.length)));
        result.push(`${indentStr}${color(b.tl)}${titleStr}${hFill}${color(b.tr)}`);
        for (const line of contentLines) {
            const wrapped = line.length === 0 ? [''] : wordWrap(line, innerWidth);
            for (const w of wrapped) {
                const display = w.length > innerWidth ? w.slice(0, innerWidth - 1) + '\u2026' : w;
                const pad = ' '.repeat(Math.max(0, innerWidth - display.length));
                result.push(`${indentStr}${color(b.v)} ${pc.white(display)}${pad} ${color(b.v)}`);
            }
        }
        result.push(`${indentStr}${color(b.bl)}${color(b.h.repeat(bw - 2))}${color(b.br)}`);
        return result;
    }
}
