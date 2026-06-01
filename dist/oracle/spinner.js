"use strict";
/**
 * Terminal spinner with different animation patterns.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Spinner = void 0;
const CONFIGS = {
    thinking: {
        frames: ['\u25D0', '\u25D3', '\u25D1', '\u25D2'],
        interval: 120,
        prefix: '[~]',
    },
    executing: {
        frames: ['\u25B6', '\u25B7', '\u25B8', '\u25B9'],
        interval: 70,
        prefix: '[>]',
    },
    processing: {
        frames: ['\u25F0', '\u25F1', '\u25F2', '\u25F3'],
        interval: 90,
        prefix: '[*]',
    },
};
class Spinner {
    constructor() {
        this.frame = 0;
        this.interval = null;
        this.message = '';
        this.running = false;
        this.type = 'thinking';
    }
    start(message, type = 'thinking') {
        if (this.running)
            return;
        this.running = true;
        this.type = type;
        this.message = message;
        this.frame = 0;
        const cfg = CONFIGS[type];
        this.interval = setInterval(() => {
            process.stdout.write(`\r${this.color(cfg.frames[this.frame])} ${cfg.prefix} ${this.message}`);
            this.frame = (this.frame + 1) % cfg.frames.length;
        }, cfg.interval);
    }
    update(message, type) {
        this.message = message;
        if (type)
            this.type = type;
    }
    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        this.running = false;
        process.stdout.write('\r' + ' '.repeat(this.message.length + 10) + '\r');
    }
    color(f) {
        if (this.type === 'thinking')
            return `\x1b[36m${f}\x1b[0m`; // cyan
        if (this.type === 'executing')
            return `\x1b[33m${f}\x1b[0m`; // yellow
        return `\x1b[35m${f}\x1b[0m`; // magenta
    }
}
exports.Spinner = Spinner;
