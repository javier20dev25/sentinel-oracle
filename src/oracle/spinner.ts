/**
 * Terminal spinner with different animation patterns.
 */

export type SpinnerType = 'thinking' | 'executing' | 'processing';

interface SpinnerConfig {
  frames: string[];
  interval: number;
  prefix: string;
}

const CONFIGS: Record<SpinnerType, SpinnerConfig> = {
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

export class Spinner {
  private frame = 0;
  private interval: NodeJS.Timeout | null = null;
  private message = '';
  private running = false;
  private type: SpinnerType = 'thinking';

  start(message: string, type: SpinnerType = 'thinking'): void {
    if (this.running) return;
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

  update(message: string, type?: SpinnerType): void {
    this.message = message;
    if (type) this.type = type;
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.running = false;
    process.stdout.write('\r' + ' '.repeat(this.message.length + 10) + '\r');
  }

  private color(f: string): string {
    if (this.type === 'thinking') return `\x1b[36m${f}\x1b[0m`;    // cyan
    if (this.type === 'executing') return `\x1b[33m${f}\x1b[0m`;   // yellow
    return `\x1b[35m${f}\x1b[0m`;                                   // magenta
  }
}
