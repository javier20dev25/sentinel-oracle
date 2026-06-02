import * as pc from 'picocolors';

export const BORDERS = {
  header: { tl: '╔', tr: '╗', bl: '╚', br: '╝', h: '═', v: '║' },
  box: { tl: '┌', tr: '┐', bl: '└', br: '┘', h: '─', v: '│' },
  chat: { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│' },
};

export const COLORS = {
  accent: pc.cyan,
  accentDim: pc.dim,
  surface: pc.bgBlack,
  surface2: pc.bgBlack,
  text: pc.white,
  textDim: pc.dim,
  user: pc.cyan,
  assistant: pc.magenta,
  tool: pc.yellow,
  error: pc.red,
  success: pc.green,
  warning: pc.yellow,
  info: pc.blue,
};

export const SPACING = {
  padX: 2,
  padY: 1,
  contentWidth: 80,
};

export function dim(text: string): string { return pc.dim(text); }
export function accent(text: string): string { return pc.cyan(text); }
export function success(text: string): string { return pc.green(text); }
export function error(text: string): string { return pc.red(text); }
export function warning(text: string): string { return pc.yellow(text); }
export function info(text: string): string { return pc.blue(text); }
export function userColor(text: string): string { return pc.cyan(text); }
export function assistantColor(text: string): string { return pc.magenta(text); }
export function toolColor(text: string): string { return pc.yellow(text); }
export function muted(text: string): string { return pc.dim(pc.gray(text)); }

export function borderBox(width: number, title?: string): { top: string; bottom: string } {
  const b = BORDERS.box;
  const titleStr = title
    ? ` ${pc.cyan(title)} `
    : '';
  const top = `${b.tl}${b.h}${titleStr}${b.h.repeat(Math.max(1, width - titleStr.length - 2))}${b.tr}`;
  const bottom = `${b.bl}${b.h.repeat(width - 2)}${b.br}`;
  return { top, bottom };
}

export function divider(char: string = '─', width: number = 60): string {
  return pc.dim(char.repeat(width));
}

export function pad(text: string, width: number = SPACING.contentWidth): string {
  const visible = text.replace(/\x1b\[[0-9;]*m/g, '');
  if (visible.length >= width) return text;
  return text + ' '.repeat(width - visible.length);
}
