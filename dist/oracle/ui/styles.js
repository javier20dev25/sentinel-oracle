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
exports.SPACING = exports.COLORS = exports.BORDERS = void 0;
exports.dim = dim;
exports.accent = accent;
exports.success = success;
exports.error = error;
exports.warning = warning;
exports.info = info;
exports.userColor = userColor;
exports.assistantColor = assistantColor;
exports.toolColor = toolColor;
exports.muted = muted;
exports.borderBox = borderBox;
exports.divider = divider;
exports.pad = pad;
const pc = __importStar(require("picocolors"));
exports.BORDERS = {
    header: { tl: '╔', tr: '╗', bl: '╚', br: '╝', h: '═', v: '║' },
    box: { tl: '┌', tr: '┐', bl: '└', br: '┘', h: '─', v: '│' },
    chat: { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│' },
};
exports.COLORS = {
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
exports.SPACING = {
    padX: 2,
    padY: 1,
    contentWidth: 80,
};
function dim(text) { return pc.dim(text); }
function accent(text) { return pc.cyan(text); }
function success(text) { return pc.green(text); }
function error(text) { return pc.red(text); }
function warning(text) { return pc.yellow(text); }
function info(text) { return pc.blue(text); }
function userColor(text) { return pc.cyan(text); }
function assistantColor(text) { return pc.magenta(text); }
function toolColor(text) { return pc.yellow(text); }
function muted(text) { return pc.dim(pc.gray(text)); }
function borderBox(width, title) {
    const b = exports.BORDERS.box;
    const titleStr = title
        ? ` ${pc.cyan(title)} `
        : '';
    const top = `${b.tl}${b.h}${titleStr}${b.h.repeat(Math.max(1, width - titleStr.length - 2))}${b.tr}`;
    const bottom = `${b.bl}${b.h.repeat(width - 2)}${b.br}`;
    return { top, bottom };
}
function divider(char = '─', width = 60) {
    return pc.dim(char.repeat(width));
}
function pad(text, width = exports.SPACING.contentWidth) {
    const visible = text.replace(/\x1b\[[0-9;]*m/g, '');
    if (visible.length >= width)
        return text;
    return text + ' '.repeat(width - visible.length);
}
