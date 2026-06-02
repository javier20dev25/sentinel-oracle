var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput, useApp, useWindowSize } from 'ink';
import { Message } from './message.js';
import { StatusBar } from './status-bar.js';
const MAX_VISIBLE_MESSAGES = 50;
export function Chat({ bridge, provider, onExit }) {
    const { exit } = useApp();
    const { columns, rows } = useWindowSize();
    const [messages, setMessages] = useState([]);
    const [inputValue, setInputValue] = useState('');
    const [inputCursor, setInputCursor] = useState(0);
    const [messageHistory, setMessageHistory] = useState([]);
    const [historyIndex, setHistoryIndex] = useState(-1);
    const [isThinking, setIsThinking] = useState(false);
    const [mode, setMode] = useState('execute');
    const [inputFocused, setInputFocused] = useState(true);
    const [scrollOffset, setScrollOffset] = useState(0);
    const [isMultiLine, setIsMultiLine] = useState(false);
    const addMessage = useCallback((msg) => {
        setMessages(prev => {
            const next = [...prev, msg];
            if (next.length > MAX_VISIBLE_MESSAGES * 2) {
                return next.slice(next.length - MAX_VISIBLE_MESSAGES);
            }
            return next;
        });
    }, []);
    useEffect(() => {
        var _a;
        (_a = bridge.setCallbacks) === null || _a === void 0 ? void 0 : _a.call(bridge, {
            onMessage: (msg) => {
                addMessage({
                    id: msg.id,
                    type: msg.type,
                    content: msg.content,
                    timestamp: msg.timestamp,
                    toolName: msg.toolName,
                    collapsed: msg.collapsed,
                    thinking: msg.thinking,
                });
            },
            onStreamingStart: (msgId) => {
                setIsThinking(false);
                setMessages(prev => prev.map(m => m.id === msgId ? Object.assign(Object.assign({}, m), { thinking: false }) : m));
            },
            onStreamingChunk: (msgId, chunk) => {
                setMessages(prev => prev.map(m => m.id === msgId ? Object.assign(Object.assign({}, m), { content: m.content + chunk }) : m));
            },
            onStreamingEnd: () => {
                setIsThinking(false);
            },
            onToolStart: (toolName) => {
                addMessage({
                    id: `tool-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                    type: 'tool',
                    content: `Running ${toolName}...`,
                    timestamp: new Date(),
                    toolName,
                    collapsed: true,
                });
            },
            onToolEnd: (toolName, result) => {
                setMessages(prev => prev.map(m => (m.toolName === toolName && m.type === 'tool')
                    ? Object.assign(Object.assign({}, m), { content: result || 'Completed', collapsed: false }) : m));
            },
            onError: (error) => {
                setIsThinking(false);
                addMessage({
                    id: `error-${Date.now()}`,
                    type: 'error',
                    content: error,
                    timestamp: new Date(),
                });
            },
        });
    }, [bridge, addMessage]);
    const handleSubmit = useCallback(() => __awaiter(this, void 0, void 0, function* () {
        const text = inputValue.trim();
        if (!text || isThinking)
            return;
        setMessageHistory(prev => [...prev, text]);
        setHistoryIndex(-1);
        setInputValue('');
        setInputCursor(0);
        setIsMultiLine(false);
        setIsThinking(true);
        setScrollOffset(0);
        try {
            yield bridge.sendMessage(text);
        }
        catch (e) {
            addMessage({
                id: `error-${Date.now()}`,
                type: 'error',
                content: e.message || 'An error occurred',
                timestamp: new Date(),
            });
        }
        finally {
            setIsThinking(false);
        }
    }), [inputValue, addMessage, bridge, isThinking]);
    const handleInput = useCallback((input, key) => {
        if (!inputFocused)
            return;
        if (key.ctrl && input === 'c') {
            onExit();
            exit();
            return;
        }
        if (key.ctrl && input === 'l') {
            setMessages([]);
            bridge.clearHistory();
            return;
        }
        if (key.escape) {
            if (bridge.hasPendingPermission()) {
                bridge.denyPermission();
                return;
            }
            if (inputValue.length === 0) {
                onExit();
            }
            else {
                setInputValue('');
                setInputCursor(0);
            }
            return;
        }
        if (key.tab) {
            const nextMode = mode === 'auto' ? 'execute' : 'auto';
            setMode(nextMode);
            bridge.setMode(nextMode);
            return;
        }
        if (key.return && !key.shift) {
            handleSubmit();
            return;
        }
        if (key.return && key.shift) {
            const before = inputValue.slice(0, inputCursor);
            const after = inputValue.slice(inputCursor);
            setInputValue(before + '\n' + after);
            setInputCursor(inputCursor + 1);
            setIsMultiLine(true);
            return;
        }
        if (key.upArrow && !isMultiLine) {
            if (messageHistory.length > 0) {
                const newIndex = historyIndex < messageHistory.length - 1 ? historyIndex + 1 : historyIndex;
                setHistoryIndex(newIndex);
                const text = messageHistory[messageHistory.length - 1 - newIndex];
                setInputValue(text);
                setInputCursor(text.length);
            }
            return;
        }
        if (key.downArrow && !isMultiLine) {
            if (historyIndex > 0) {
                const newIndex = historyIndex - 1;
                setHistoryIndex(newIndex);
                const text = messageHistory[messageHistory.length - 1 - newIndex];
                setInputValue(text);
                setInputCursor(text.length);
            }
            else if (historyIndex === 0) {
                setHistoryIndex(-1);
                setInputValue('');
                setInputCursor(0);
            }
            return;
        }
        if (key.upArrow && isMultiLine) {
            if (inputCursor > 0) {
                const lineStart = inputValue.lastIndexOf('\n', inputCursor - 1);
                if (lineStart >= 0) {
                    const prevLineStart = inputValue.lastIndexOf('\n', lineStart - 1);
                    const col = inputCursor - lineStart - 1;
                    const prevLine = inputValue.slice(prevLineStart + 1, lineStart);
                    const newPos = prevLineStart + 1 + Math.min(col, prevLine.length);
                    setInputCursor(newPos >= 0 ? newPos : 0);
                }
                else {
                    setInputCursor(0);
                }
            }
            return;
        }
        if (key.downArrow && isMultiLine) {
            const nextNewline = inputValue.indexOf('\n', inputCursor);
            if (nextNewline >= 0) {
                const lineStart = inputValue.lastIndexOf('\n', inputCursor - 1);
                const col = inputCursor - lineStart - 1;
                const nextLineEnd = inputValue.indexOf('\n', nextNewline + 1);
                const nextLineLen = nextLineEnd >= 0 ? nextLineEnd - nextNewline - 1 : inputValue.length - nextNewline - 1;
                setInputCursor(nextNewline + 1 + Math.min(col, nextLineLen));
            }
            else {
                setInputCursor(inputValue.length);
            }
            return;
        }
        if (key.leftArrow) {
            if (inputCursor > 0)
                setInputCursor(c => c - 1);
            return;
        }
        if (key.rightArrow) {
            if (inputCursor < inputValue.length)
                setInputCursor(c => c + 1);
            return;
        }
        if (key.home) {
            setInputCursor(0);
            return;
        }
        if (key.end) {
            setInputCursor(inputValue.length);
            return;
        }
        if (key.backspace || key.delete) {
            if (key.delete && inputCursor < inputValue.length) {
                setInputValue(prev => prev.slice(0, inputCursor) + prev.slice(inputCursor + 1));
            }
            else if (inputCursor > 0) {
                setInputValue(prev => prev.slice(0, inputCursor - 1) + prev.slice(inputCursor));
                setInputCursor(c => c - 1);
            }
            return;
        }
        if (input && input.length >= 1 && input.charCodeAt(0) >= 32) {
            setInputValue(prev => prev.slice(0, inputCursor) + input + prev.slice(inputCursor));
            setInputCursor(c => c + input.length);
        }
    }, [inputFocused, inputValue, inputCursor, messageHistory, historyIndex, isMultiLine, handleSubmit, onExit, exit, bridge, mode]);
    useInput(handleInput);
    const headerHeight = 1;
    const statusHeight = 1;
    const inputAreaHeight = isMultiLine ? Math.min(inputValue.split('\n').length + 2, 6) : 3;
    const visibleMessages = messages.slice(-Math.min(messages.length, MAX_VISIBLE_MESSAGES));
    return (_jsxs(Box, { flexDirection: "column", height: rows, width: columns, children: [_jsxs(Box, { width: "100%", paddingX: 1, paddingY: 0, backgroundColor: "#0d0d1a", children: [_jsxs(Box, { flexGrow: 1, children: [_jsx(Text, { color: "#00d4aa", bold: true, children: "\u2726 Sentinel Oracle" }), _jsxs(Text, { color: "#22c55e", children: [" \u25CF ", provider] }), _jsx(Text, { dimColor: true, color: "#6b7280", children: " \u25CF GitHub" })] }), _jsxs(Box, { children: [_jsx(Text, { dimColor: true, color: "#6b7280", children: "Mode: " }), _jsx(Text, { color: mode === 'auto' ? '#22c55e' : '#3b82f6', bold: true, children: mode === 'auto' ? 'Auto' : 'Execute' })] })] }), _jsxs(Box, { flexDirection: "column", flexGrow: 1, paddingX: 1, paddingY: 1, children: [visibleMessages.length === 0 && !isThinking && (_jsx(Box, { justifyContent: "center", marginTop: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "Ask Sentinel Oracle anything to get started." }) })), visibleMessages.map((msg) => (_jsx(Message, { message: msg, terminalWidth: columns }, msg.id))), bridge.hasPendingPermission() && (_jsx(Box, { marginLeft: 2, marginTop: 1, paddingX: 1, borderStyle: "round", borderColor: "#f59e0b", children: _jsxs(Box, { flexDirection: "column", children: [_jsx(Text, { color: "#f59e0b", bold: true, children: "\u26A0 Tool requires approval" }), _jsx(Text, { dimColor: true, color: "#6b7280", children: "Enter: Approve \u00B7 Esc: Deny" })] }) })), isThinking && !bridge.hasPendingPermission() && (_jsxs(Box, { marginLeft: 2, marginTop: 1, children: [_jsx(Text, { color: "#a78bfa", children: "\u2726 Thinking" }), _jsx(Text, { color: "#a78bfa", children: "..." })] }))] }), _jsxs(Box, { borderStyle: "round", borderColor: inputFocused ? '#00d4aa' : '#6b7280', marginX: 1, marginBottom: 0, paddingX: 1, children: [_jsx(Box, { flexGrow: 1, flexDirection: "column", children: inputValue.length === 0 && !isMultiLine ? (_jsx(Text, { dimColor: true, color: "#6b7280", children: "Ask Sentinel Oracle anything..." })) : (_jsx(Text, { wrap: "wrap", color: "#e0e0e0", children: inputValue })) }), _jsx(Box, { children: _jsx(Text, { dimColor: true, color: "#6b7280", children: inputValue.length }) })] }), _jsx(StatusBar, { provider: provider, isConnected: true })] }));
}
