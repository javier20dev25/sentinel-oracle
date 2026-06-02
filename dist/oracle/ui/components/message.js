import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Text } from 'ink';
export function Message({ message, isStreaming, terminalWidth }) {
    switch (message.type) {
        case 'user':
            return (_jsx(Box, { flexDirection: "column", marginBottom: 1, children: _jsxs(Box, { borderStyle: "round", borderColor: "#00d4aa", paddingX: 1, paddingY: 0, flexDirection: "column", children: [_jsx(Box, { marginBottom: 0, children: _jsx(Text, { color: "#00d4aa", bold: true, children: "You" }) }), _jsx(Text, { wrap: "wrap", color: "#e0e0e0", children: message.content })] }) }));
        case 'assistant':
            return (_jsx(Box, { flexDirection: "column", marginBottom: 1, children: _jsxs(Box, { marginLeft: 1, paddingX: 1, flexDirection: "column", children: [_jsxs(Box, { marginBottom: 0, children: [_jsx(Text, { color: "#a78bfa", bold: true, children: "\u2726 Sentinel" }), isStreaming && (_jsx(Text, { color: "#a78bfa", children: "\u2588" }))] }), _jsx(Text, { wrap: "wrap", color: "#e0e0e0", children: message.content })] }) }));
        case 'tool':
            return (_jsx(Box, { flexDirection: "column", marginBottom: 1, marginLeft: 2, children: _jsxs(Box, { borderStyle: "single", borderColor: "#f59e0b", paddingX: 1, flexDirection: "column", children: [_jsxs(Box, { children: [_jsxs(Text, { color: "#f59e0b", children: ["\uD83D\uDD27 ", message.toolName || 'tool'] }), _jsx(Text, { dimColor: true, color: "#6b7280", children: message.collapsed ? ' — completed' : '' })] }), !message.collapsed && message.content && (_jsx(Text, { wrap: "wrap", color: "#e0e0e0", children: message.content }))] }) }));
        case 'system':
            return (_jsx(Box, { justifyContent: "center", marginBottom: 1, marginTop: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", italic: true, wrap: "wrap", children: message.content }) }));
        case 'error':
            return (_jsx(Box, { flexDirection: "column", marginBottom: 1, children: _jsxs(Box, { borderStyle: "round", borderColor: "#ef4444", paddingX: 1, flexDirection: "column", children: [_jsx(Box, { children: _jsx(Text, { color: "#ef4444", bold: true, children: "\u2716 Error" }) }), _jsx(Text, { wrap: "wrap", color: "#ef4444", children: message.content })] }) }));
        default:
            return null;
    }
}
