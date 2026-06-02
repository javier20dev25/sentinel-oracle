"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Message = Message;
const jsx_runtime_1 = require("react/jsx-runtime");
const ink_1 = require("ink");
function Message({ message, isStreaming, terminalWidth }) {
    switch (message.type) {
        case 'user':
            return ((0, jsx_runtime_1.jsx)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: (0, jsx_runtime_1.jsxs)(ink_1.Box, { borderStyle: "round", borderColor: "#00d4aa", paddingX: 1, paddingY: 0, flexDirection: "column", children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 0, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#00d4aa", bold: true, children: "You" }) }), (0, jsx_runtime_1.jsx)(ink_1.Text, { wrap: "wrap", color: "#e0e0e0", children: message.content })] }) }));
        case 'assistant':
            return ((0, jsx_runtime_1.jsx)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: (0, jsx_runtime_1.jsxs)(ink_1.Box, { marginLeft: 1, paddingX: 1, flexDirection: "column", children: [(0, jsx_runtime_1.jsxs)(ink_1.Box, { marginBottom: 0, children: [(0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#a78bfa", bold: true, children: "\u2726 Sentinel" }), isStreaming && ((0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#a78bfa", children: "\u2588" }))] }), (0, jsx_runtime_1.jsx)(ink_1.Text, { wrap: "wrap", color: "#e0e0e0", children: message.content })] }) }));
        case 'tool':
            return ((0, jsx_runtime_1.jsx)(ink_1.Box, { flexDirection: "column", marginBottom: 1, marginLeft: 2, children: (0, jsx_runtime_1.jsxs)(ink_1.Box, { borderStyle: "single", borderColor: "#f59e0b", paddingX: 1, flexDirection: "column", children: [(0, jsx_runtime_1.jsxs)(ink_1.Box, { children: [(0, jsx_runtime_1.jsxs)(ink_1.Text, { color: "#f59e0b", children: ["\uD83D\uDD27 ", message.toolName || 'tool'] }), (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: message.collapsed ? ' — completed' : '' })] }), !message.collapsed && message.content && ((0, jsx_runtime_1.jsx)(ink_1.Text, { wrap: "wrap", color: "#e0e0e0", children: message.content }))] }) }));
        case 'system':
            return ((0, jsx_runtime_1.jsx)(ink_1.Box, { justifyContent: "center", marginBottom: 1, marginTop: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", italic: true, wrap: "wrap", children: message.content }) }));
        case 'error':
            return ((0, jsx_runtime_1.jsx)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: (0, jsx_runtime_1.jsxs)(ink_1.Box, { borderStyle: "round", borderColor: "#ef4444", paddingX: 1, flexDirection: "column", children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#ef4444", bold: true, children: "\u2716 Error" }) }), (0, jsx_runtime_1.jsx)(ink_1.Text, { wrap: "wrap", color: "#ef4444", children: message.content })] }) }));
        default:
            return null;
    }
}
