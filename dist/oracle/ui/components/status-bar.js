"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatusBar = StatusBar;
const jsx_runtime_1 = require("react/jsx-runtime");
const ink_1 = require("ink");
function StatusBar({ provider, isConnected }) {
    return ((0, jsx_runtime_1.jsx)(ink_1.Box, { width: "100%", paddingX: 1, paddingY: 0, justifyContent: "center", children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "[Enter] Send  [\u2191\u2193] History  [Tab] Commands  [Ctrl+L] Clear  [Ctrl+C] Exit" }) }));
}
