"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Splash = Splash;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const ink_1 = require("ink");
const dots = ['', '.', '..', '...'];
function Splash({ onComplete }) {
    const [dotIndex, setDotIndex] = (0, react_1.useState)(0);
    const { frame } = (0, ink_1.useAnimation)({ interval: 120 });
    const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'][frame % 10];
    (0, react_1.useEffect)(() => {
        const dotTimer = setInterval(() => {
            setDotIndex(i => (i + 1) % dots.length);
        }, 400);
        const exitTimer = setTimeout(() => {
            onComplete();
        }, 1500);
        return () => {
            clearInterval(dotTimer);
            clearTimeout(exitTimer);
        };
    }, [onComplete]);
    return ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 1, children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { bold: true, color: "#00d4aa", children: "\u2726 Sentinel Oracle" }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "AI-Powered Security Assistant" }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "v4.0.0" }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { children: (0, jsx_runtime_1.jsxs)(ink_1.Text, { color: "#6b7280", children: ["Initializing", dots[dotIndex]] }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginTop: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#00d4aa", children: spinner }) })] }));
}
