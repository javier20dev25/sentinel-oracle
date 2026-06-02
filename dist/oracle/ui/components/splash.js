import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { Box, Text, useAnimation } from 'ink';
const dots = ['', '.', '..', '...'];
export function Splash({ onComplete }) {
    const [dotIndex, setDotIndex] = useState(0);
    const { frame } = useAnimation({ interval: 120 });
    const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'][frame % 10];
    useEffect(() => {
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
    return (_jsxs(Box, { flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 1, children: [_jsx(Box, { marginBottom: 1, children: _jsx(Text, { bold: true, color: "#00d4aa", children: "\u2726 Sentinel Oracle" }) }), _jsx(Box, { marginBottom: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "AI-Powered Security Assistant" }) }), _jsx(Box, { marginBottom: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "v4.0.0" }) }), _jsx(Box, { children: _jsxs(Text, { color: "#6b7280", children: ["Initializing", dots[dotIndex]] }) }), _jsx(Box, { marginTop: 1, children: _jsx(Text, { color: "#00d4aa", children: spinner }) })] }));
}
