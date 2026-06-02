import { jsx as _jsx } from "react/jsx-runtime";
import { Box, Text } from 'ink';
export function StatusBar({ provider, isConnected }) {
    return (_jsx(Box, { width: "100%", paddingX: 1, paddingY: 0, justifyContent: "center", children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "[Enter] Send  [\u2191\u2193] History  [Tab] Commands  [Ctrl+L] Clear  [Ctrl+C] Exit" }) }));
}
