import React from 'react';
import { Box, Text } from 'ink';

interface StatusBarProps {
  provider: string;
  isConnected: boolean;
}

export function StatusBar({ provider, isConnected }: StatusBarProps) {
  return (
    <Box
      width="100%"
      paddingX={1}
      paddingY={0}
      justifyContent="center"
    >
      <Text dimColor color="#6b7280">
        [Enter] Send  [↑↓] History  [Tab] Commands  [Ctrl+L] Clear  [Ctrl+C] Exit
      </Text>
    </Box>
  );
}
