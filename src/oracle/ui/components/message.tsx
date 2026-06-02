import React from 'react';
import { Box, Text } from 'ink';

export interface ChatMessage {
  id: string;
  type: 'user' | 'assistant' | 'tool' | 'system' | 'error';
  content: string;
  timestamp: Date;
  toolName?: string;
  collapsed?: boolean;
  thinking?: boolean;
}

interface MessageProps {
  message: ChatMessage;
  isStreaming?: boolean;
  terminalWidth?: number;
}

export function Message({ message, isStreaming, terminalWidth }: MessageProps) {
  switch (message.type) {
    case 'user':
      return (
        <Box flexDirection="column" marginBottom={1}>
          <Box
            borderStyle="round"
            borderColor="#00d4aa"
            paddingX={1}
            paddingY={0}
            flexDirection="column"
          >
            <Box marginBottom={0}>
              <Text color="#00d4aa" bold>You</Text>
            </Box>
            <Text wrap="wrap" color="#e0e0e0">{message.content}</Text>
          </Box>
        </Box>
      );

    case 'assistant':
      return (
        <Box flexDirection="column" marginBottom={1}>
          <Box marginLeft={1} paddingX={1} flexDirection="column">
            <Box marginBottom={0}>
              <Text color="#a78bfa" bold>✦ Sentinel</Text>
              {isStreaming && (
                <Text color="#a78bfa">█</Text>
              )}
            </Box>
            <Text wrap="wrap" color="#e0e0e0">{message.content}</Text>
          </Box>
        </Box>
      );

    case 'tool':
      return (
        <Box flexDirection="column" marginBottom={1} marginLeft={2}>
          <Box
            borderStyle="single"
            borderColor="#f59e0b"
            paddingX={1}
            flexDirection="column"
          >
            <Box>
              <Text color="#f59e0b">🔧 {message.toolName || 'tool'}</Text>
              <Text dimColor color="#6b7280">
                {message.collapsed ? ' — completed' : ''}
              </Text>
            </Box>
            {!message.collapsed && message.content && (
              <Text wrap="wrap" color="#e0e0e0">{message.content}</Text>
            )}
          </Box>
        </Box>
      );

    case 'system':
      return (
        <Box justifyContent="center" marginBottom={1} marginTop={1}>
          <Text dimColor color="#6b7280" italic wrap="wrap">
            {message.content}
          </Text>
        </Box>
      );

    case 'error':
      return (
        <Box flexDirection="column" marginBottom={1}>
          <Box
            borderStyle="round"
            borderColor="#ef4444"
            paddingX={1}
            flexDirection="column"
          >
            <Box>
              <Text color="#ef4444" bold>✖ Error</Text>
            </Box>
            <Text wrap="wrap" color="#ef4444">{message.content}</Text>
          </Box>
        </Box>
      );

    default:
      return null;
  }
}
