import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Box, Text, useInput, useApp, useWindowSize } from 'ink';
import { execFileSync } from 'child_process';
import { Message, ChatMessage } from './message.js';
import { StatusBar } from './status-bar.js';
import { ChatBridge } from '../bridge.js';

interface ChatProps {
  bridge: ChatBridge;
  provider: string;
  onExit: () => void;
}

const MAX_VISIBLE_MESSAGES = 50;

export function Chat({ bridge, provider, onExit }: ChatProps) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [inputCursor, setInputCursor] = useState(0);
  const [messageHistory, setMessageHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isThinking, setIsThinking] = useState(false);
  const [mode, setMode] = useState<'auto' | 'execute'>('execute');
  const [inputFocused, setInputFocused] = useState(true);
  const [scrollOffset, setScrollOffset] = useState(0);
  const [isMultiLine, setIsMultiLine] = useState(false);

  const addMessage = useCallback((msg: ChatMessage) => {
    setMessages(prev => {
      const next = [...prev, msg];
      if (next.length > MAX_VISIBLE_MESSAGES * 2) {
        return next.slice(next.length - MAX_VISIBLE_MESSAGES);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    bridge.setCallbacks?.({
      onMessage: (msg) => {
        addMessage({
          id: msg.id,
          type: msg.type as ChatMessage['type'],
          content: msg.content,
          timestamp: msg.timestamp,
          toolName: msg.toolName,
          collapsed: msg.collapsed,
          thinking: msg.thinking,
        });
      },
      onStreamingStart: (msgId) => {
        setIsThinking(false);
        setMessages(prev => prev.map(m =>
          m.id === msgId ? { ...m, thinking: false } : m
        ));
      },
      onStreamingChunk: (msgId, chunk) => {
        setMessages(prev => prev.map(m =>
          m.id === msgId ? { ...m, content: m.content + chunk } : m
        ));
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
        setMessages(prev => prev.map(m =>
          (m.toolName === toolName && m.type === 'tool')
            ? { ...m, content: result || 'Completed', collapsed: false }
            : m
        ));
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

  const handleSubmit = useCallback(async () => {
    const text = inputValue.trim();
    if (!text || isThinking) return;

    setMessageHistory(prev => [...prev, text]);
    setHistoryIndex(-1);
    setInputValue('');
    setInputCursor(0);
    setIsMultiLine(false);
    setIsThinking(true);
    setScrollOffset(0);

    try {
      await bridge.sendMessage(text);
    } catch (e: any) {
      addMessage({
        id: `error-${Date.now()}`,
        type: 'error',
        content: e.message || 'An error occurred',
        timestamp: new Date(),
      });
    } finally {
      setIsThinking(false);
    }
  }, [inputValue, addMessage, bridge, isThinking]);

  const pasteText = useCallback(() => {
    try {
      const clipboard = execFileSync('powershell', ['-command', 'Get-Clipboard'], { timeout: 2000, encoding: 'utf-8' });
      if (clipboard) {
        setInputValue(prev => prev.slice(0, inputCursor) + clipboard + prev.slice(inputCursor));
        setInputCursor(c => c + clipboard.length);
      }
    } catch {}
  }, [inputCursor]);

  const handleInput = useCallback((input: string, key: any) => {
    if (!inputFocused) return;

    if (key.ctrl && (input === 'c' || key.name === 'c')) {
      if (key.name === 'c' && !input) return; // ignore empty ctrl+c from some terminals
      onExit();
      exit();
      return;
    }

    if (key.ctrl && (input === 'l' || key.name === 'l')) {
      setMessages([]);
      bridge.clearHistory();
      return;
    }

    if (key.ctrl && key.name === 'v') {
      pasteText();
      return;
    }

    if (key.escape) {
      if (bridge.hasPendingPermission()) {
        bridge.denyPermission();
        return;
      }
      if (inputValue.length === 0) {
        onExit();
      } else {
        setInputValue('');
        setInputCursor(0);
      }
      return;
    }

    if (key.tab) {
      const nextMode: 'auto' | 'execute' = mode === 'auto' ? 'execute' : 'auto';
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
      } else if (historyIndex === 0) {
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
        } else {
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
      } else {
        setInputCursor(inputValue.length);
      }
      return;
    }

    if (key.leftArrow) {
      if (inputCursor > 0) setInputCursor(c => c - 1);
      return;
    }

    if (key.rightArrow) {
      if (inputCursor < inputValue.length) setInputCursor(c => c + 1);
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
      } else if (inputCursor > 0) {
        setInputValue(prev => prev.slice(0, inputCursor - 1) + prev.slice(inputCursor));
        setInputCursor(c => c - 1);
      }
      return;
    }

    if (input && input.length >= 1 && input.charCodeAt(0) >= 32) {
      setInputValue(prev => prev.slice(0, inputCursor) + input + prev.slice(inputCursor));
      setInputCursor(c => c + input.length);
    }
  }, [inputFocused, inputValue, inputCursor, messageHistory, historyIndex, isMultiLine, handleSubmit, onExit, exit, bridge, mode, pasteText]);

  useInput(handleInput);

  const headerHeight = 1;
  const statusHeight = 1;
  const inputAreaHeight = isMultiLine ? Math.min(inputValue.split('\n').length + 2, 6) : 3;

  const visibleMessages = messages.slice(-Math.min(messages.length, MAX_VISIBLE_MESSAGES));

  return (
    <Box flexDirection="column" height={rows} width={columns}>
      <Box
        width="100%"
        paddingX={1}
        paddingY={0}
        backgroundColor="#0d0d1a"
      >
        <Box flexGrow={1}>
          <Text color="#00d4aa" bold>✦ Sentinel Oracle</Text>
          <Text color="#22c55e"> ● {provider}</Text>
          <Text dimColor color="#6b7280"> ● GitHub</Text>
        </Box>
        <Box>
          <Text dimColor color="#6b7280">Mode: </Text>
          <Text color={mode === 'auto' ? '#22c55e' : '#3b82f6'} bold>
            {mode === 'auto' ? 'Auto' : 'Execute'}
          </Text>
        </Box>
      </Box>

      <Box
        flexDirection="column"
        flexGrow={1}
        paddingX={1}
        paddingY={1}
      >
        {visibleMessages.length === 0 && !isThinking && (
          <Box justifyContent="center" marginTop={1}>
            <Text dimColor color="#6b7280">Ask Sentinel Oracle anything to get started.</Text>
          </Box>
        )}

        {visibleMessages.map((msg) => (
          <Message
            key={msg.id}
            message={msg}
            terminalWidth={columns}
          />
        ))}

        {bridge.hasPendingPermission() && (
          <Box marginLeft={2} marginTop={1} paddingX={1}
            borderStyle="round"
            borderColor="#f59e0b"
          >
            <Box flexDirection="column">
              <Text color="#f59e0b" bold>⚠ Tool requires approval</Text>
              <Text dimColor color="#6b7280">Enter: Approve · Esc: Deny</Text>
            </Box>
          </Box>
        )}

        {isThinking && !bridge.hasPendingPermission() && (
          <Box marginLeft={2} marginTop={1}>
            <Text color="#a78bfa">✦ Thinking</Text>
            <Text color="#a78bfa">...</Text>
          </Box>
        )}
      </Box>

      <Box
        borderStyle="round"
        borderColor={inputFocused ? '#00d4aa' : '#6b7280'}
        marginX={1}
        marginBottom={0}
        paddingX={1}
      >
        <Box flexGrow={1} flexDirection="column">
          {inputValue.length === 0 && !isMultiLine ? (
            <Text dimColor color="#6b7280">Ask Sentinel Oracle anything...</Text>
          ) : (
            <Text wrap="wrap" color="#e0e0e0">{inputValue}</Text>
          )}
        </Box>
        <Box>
          <Text dimColor color="#6b7280">{inputValue.length}</Text>
        </Box>
      </Box>

      <StatusBar provider={provider} isConnected={true} />
    </Box>
  );
}