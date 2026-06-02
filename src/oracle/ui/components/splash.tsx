import React, { useEffect, useState } from 'react';
import { Box, Text, useAnimation } from 'ink';

interface SplashProps {
  onComplete: () => void;
}

const dots = ['', '.', '..', '...'];

export function Splash({ onComplete }: SplashProps) {
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

  return (
    <Box flexDirection="column" alignItems="center" justifyContent="center" padding={1}>
      <Box marginBottom={1}>
        <Text bold color="#00d4aa">✦ Sentinel Oracle</Text>
      </Box>
      <Box marginBottom={1}>
        <Text dimColor color="#6b7280">AI-Powered Security Assistant</Text>
      </Box>
      <Box marginBottom={1}>
        <Text dimColor color="#6b7280">v4.0.0</Text>
      </Box>
      <Box>
        <Text color="#6b7280">Initializing{dots[dotIndex]}</Text>
      </Box>
      <Box marginTop={1}>
        <Text color="#00d4aa">{spinner}</Text>
      </Box>
    </Box>
  );
}
