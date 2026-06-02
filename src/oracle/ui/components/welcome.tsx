import React, { useState, useCallback, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
import { oauthLogin } from '../oauth.js';
import { setApiKey as storeApiKey, setConfig as storeConfig } from '../../auth.js';

interface WelcomeProps {
  onComplete: (result: { provider: string; apiKey: string } | null) => void;
}

const PROVIDERS = [
  { id: 'gemini', icon: '☀️', name: 'Gemini', desc: 'Google AI models', needsKey: true },
  { id: 'claude', icon: '🧠', name: 'Claude', desc: 'Anthropic AI assistant', needsKey: true },
  { id: 'openai', icon: '⚡', name: 'OpenAI', desc: 'GPT-4 and GPT models', needsKey: true },
  { id: 'ollama', icon: '💻', name: 'Ollama', desc: 'Local open-source models', needsKey: false },
];

type Phase = 'select' | 'input' | 'oauth' | 'done';

export function Welcome({ onComplete }: WelcomeProps) {
  const [phase, setPhase] = useState<Phase>('select');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [chosenProvider, setChosenProvider] = useState<typeof PROVIDERS[0] | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [oauthStatus, setOauthStatus] = useState('');
  const [oauthError, setOauthError] = useState('');

  const finishSetup = useCallback((provider: string, key: string) => {
    storeApiKey(provider, key);
    storeConfig(provider);
    setPhase('done');
    onComplete({ provider, apiKey: key });
  }, [onComplete]);

  const tryOAuth = useCallback(async (prov: typeof PROVIDERS[0]) => {
    setPhase('oauth');
    setOauthStatus(`Opening browser for ${prov.name} authentication...`);
    setOauthError('');

    const token = await oauthLogin(prov.id);
    if (token) {
      finishSetup(prov.id, token);
    } else {
      setOauthStatus('');
      setOauthError('OAuth failed or timed out. You can paste your API key manually.');
      setPhase('input');
    }
  }, [finishSetup]);

  const handleSelectProvider = useCallback((input: string, key: any) => {
    if (key.upArrow) {
      setSelectedIndex(i => (i > 0 ? i - 1 : PROVIDERS.length - 1));
    } else if (key.downArrow) {
      setSelectedIndex(i => (i < PROVIDERS.length - 1 ? i + 1 : 0));
    } else if (key.return) {
      const prov = PROVIDERS[selectedIndex];
      setChosenProvider(prov);
      if (prov.needsKey) {
        tryOAuth(prov);
      } else {
        finishSetup(prov.id, 'local');
      }
    } else if (key.escape) {
      onComplete(null);
    }
  }, [selectedIndex, onComplete, tryOAuth, finishSetup]);

  const handleApiInput = useCallback((input: string, key: any) => {
    if (key.return) {
      if (apiKey.trim().length > 0 && chosenProvider) {
        finishSetup(chosenProvider.id, apiKey.trim());
      }
    } else if (key.escape) {
      setApiKey('');
      setOauthError('');
      setPhase('select');
    } else if (key.backspace || key.delete) {
      setApiKey(prev => prev.slice(0, -1));
    } else if (input && input.length === 1 && input.charCodeAt(0) >= 32) {
      setApiKey(prev => prev + input);
    }
  }, [apiKey, chosenProvider, finishSetup]);

  useInput(
    phase === 'select' ? handleSelectProvider :
    phase === 'input' ? handleApiInput :
    () => {}
  );

  if (phase === 'done') {
    return (
      <Box flexDirection="column" alignItems="center" padding={1}>
        <Box marginBottom={1}>
          <Text color="#22c55e" bold>✓ Connected</Text>
        </Box>
        <Box>
          <Text color="#e0e0e0">{chosenProvider?.icon} </Text>
          <Text bold color="#00d4aa">{chosenProvider?.name}</Text>
        </Box>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" padding={1} paddingX={2}>
      <Box marginBottom={1}>
        <Text bold color="#00d4aa">✦ Sentinel Oracle</Text>
      </Box>
      <Box marginBottom={1}>
        <Text dimColor color="#6b7280">AI Security Assistant</Text>
      </Box>
      <Box marginBottom={1}>
        <Text color="#e0e0e0">Let's connect your AI provider.</Text>
      </Box>

      {phase === 'select' && (
        <Box flexDirection="column" marginBottom={1}>
          {PROVIDERS.map((prov, i) => {
            const isSelected = i === selectedIndex;
            return (
              <Box
                key={prov.id}
                paddingX={1}
                paddingY={0}
                {...(isSelected ? { backgroundColor: '#1a1a2e' } : {})}
              >
                <Text color={isSelected ? '#00d4aa' : '#6b7280'}>
                  {isSelected ? '▸ ' : '  '}
                </Text>
                <Text color="#e0e0e0">
                  {prov.icon} {prov.name}
                </Text>
                <Text dimColor color="#6b7280"> — {prov.desc}</Text>
              </Box>
            );
          })}
          <Box marginTop={1}>
            <Text dimColor color="#6b7280">  ↑↓ Navigate · Enter select · Esc cancel</Text>
          </Box>
        </Box>
      )}

      {phase === 'oauth' && (
        <Box flexDirection="column" marginBottom={1}>
          <Box marginBottom={1}>
            <Text color="#a78bfa">{oauthStatus}</Text>
          </Box>
          <Box>
            <Text dimColor color="#6b7280">Waiting for browser authentication...</Text>
          </Box>
        </Box>
      )}

      {phase === 'input' && (
        <Box flexDirection="column" marginBottom={1}>
          {oauthError && (
            <Box marginBottom={1}>
              <Text color="#ef4444">{oauthError}</Text>
            </Box>
          )}
          <Box marginBottom={1}>
            <Text color="#e0e0e0">Paste your {chosenProvider?.name} API key:</Text>
          </Box>
          <Box
            borderStyle="round"
            borderColor="#00d4aa"
            paddingX={1}
            minWidth={40}
          >
            <Text color="#e0e0e0">
              {apiKey.length === 0
                ? <Text dimColor color="#6b7280">Enter API key...</Text>
                : apiKey.split('').map((ch, i) =>
                    i < apiKey.length - 4 ? '•' : ch
                  ).join('')
              }
            </Text>
          </Box>
          <Box marginTop={1}>
            <Text dimColor color="#6b7280">  Enter confirm · Esc back</Text>
          </Box>
        </Box>
      )}
    </Box>
  );
}
