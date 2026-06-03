import React, { useState, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import { execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { oauthLogin } from '../oauth.js';
import { setApiKey as storeApiKey, setConfig as storeConfig } from '../../auth.js';
import { QwenProvider } from '../../providers/qwen.js';

interface WelcomeProps {
  onComplete: (result: { provider: string; apiKey: string } | null) => void;
}

const PROVIDERS = [
  { id: 'gemini', icon: '☀️', name: 'Gemini', desc: 'Google AI models', needsKey: true },
  { id: 'claude', icon: '🧠', name: 'Claude', desc: 'Anthropic AI assistant', needsKey: true },
  { id: 'openai', icon: '⚡', name: 'OpenAI', desc: 'GPT-4 and GPT models', needsKey: true },
  { id: 'ollama', icon: '💻', name: 'Ollama', desc: 'Local open-source models', needsKey: false },
  { id: 'qwen', icon: '🔌', name: 'Qwen', desc: 'Local 1.5B model (download on first use)', needsKey: false },
];

type Phase = 'select' | 'input' | 'oauth' | 'downloading' | 'done';

export function Welcome({ onComplete }: WelcomeProps) {
  const [phase, setPhase] = useState<Phase>('select');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [chosenProvider, setChosenProvider] = useState<typeof PROVIDERS[0] | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [oauthStatus, setOauthStatus] = useState('');
  const [oauthError, setOauthError] = useState('');
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [downloadTotal, setDownloadTotal] = useState(0);

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
      } else if (prov.id === 'qwen') {
        // Check if model exists
        const qwen = new QwenProvider();
        if (qwen.isDownloaded()) {
          finishSetup(prov.id, 'local');
        } else {
          startDownload(qwen);
        }
      } else {
        finishSetup(prov.id, 'local');
      }
    } else if (key.escape) {
      onComplete(null);
    }
  }, [selectedIndex, onComplete, tryOAuth, finishSetup]);

  const startDownload = useCallback(async (qwen: QwenProvider) => {
    setPhase('downloading');
    try {
      await qwen.download((downloaded, total) => {
        setDownloadProgress(downloaded);
        setDownloadTotal(total);
      });
      finishSetup('qwen', 'local');
    } catch (e: any) {
      setPhase('select');
    }
  }, [finishSetup]);

  const pasteFromClipboard = useCallback(() => {
    try {
      const clipboard = execFileSync('powershell', ['-command', 'Get-Clipboard'], { timeout: 2000, encoding: 'utf-8' });
      if (clipboard) setApiKey(prev => prev + clipboard.trim());
    } catch {}
  }, []);

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
    } else if (key.ctrl && key.name === 'v') {
      pasteFromClipboard();
    } else if (input && input.charCodeAt(0) >= 32) {
      setApiKey(prev => prev + input);
    }
  }, [apiKey, chosenProvider, finishSetup, pasteFromClipboard]);

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

      {phase === 'downloading' && (
        <Box flexDirection="column" marginBottom={1}>
          <Box marginBottom={1}>
            <Text color="#a78bfa">✦ Downloading Qwen 2.5 1.5B model...</Text>
          </Box>
          <Box>
            <Text dimColor color="#6b7280">
              {downloadTotal > 0
                ? `${(downloadProgress / 1024 / 1024).toFixed(1)} MB / ${(downloadTotal / 1024 / 1024).toFixed(1)} MB`
                : 'Starting download...'}
            </Text>
          </Box>
          {downloadTotal > 0 && (
            <Box marginTop={1} width={40}>
              <Box width={Math.round(40 * downloadProgress / downloadTotal)}>
                <Text color="#00d4aa">{'█'.repeat(Math.max(1, Math.round(40 * downloadProgress / downloadTotal)))}</Text>
              </Box>
            </Box>
          )}
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
