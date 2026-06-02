import React, { useState, useCallback, useEffect, useRef } from 'react';
import { Splash } from './components/splash';
import { Welcome } from './components/welcome';
import { Chat } from './components/chat';
import { ChatBridge } from './bridge';

type AppPhase = 'loading' | 'setup' | 'ready';

interface AppProps {
  onExit: () => void;
  existingProvider?: string;
}

export function App({ onExit, existingProvider }: AppProps) {
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [provider, setProvider] = useState<string>(existingProvider || '');
  const bridgeRef = useRef<ChatBridge | null>(null);
  const [bridge, setBridge] = useState<ChatBridge | null>(null);

  useEffect(() => {
    const b = new ChatBridge({
      onMessage: () => {},
      onStreamingStart: () => {},
      onStreamingChunk: () => {},
      onStreamingEnd: () => {},
      onToolStart: () => {},
      onToolEnd: () => {},
      onError: () => {},
    });
    bridgeRef.current = b;

    b.initialize().then((configured) => {
      if (configured) {
        const p = b.getProvider();
        setProvider(p);
      }
      setBridge(b);
      setPhase(configured ? 'ready' : 'setup');
    });
  }, []);

  const handleSplashComplete = useCallback(() => {
    // Splash timeout finished; bridge init already drove phase transition
  }, []);

  const handleWelcomeComplete = useCallback((result: { provider: string; apiKey: string } | null) => {
    if (result && bridgeRef.current) {
      bridgeRef.current.configureProvider(result.provider, result.apiKey);
      setProvider(result.provider);
      setPhase('ready');
    } else {
      onExit();
    }
  }, [onExit]);

  if (phase === 'loading') {
    return <Splash onComplete={handleSplashComplete} />;
  }

  if (phase === 'setup') {
    return <Welcome onComplete={handleWelcomeComplete} />;
  }

  if (phase === 'ready' && bridge) {
    return (
      <Chat
        bridge={bridge}
        provider={provider}
        onExit={onExit}
      />
    );
  }

  return null;
}
