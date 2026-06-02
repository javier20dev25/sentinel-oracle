import { jsx as _jsx } from "react/jsx-runtime";
import { useState, useCallback, useEffect, useRef } from 'react';
import { Splash } from './components/splash.js';
import { Welcome } from './components/welcome.js';
import { Chat } from './components/chat.js';
import { ChatBridge } from './bridge.js';
export function App({ onExit, existingProvider }) {
    const [phase, setPhase] = useState('loading');
    const [provider, setProvider] = useState(existingProvider || '');
    const bridgeRef = useRef(null);
    const [bridge, setBridge] = useState(null);
    useEffect(() => {
        const b = new ChatBridge({
            onMessage: () => { },
            onStreamingStart: () => { },
            onStreamingChunk: () => { },
            onStreamingEnd: () => { },
            onToolStart: () => { },
            onToolEnd: () => { },
            onError: () => { },
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
    const handleRestart = useCallback(() => {
        setPhase('setup');
        setProvider('');
        setBridge(null);
    }, []);
    const handleWelcomeComplete = useCallback((result) => {
        if (result && bridgeRef.current) {
            bridgeRef.current.configureProvider(result.provider, result.apiKey);
            setProvider(result.provider);
            setPhase('ready');
        }
        else {
            onExit();
        }
    }, [onExit]);
    if (phase === 'loading') {
        return _jsx(Splash, { onComplete: handleSplashComplete });
    }
    if (phase === 'setup') {
        return _jsx(Welcome, { onComplete: handleWelcomeComplete });
    }
    if (phase === 'ready' && bridge) {
        return (_jsx(Chat, { bridge: bridge, provider: provider, onExit: onExit, onRestart: handleRestart }));
    }
    return null;
}
