"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.App = App;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const splash_1 = require("./components/splash");
const welcome_1 = require("./components/welcome");
const chat_1 = require("./components/chat");
const bridge_1 = require("./bridge");
function App({ onExit, existingProvider }) {
    const [phase, setPhase] = (0, react_1.useState)('loading');
    const [provider, setProvider] = (0, react_1.useState)(existingProvider || '');
    const bridgeRef = (0, react_1.useRef)(null);
    const [bridge, setBridge] = (0, react_1.useState)(null);
    (0, react_1.useEffect)(() => {
        const b = new bridge_1.ChatBridge({
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
    const handleSplashComplete = (0, react_1.useCallback)(() => {
        // Splash timeout finished; bridge init already drove phase transition
    }, []);
    const handleWelcomeComplete = (0, react_1.useCallback)((result) => {
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
        return (0, jsx_runtime_1.jsx)(splash_1.Splash, { onComplete: handleSplashComplete });
    }
    if (phase === 'setup') {
        return (0, jsx_runtime_1.jsx)(welcome_1.Welcome, { onComplete: handleWelcomeComplete });
    }
    if (phase === 'ready' && bridge) {
        return ((0, jsx_runtime_1.jsx)(chat_1.Chat, { bridge: bridge, provider: provider, onExit: onExit }));
    }
    return null;
}
