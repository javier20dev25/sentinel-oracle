import React from 'react';
import { ChatBridge } from '../bridge.js';
interface ChatProps {
    bridge: ChatBridge;
    provider: string;
    onExit: () => void;
    onRestart: () => void;
}
export declare function Chat({ bridge, provider, onExit, onRestart }: ChatProps): React.JSX.Element;
export {};
