import React from 'react';
import { ChatBridge } from '../bridge.js';
interface ChatProps {
    bridge: ChatBridge;
    provider: string;
    onExit: () => void;
}
export declare function Chat({ bridge, provider, onExit }: ChatProps): React.JSX.Element;
export {};
