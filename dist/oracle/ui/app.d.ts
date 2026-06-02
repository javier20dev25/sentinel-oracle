import React from 'react';
interface AppProps {
    onExit: () => void;
    existingProvider?: string;
}
export declare function App({ onExit, existingProvider }: AppProps): React.JSX.Element | null;
export {};
