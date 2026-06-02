import React from 'react';
interface WelcomeProps {
    onComplete: (result: {
        provider: string;
        apiKey: string;
    } | null) => void;
}
export declare function Welcome({ onComplete }: WelcomeProps): React.JSX.Element;
export {};
