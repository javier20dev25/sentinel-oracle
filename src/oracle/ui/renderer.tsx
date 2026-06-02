import React from 'react';
import { render } from 'ink';
import { App } from './app';

export interface RenderOptions {
  provider?: string;
  onExit?: () => void;
}

export function startUI(options?: RenderOptions): { waitUntilExit: Promise<void> } {
  const instance = render(
    <App
      onExit={options?.onExit || (() => { process.exit(0); })}
      existingProvider={options?.provider}
    />
  );
  return { waitUntilExit: instance.waitUntilExit() as Promise<void> };
}
