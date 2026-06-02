import { jsx as _jsx } from "react/jsx-runtime";
import { render } from 'ink';
import { App } from './app.js';
export function startUI(options) {
    const instance = render(_jsx(App, { onExit: (options === null || options === void 0 ? void 0 : options.onExit) || (() => { process.exit(0); }), existingProvider: options === null || options === void 0 ? void 0 : options.provider }));
    return { waitUntilExit: instance.waitUntilExit() };
}
