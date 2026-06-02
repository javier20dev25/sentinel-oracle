"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.startUI = startUI;
const jsx_runtime_1 = require("react/jsx-runtime");
const ink_1 = require("ink");
const app_1 = require("./app");
function startUI(options) {
    const instance = (0, ink_1.render)((0, jsx_runtime_1.jsx)(app_1.App, { onExit: (options === null || options === void 0 ? void 0 : options.onExit) || (() => { process.exit(0); }), existingProvider: options === null || options === void 0 ? void 0 : options.provider }));
    return { waitUntilExit: instance.waitUntilExit() };
}
