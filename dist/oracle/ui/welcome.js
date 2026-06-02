"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.welcomeSequence = welcomeSequence;
const pc = __importStar(require("picocolors"));
const auth_1 = require("../auth");
const github_1 = require("./github");
const wizard_1 = require("./wizard");
function clearScreen() {
    process.stdout.write('\x1Bc');
}
function renderHeader() {
    const W = 60;
    const top = `${pc.cyan('╔')}${pc.cyan('═'.repeat(W))}${pc.cyan('╗')}`;
    const line1 = `${pc.cyan('║')}  ${pc.bold(pc.cyan('Sentinel Oracle'))}${' '.repeat(W - 20)}${pc.cyan('║')}`;
    const line2 = `${pc.cyan('║')}  ${pc.dim('AI-Powered Security Assistant')}${' '.repeat(W - 34)}${pc.cyan('║')}`;
    const line3 = `${pc.cyan('║')}  ${pc.dim('CLI 2  ·  Multi-Provider  ·  Tool-Orchestrated')}${' '.repeat(W - 50)}${pc.cyan('║')}`;
    const bot = `${pc.cyan('╚')}${pc.cyan('═'.repeat(W))}${pc.cyan('╝')}`;
    console.log(`\n  ${top}\n  ${line1}\n  ${line2}\n  ${line3}\n  ${bot}\n`);
}
function renderSummary(provider, model) {
    console.log(`  ${pc.dim('─'.repeat(60))}`);
    if (provider) {
        console.log(`  ${pc.green('✓')} ${pc.dim('Provider:')} ${pc.bold(pc.white(provider))}${model ? pc.dim(` | Model: ${model}`) : ''}`);
    }
    else {
        console.log(`  ${pc.yellow('!')} ${pc.dim('No provider configured — limited functionality')}`);
    }
    console.log(`  ${pc.dim('─'.repeat(60))}\n`);
}
function renderTips() {
    console.log(`  ${pc.bold(pc.white('Getting Started'))}\n`);
    const tips = [
        `${pc.cyan('•')} ${pc.dim('"analyze package axios"')}`,
        `${pc.cyan('•')} ${pc.dim('"review a GitHub PR"')}`,
        `${pc.cyan('•')} ${pc.dim('"explain CVE-2024-3094"')}`,
        `${pc.cyan('•')} ${pc.dim('"audit dependencies"')}`,
    ];
    tips.forEach(t => console.log(`  ${t}`));
    console.log();
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function welcomeSequence() {
    return __awaiter(this, void 0, void 0, function* () {
        clearScreen();
        renderHeader();
        yield (0, github_1.checkGitHubLogin)();
        const config = (0, auth_1.getConfig)();
        let provider = config.provider;
        if (!provider) {
            const result = yield (0, wizard_1.providerWizard)();
            if (result) {
                provider = result.provider;
            }
        }
        renderSummary(provider, config.model);
        renderTips();
        yield sleep(1500);
    });
}
