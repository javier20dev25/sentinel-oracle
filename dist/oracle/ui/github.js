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
exports.checkGitHubLogin = checkGitHubLogin;
const readline = __importStar(require("readline"));
const child_process_1 = require("child_process");
const pc = __importStar(require("picocolors"));
function hasGh() {
    try {
        (0, child_process_1.execFileSync)('gh', ['--version'], { encoding: 'utf-8', stdio: 'pipe' });
        return true;
    }
    catch (_a) {
        return false;
    }
}
function getGhUsername() {
    try {
        const out = (0, child_process_1.execFileSync)('gh', ['auth', 'status'], { encoding: 'utf-8', stdio: 'pipe' });
        const match = out.match(/Logged in to github\.com(?: as ([^\s]+))?/);
        return match ? (match[1] || 'authenticated') : null;
    }
    catch (_a) {
        return null;
    }
}
function checkGitHubLogin() {
    return __awaiter(this, void 0, void 0, function* () {
        if (!hasGh()) {
            console.log(`  ${pc.dim(pc.gray('  gh CLI not detected — skipping GitHub check'))}\n`);
            return false;
        }
        const username = getGhUsername();
        if (username) {
            console.log(`  ${pc.green('✓')} ${pc.dim('GitHub:')} ${pc.bold(pc.white(`@${username}`))} ${pc.dim('authenticated')}\n`);
            return true;
        }
        const W = 54;
        const top = `${pc.cyan('┌')}${pc.cyan('─'.repeat(W))}${pc.cyan('┐')}`;
        const title = `${pc.cyan('│')}  ${pc.white(pc.bold('GitHub authentication recommended'))}${' '.repeat(W - 37)}${pc.cyan('│')}`;
        const blank = `${pc.cyan('│')}${' '.repeat(W + 2)}${pc.cyan('│')}`;
        const line1 = `${pc.cyan('│')}  ${pc.dim('• PR analysis')}${' '.repeat(W - 15)}${pc.cyan('│')}`;
        const line2 = `${pc.cyan('│')}  ${pc.dim('• repository scanning')}${' '.repeat(W - 24)}${pc.cyan('│')}`;
        const line3 = `${pc.cyan('│')}  ${pc.dim('• issue creation')}${' '.repeat(W - 19)}${pc.cyan('│')}`;
        const bot = `${pc.cyan('└')}${pc.cyan('─'.repeat(W))}${pc.cyan('┘')}`;
        console.log(`  ${top}`);
        console.log(`  ${title}`);
        console.log(`  ${blank}`);
        console.log(`  ${line1}`);
        console.log(`  ${line2}`);
        console.log(`  ${line3}`);
        console.log(`  ${blank}`);
        console.log(`  ${pc.cyan('│')}  ${pc.cyan('[1]')} ${pc.white('Login with GitHub CLI')}${' '.repeat(W - 28)}${pc.cyan('│')}`);
        console.log(`  ${pc.cyan('│')}  ${pc.cyan('[2]')} ${pc.white('Skip (limited functionality)')}${' '.repeat(W - 34)}${pc.cyan('│')}`);
        console.log(`  ${bot}`);
        console.log();
        const answer = yield new Promise((resolve) => {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });
            rl.question(`  ${pc.cyan('Select option')} ${pc.dim('(1-2)')}: `, (a) => {
                rl.close();
                resolve(a.trim());
            });
        });
        if (answer === '1') {
            console.log(`  ${pc.dim('Opening browser for GitHub authentication...')}\n`);
            try {
                (0, child_process_1.execFileSync)('gh', ['auth', 'login', '-w', '-p', 'https'], {
                    encoding: 'utf-8',
                    stdio: 'inherit',
                    timeout: 120000,
                });
                const loggedIn = getGhUsername();
                if (loggedIn) {
                    console.log(`\n  ${pc.green('✓')} ${pc.bold(pc.white(`GitHub authenticated as @${loggedIn}`))}\n`);
                    return true;
                }
                console.log(`\n  ${pc.yellow('GitHub authentication incomplete. Run /gh-login later.\n')}`);
                return false;
            }
            catch (_a) {
                console.log(`\n  ${pc.red('GitHub login failed. You can retry later with /gh-login.\n')}`);
                return false;
            }
        }
        console.log(`  ${pc.yellow('Skipping GitHub setup. Some features limited.')}\n`);
        return false;
    });
}
