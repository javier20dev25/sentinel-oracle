import { GitHubApiError, type GitHubClient, type CheckStatus, type BranchProtection } from './client';
import type { DatabaseStore } from '../storage/database';

const REQUIRED_CHECKS = ['build-and-test', 'Sentinel Authorization'];

export interface MonitorResult {
    newPRs: number;
    updatedPRs: number;
    authorizedPRs: number;
}

export type PollPRsErrorCode =
    | 'REPO_NOT_ACCESSIBLE'
    | 'GITHUB_PERMISSION_DENIED'
    | 'GITHUB_RATE_LIMITED'
    | 'GITHUB_AUTH_FAILED'
    | 'GITHUB_UNAVAILABLE'

export class PollPRsError extends Error {
    code: PollPRsErrorCode;
    httpStatus: number;
    owner: string;
    repo: string;
    githubStatus?: number;

    constructor(code: PollPRsErrorCode, message: string, owner: string, repo: string, githubStatus?: number) {
        super(message);
        this.name = 'PollPRsError';
        this.code = code;
        this.httpStatus = code === 'GITHUB_UNAVAILABLE' ? 503 : 424;
        this.owner = owner;
        this.repo = repo;
        this.githubStatus = githubStatus;
    }
}

export async function pollPRs(client: GitHubClient, db: DatabaseStore, defaultBranch = 'main'): Promise<MonitorResult> {
    const result: MonitorResult = { newPRs: 0, updatedPRs: 0, authorizedPRs: 0 };

    let prs;
    try {
        prs = await client.listOpenPRs();
    } catch (err: any) {
        const pollError = classifyPollError(err, client);
        console.error(`[monitor] pollPRs: ${pollError.message}`);
        throw pollError;
    }

    for (const pr of prs) {
        const existing = db.getPRByNumber(pr.number);

        if (!existing) {
            db.upsertPR({
                prNumber: pr.number,
                owner: client.owner,
                repo: client.repo,
                title: pr.title,
                author: pr.author,
                sha: pr.sha,
                ciStatus: 'checking',
                sentinelStatus: 'checking',
                authStatus: 'pending',
                createdAt: Date.now(),
                authorizedAt: null,
                deviceName: null,
                checkRunId: null,
            });
            result.newPRs++;

            const checkRun = await client.createCheckRun(pr.number, pr.sha, 'action_required', 'Sentinel Oracle review required before merge')
            if (checkRun && checkRun.id) {
                db.setCheckRunId(pr.number, checkRun.id)
            }
        }

        if (existing && (existing.sha !== pr.sha || existing.authStatus === 'expired')) {
            db.upsertPR({
                prNumber: pr.number,
                owner: client.owner,
                repo: client.repo,
                title: pr.title,
                author: pr.author,
                sha: pr.sha,
                ciStatus: 'checking',
                sentinelStatus: 'checking',
                authStatus: 'pending',
                createdAt: Date.now(),
                authorizedAt: null,
                deviceName: null,
                checkRunId: null,
            });
            result.updatedPRs++;

            const checkRun = await client.createCheckRun(pr.number, pr.sha, 'action_required', 'Sentinel Oracle review required before merge')
            if (checkRun && checkRun.id) {
                db.setCheckRunId(pr.number, checkRun.id)
            }
        }

        const statuses = await getPRStatuses(client, pr.sha);
        const allPassed = evaluateStatuses(statuses);

        const current = db.getPRByNumber(pr.number);
        if (current) {
            db.upsertPR({
                ...current,
                ciStatus: allPassed ? 'passed' : 'pending',
                sentinelStatus: statuses.sentinel,
                authStatus: current.authStatus === 'expired' ? 'pending' : current.authStatus,
                sha: pr.sha,
            });
        }
    }

    // Check branch protection once per poll cycle
    try {
        const protection = await client.getBranchProtection(defaultBranch);
        checkBranchProtection(protection, db, defaultBranch);
    } catch {}

    return result;
}

function classifyPollError(err: unknown, client: GitHubClient): PollPRsError {
    const ownerRepo = `${client.owner}/${client.repo}`;
    const status = err instanceof GitHubApiError ? err.status : undefined;
    const rawMessage = err instanceof Error ? err.message : String(err);

    if (status === 404 || rawMessage.includes('404')) {
        return new PollPRsError(
            'REPO_NOT_ACCESSIBLE',
            `Repo not accessible: GitHub credentials cannot read ${ownerRepo}. For GitHub App mode, confirm the installation ID belongs to the account that owns this repo and that the installation includes this repository.`,
            client.owner,
            client.repo,
            status,
        );
    }

    if (status === 401) {
        return new PollPRsError(
            'GITHUB_AUTH_FAILED',
            `GitHub authentication failed while listing PRs for ${ownerRepo}. Check the App ID, installation ID, private key, and system clock.`,
            client.owner,
            client.repo,
            status,
        );
    }

    if (status === 403) {
        return new PollPRsError(
            'GITHUB_PERMISSION_DENIED',
            `GitHub denied access while listing PRs for ${ownerRepo}. The App installation needs Pull requests: Read access and must include this repository.`,
            client.owner,
            client.repo,
            status,
        );
    }

    if (status === 429) {
        return new PollPRsError(
            'GITHUB_RATE_LIMITED',
            `GitHub rate limited PR polling for ${ownerRepo}. Retry after the rate limit resets.`,
            client.owner,
            client.repo,
            status,
        );
    }

    return new PollPRsError(
        'GITHUB_UNAVAILABLE',
        `Failed to list PRs for ${ownerRepo}: ${rawMessage}`,
        client.owner,
        client.repo,
        status,
    );
}

async function getPRStatuses(client: GitHubClient, sha: string): Promise<{
    checks: CheckStatus[];
    allRequiredPass: boolean;
    sentinel: string;
}> {
    const [commitStatuses, checkRuns] = await Promise.all([
        client.getCombinedStatus(sha),
        client.getCheckRuns(sha),
    ]);

    const allChecks = [...commitStatuses, ...checkRuns];

    const sentinelCheck = allChecks.find(
        c => c.context === 'Sentinel Authorization'
    );
    const sentinel = sentinelCheck ? sentinelCheck.state : 'missing';

    const required = allChecks.filter(c => REQUIRED_CHECKS.includes(c.context));
    const allRequiredPass = required.length > 0 && required.every(c => c.state === 'success');

    return { checks: allChecks, allRequiredPass, sentinel };
}

function evaluateStatuses(statuses: {
    checks: CheckStatus[];
    allRequiredPass: boolean;
    sentinel: string;
}): boolean {
    return statuses.allRequiredPass;
}

function checkBranchProtection(protection: BranchProtection, db: DatabaseStore, defaultBranch = 'main'): void {
    if (!protection.enabled) {
        db.log('branch_protection_warning', null, `Branch protection is NOT enabled on ${defaultBranch} — merges can bypass Sentinel Oracle`);
        return;
    }

    const issues: string[] = [];
    if (!protection.requiredStatusChecks.includes('Sentinel Authorization')) {
        issues.push('Sentinel Authorization is not in required status checks');
    }
    if (!protection.adminEnforced) {
        issues.push('Admins can bypass required status checks');
    }

    for (const issue of issues) {
        db.log('branch_protection_issue', null, issue);
    }
}
