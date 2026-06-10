import type { GitHubClient, CheckStatus, PRInfo } from './client';
import type { DatabaseStore } from '../storage/database';
import { promises as dns } from 'dns'

const REQUIRED_CHECKS = ['build-and-test', 'Sentinel Authorization'];

export interface MonitorResult {
    newPRs: number;
    updatedPRs: number;
    authorizedPRs: number;
}

export async function pollPRs(client: GitHubClient, db: DatabaseStore): Promise<MonitorResult> {
    const result: MonitorResult = { newPRs: 0, updatedPRs: 0, authorizedPRs: 0 };

    let prs: PRInfo[];
    try {
        await dns.resolve('api.github.com').catch(() => {})
        prs = await client.listOpenPRs();
    } catch (err) {
        console.error('[monitor] Failed to list PRs:', err instanceof Error ? err.message : String(err))
        return result;
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
            });
            result.newPRs++;
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
            });
            result.updatedPRs++;
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

            if (allPassed && current.authStatus === 'pending') {
                await client.setCommitStatus(pr.sha, 'pending', 'Awaiting physical authorization');
            }
        }
    }

    return result;
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
