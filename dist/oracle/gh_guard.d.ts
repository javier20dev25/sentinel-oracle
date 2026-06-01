export interface GuardReport {
    passed: boolean;
    machine: {
        status: string;
        detail: string;
    };
    gh: {
        status: string;
        detail: string;
    };
    auth: {
        status: string;
        detail: string;
    };
    remote: {
        status: string;
        detail: string;
    };
    repo: {
        status: string;
        detail: string;
    };
}
export declare function runGuard(): GuardReport;
export declare function ghLogin(): Promise<{
    success: boolean;
    username?: string;
    message?: string;
}>;
export declare function formatGuardReport(report: GuardReport): string;
