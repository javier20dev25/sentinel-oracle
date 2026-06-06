import { v4 as uuidv4 } from 'uuid';
import { createChallengeToken } from '../crypto/signing';
import type { DatabaseStore } from '../storage/database';

export interface ChallengeResult {
    challengeId: string;
    prNumber: number;
    qrPayload: string;
    expiresAt: number;
    qrUrl: string;
}

export function createAuthChallenge(prNumber: number, db: DatabaseStore, ttlMs: number, serverOrigin: string): ChallengeResult {
    const challengeId = uuidv4();
    const token = createChallengeToken(challengeId, prNumber);
    const expiresAt = Date.now() + ttlMs;

    const qrUrl = `${serverOrigin}/authorize?cid=${challengeId}&pr=${prNumber}`;

    const qrPayload = JSON.stringify({
        v: 1,
        cid: challengeId,
        pr: prNumber,
        ts: token.timestamp,
        sig: token.signature,
        exp: expiresAt,
        url: qrUrl,
    });

    db.storeChallenge(challengeId, prNumber, qrPayload, expiresAt);

    return { challengeId, prNumber, qrPayload, expiresAt, qrUrl };
}
