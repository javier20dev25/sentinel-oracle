import { randomBytes, createHmac, timingSafeEqual } from 'crypto';

export interface SignedChallenge {
    challengeId: string;
    prNumber: number;
    timestamp: number;
    signature: string;
}

let _hmacKey: Buffer | null = null;

export function initHmacKey(seed: Buffer): void {
    _hmacKey = createHmac('sha256', seed).update('sentinel-oracle-hmac-key-v1').digest()
}

export function getHmacKey(): Buffer {
    if (!_hmacKey) {
        _hmacKey = randomBytes(32)
    }
    return _hmacKey
}

export function createChallengeToken(challengeId: string, prNumber: number): SignedChallenge {
    const timestamp = Date.now();
    const payload = `${challengeId}:${prNumber}:${timestamp}`;
    const signature = createHmac('sha256', getHmacKey()).update(payload).digest('hex');
    return { challengeId, prNumber, timestamp, signature };
}

export function verifyChallengeToken(token: SignedChallenge, maxAgeMs: number): boolean {
    const age = Date.now() - token.timestamp;
    if (age > maxAgeMs || age < 0) return false;
    const payload = `${token.challengeId}:${token.prNumber}:${token.timestamp}`;
    const expected = createHmac('sha256', getHmacKey()).update(payload).digest('hex');
    try {
        return timingSafeEqual(Buffer.from(expected), Buffer.from(token.signature));
    } catch {
        return false;
    }
}

export function generateNonce(): string {
    return randomBytes(32).toString('hex');
}
