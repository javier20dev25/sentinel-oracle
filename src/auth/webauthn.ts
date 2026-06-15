import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server'
import type { AuthenticatorTransportFuture } from '@simplewebauthn/types'
import { generateNonce } from '../crypto/signing'
import type { DatabaseStore } from '../storage/database'

const RP_NAME = 'Sentinel Oracle'

export interface WebAuthnRegistration {
  options: PublicKeyCredentialCreationOptions
  challenge: string
}

export interface WebAuthnAssertion {
  options: PublicKeyCredentialRequestOptions
  challenge: string
}

export function getRpId(config: { rpId: string; serverOrigin: string }): string {
  if (config.rpId) return config.rpId
  try {
    return new URL(config.serverOrigin).hostname
  } catch {
    return 'localhost'
  }
}

export async function generateRegistration(
  deviceName: string,
  db: DatabaseStore,
  origin: string,
  rpId: string,
): Promise<WebAuthnRegistration> {
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userName: deviceName,
    userDisplayName: deviceName,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
  })

  db.setConfig(`webauthn_challenge_${options.challenge}`, JSON.stringify({
    challenge: options.challenge,
    deviceName,
    createdAt: Date.now(),
  }))

  return { options: options as unknown as PublicKeyCredentialCreationOptions, challenge: options.challenge }
}

export async function verifyRegistration(
  credential: unknown,
  expectedChallenge: string,
  db: DatabaseStore,
  origin: string,
  rpId: string,
): Promise<{ verified: boolean; credentialId: string; publicKey: string; counter: number; transports: string[] }> {
  const storedJson = db.getConfig(`webauthn_challenge_${expectedChallenge}`)
  if (!storedJson) return { verified: false, credentialId: '', publicKey: '', counter: 0, transports: [] }

  db.setConfig(`webauthn_challenge_${expectedChallenge}`, '')

  const verification = await verifyRegistrationResponse({
    response: credential as any,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
  })

  if (!verification.verified || !verification.registrationInfo) {
    return { verified: false, credentialId: '', publicKey: '', counter: 0, transports: [] }
  }

  const info = verification.registrationInfo
  const transports = (credential as any)?.response?.transports || []

  return {
    verified: true,
    credentialId: info.credential.id,
    publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
    counter: info.credential.counter,
    transports,
  }
}

export async function generateAssertion(
  db: DatabaseStore,
  origin: string,
  rpId: string,
  prNumber?: number,
): Promise<WebAuthnAssertion & { prNumber?: number }> {
  const devices = db.listDevices()
  const allowCredentials = devices.length > 0
    ? devices.map(d => ({
        id: d.credentialId,
        transports: JSON.parse(d.transports) as AuthenticatorTransportFuture[],
      }))
    : undefined

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials,
    userVerification: 'required',
  })

  db.setConfig(`webauthn_assertion_${options.challenge}`, JSON.stringify({
    challenge: options.challenge,
    createdAt: Date.now(),
    prNumber: prNumber || null,
  }))

  return { options: options as unknown as PublicKeyCredentialRequestOptions, challenge: options.challenge, prNumber }
}

export async function verifyAssertion(
  credential: unknown,
  expectedChallenge: string,
  db: DatabaseStore,
  origin: string,
  rpId: string,
  expectedPrNumber?: number,
): Promise<{ verified: boolean; credentialId: string; prNumber?: number; error?: string }> {
  const storedJson = db.getConfig(`webauthn_assertion_${expectedChallenge}`)
  if (!storedJson) return { verified: false, credentialId: '', error: 'Challenge not found or expired. Please try again.' }

  const stored = JSON.parse(storedJson)
  const originalPrNumber: number | undefined = stored.prNumber || undefined
  db.setConfig(`webauthn_assertion_${expectedChallenge}`, '')

  if (expectedPrNumber !== undefined && originalPrNumber !== expectedPrNumber) {
    return { verified: false, credentialId: '', error: 'PR number mismatch in challenge.' }
  }

  const credentialData = credential as any
  const credentialId = credentialData?.id || ''
  const device = db.getDeviceByCredentialId(credentialId)
  if (!device) return { verified: false, credentialId: '', error: `Device not found for credential ${credentialId.slice(0,12)}...` }

  const receivedOrigin = credentialData?.response?.clientDataJSON
    ? (() => { try { return JSON.parse(Buffer.from(credentialData.response.clientDataJSON, 'base64url').toString()).origin } catch { return '?' } })()
    : '?'

  const verification = await verifyAuthenticationResponse({
    response: credentialData,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
    credential: {
      id: device.credentialId,
      publicKey: Buffer.from(device.publicKey, 'base64url'),
      counter: device.counter,
      transports: JSON.parse(device.transports) as AuthenticatorTransportFuture[],
    },
  })

  console.log('[webauthn] verifyAssertion: expectedOrigin=%s receivedOrigin=%s rpId=%s verified=%s', origin, receivedOrigin, rpId, verification.verified)

  if (!verification.verified) {
    return { verified: false, credentialId: '', error: `WebAuthn assertion verification failed. expectedOrigin="${origin}" receivedOrigin="${receivedOrigin}" rpId="${rpId}"` }
  }

  db.updateDeviceCounter(device.credentialId, verification.authenticationInfo.newCounter)

  return { verified: true, credentialId, prNumber: originalPrNumber }
}
