import { describe, it, expect } from 'vitest'
import { encrypt, decrypt } from '../../src/storage/encryption'
import { randomBytes } from 'crypto'

describe('encrypt/decrypt', () => {
  const key = randomBytes(32)

  it('encrypts and decrypts a string', () => {
    const plaintext = 'hello world'
    const ciphertext = encrypt(plaintext, key)
    expect(ciphertext).toBeTruthy()
    expect(ciphertext).not.toBe(plaintext)
    const decrypted = decrypt(ciphertext, key)
    expect(decrypted).toBe(plaintext)
  })

  it('produces different ciphertext for same plaintext (different IV)', () => {
    const plaintext = 'same text'
    const a = encrypt(plaintext, key)
    const b = encrypt(plaintext, key)
    expect(a).not.toBe(b)
  })

  it('handles empty string', () => {
    const ciphertext = encrypt('', key)
    const decrypted = decrypt(ciphertext, key)
    expect(decrypted).toBe('')
  })

  it('handles special characters', () => {
    const plaintext = '¡Hola! 你好 @#$% 🎉'
    const ciphertext = encrypt(plaintext, key)
    const decrypted = decrypt(ciphertext, key)
    expect(decrypted).toBe(plaintext)
  })

  it('throws on wrong key', () => {
    const plaintext = 'secret data'
    const ciphertext = encrypt(plaintext, key)
    const wrongKey = randomBytes(32)
    expect(() => decrypt(ciphertext, wrongKey)).toThrow()
  })

  it('throws on malformed ciphertext', () => {
    expect(() => decrypt('invalid', key)).toThrow()
    expect(() => decrypt('a:b', key)).toThrow()
    expect(() => decrypt('a:b:c:d', key)).toThrow()
  })
})
