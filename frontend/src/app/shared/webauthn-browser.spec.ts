import { createPasskeyCredential, getPasskeyAssertion, passkeysSupported } from './webauthn-browser'

// A small fake buffer so the round trip through the browser API mock is realistic — a non-empty binary payload, not just an empty ArrayBuffer.
const SAMPLE_BYTES = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252])
const SAMPLE_BASE64URL = 'AQIDBAX6-_w'

function stubCredentials(create: unknown, get: unknown): void {
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { create, get },
  })
}

describe('passkeysSupported', () => {
  afterEach(() => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('is true when navigator.credentials.create exists', () => {
    stubCredentials(
      () => Promise.resolve(null),
      () => Promise.resolve(null),
    )
    expect(passkeysSupported()).toBe(true)
  })

  it('is false when navigator.credentials is missing', () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
    expect(passkeysSupported()).toBe(false)
  })
})

describe('createPasskeyCredential', () => {
  afterEach(() => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('decodes server-sent base64url fields to buffers and re-encodes the browser response', async () => {
    let capturedOptions: CredentialCreationOptions | undefined
    stubCredentials(
      (options: CredentialCreationOptions) => {
        capturedOptions = options
        return Promise.resolve({
          id: 'cred-id',
          type: 'public-key',
          rawId: SAMPLE_BYTES.buffer,
          response: {
            attestationObject: SAMPLE_BYTES.buffer,
            clientDataJSON: SAMPLE_BYTES.buffer,
          },
        })
      },
      () => Promise.resolve(null),
    )

    const result = (await createPasskeyCredential({
      challenge: SAMPLE_BASE64URL,
      rp: { id: 'hangar.example.com', name: 'Hangar' },
      user: { id: SAMPLE_BASE64URL, name: 'florian', displayName: 'florian' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: SAMPLE_BASE64URL }],
    })) as {
      id: string
      rawId: string
      type: string
      response: { attestationObject: string; clientDataJSON: string }
    }

    // The challenge and user id passed to the real browser API must be actual ArrayBuffers, not the base64url strings the server sent.
    const sentPublicKey = capturedOptions!.publicKey!
    expect(sentPublicKey.challenge instanceof ArrayBuffer).toBe(true)
    expect(new Uint8Array(sentPublicKey.challenge as ArrayBuffer)).toEqual(SAMPLE_BYTES)
    expect(sentPublicKey.user.id instanceof ArrayBuffer).toBe(true)
    expect(sentPublicKey.excludeCredentials?.[0].id instanceof ArrayBuffer).toBe(true)

    // The credential handed back to the server must be base64url strings again.
    expect(result.rawId).toBe(SAMPLE_BASE64URL)
    expect(result.response.attestationObject).toBe(SAMPLE_BASE64URL)
    expect(result.response.clientDataJSON).toBe(SAMPLE_BASE64URL)
    expect(result.id).toBe('cred-id')
    expect(result.type).toBe('public-key')
  })
})

describe('getPasskeyAssertion', () => {
  afterEach(() => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined })
  })

  it('decodes server-sent base64url fields and re-encodes the assertion response', async () => {
    let capturedOptions: CredentialRequestOptions | undefined
    stubCredentials(
      () => Promise.resolve(null),
      (options: CredentialRequestOptions) => {
        capturedOptions = options
        return Promise.resolve({
          id: 'cred-id',
          type: 'public-key',
          rawId: SAMPLE_BYTES.buffer,
          response: {
            authenticatorData: SAMPLE_BYTES.buffer,
            clientDataJSON: SAMPLE_BYTES.buffer,
            signature: SAMPLE_BYTES.buffer,
            userHandle: null,
          },
        })
      },
    )

    const result = (await getPasskeyAssertion({
      challenge: SAMPLE_BASE64URL,
      rpId: 'hangar.example.com',
      allowCredentials: [{ type: 'public-key', id: SAMPLE_BASE64URL }],
      userVerification: 'required',
    })) as {
      rawId: string
      response: {
        authenticatorData: string
        clientDataJSON: string
        signature: string
        userHandle: string | null
      }
    }

    const sentPublicKey = capturedOptions!.publicKey!
    expect(sentPublicKey.challenge instanceof ArrayBuffer).toBe(true)
    expect(sentPublicKey.allowCredentials?.[0].id instanceof ArrayBuffer).toBe(true)

    expect(result.rawId).toBe(SAMPLE_BASE64URL)
    expect(result.response.authenticatorData).toBe(SAMPLE_BASE64URL)
    expect(result.response.signature).toBe(SAMPLE_BASE64URL)
    expect(result.response.userHandle).toBeNull()
  })
})
