// Bridges the server's base64url-encoded WebAuthn options to the browser's navigator.credentials API, which wants raw ArrayBuffers, and back.

function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4)
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(base64)
  const bytes = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i)
  }
  return bytes.buffer
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function passkeysSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    !!navigator.credentials &&
    typeof navigator.credentials.create === 'function'
  )
}

/** Server-sent registration options (the `public_key` field of the enroll-start response). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function createPasskeyCredential(serverOptions: any): Promise<unknown> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...serverOptions,
    challenge: base64UrlToBuffer(serverOptions.challenge),
    user: { ...serverOptions.user, id: base64UrlToBuffer(serverOptions.user.id) },
    excludeCredentials: (serverOptions.excludeCredentials ?? []).map(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (c: any) => ({ ...c, id: base64UrlToBuffer(c.id) }),
    ),
  }

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64Url(response.attestationObject),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    },
  }
}

/** Server-sent authentication options (the `public_key` field of an mfa/passkey start response). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function getPasskeyAssertion(serverOptions: any): Promise<unknown> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...serverOptions,
    challenge: base64UrlToBuffer(serverOptions.challenge),
    allowCredentials: (serverOptions.allowCredentials ?? []).map(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (c: any) => ({ ...c, id: base64UrlToBuffer(c.id) }),
    ),
  }

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  }
}
