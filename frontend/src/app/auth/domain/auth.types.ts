export interface LoginResponse {
  token: string | null
  mfa_token: string | null
  mfa_setup_required: boolean
  mfa_has_totp: boolean
  mfa_has_passkey: boolean
}

export interface LoginOutcome {
  /** `true` when a second factor still needs to be verified or enrolled — see `mfaToken`. */
  mfaRequired: boolean
  mfaToken?: string
  /** `true` when the account has no second factor enrolled yet — a factor is mandatory for every account, so this routes to setup instead of verify. */
  mfaSetupRequired?: boolean
  /** Which factor(s) the account actually has — lets the verify step show only what applies. */
  mfaHasTotp?: boolean
  mfaHasPasskey?: boolean
}

export interface TotpSetupEnrollment {
  secret: string
  otpauth_url: string
}

export interface TotpSetupComplete {
  token: string
  backup_codes: string[]
}

export interface SsoConfig {
  type: 'ldap' | 'oidc' | null
  registration_enabled: boolean
}
