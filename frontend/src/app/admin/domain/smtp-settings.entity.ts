export type SmtpSecurity = 'none' | 'start_tls' | 'tls'

export interface SmtpSettings {
  host: string
  port: number
  username: string
  from_name: string
  from_address: string
  security: SmtpSecurity
  password_set: boolean
}

export interface UpdateSmtpSettings {
  host: string
  port: number
  username: string
  /** Omit (or leave `undefined`) to keep the currently stored password. */
  password?: string
  from_name: string
  from_address: string
  security: SmtpSecurity
}
