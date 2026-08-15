export interface ApiToken {
  id: string
  label: string
  created_at: string
  last_used_at: string | null
}

export interface CreatedApiToken {
  id: string
  token: string
}
