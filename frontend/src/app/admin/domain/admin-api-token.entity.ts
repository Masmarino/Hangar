export interface AdminApiToken {
  id: string
  user_id: string
  username: string
  label: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}
