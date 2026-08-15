export interface UserSummary {
  id: string
  username: string
  is_super_admin: boolean
  organization_id: string
  email: string | null
  invitation_pending: boolean
}
