export interface OrganizationMember {
  id: string
  username: string
  email: string | null
  is_organization_admin: boolean
  invitation_pending: boolean
}
