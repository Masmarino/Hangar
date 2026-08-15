import { RepositoryFormat } from './repository.entity'

export type Role = 'read' | 'write' | 'admin'

export const ROLE_OPTIONS: { value: Role; label: string }[] = [
  { value: 'read', label: 'read' },
  { value: 'write', label: 'write' },
  { value: 'admin', label: 'admin' },
]

export interface PermissionEntry {
  user_id: string
  username: string
  role: Role
}

// Narrower than a full user record — the backend never sends is_super_admin here.
export interface UserLookup {
  id: string
  username: string
}

export interface UserPermissionEntry {
  repository_id: string
  repository_name: string
  format: RepositoryFormat
  role: Role
}
