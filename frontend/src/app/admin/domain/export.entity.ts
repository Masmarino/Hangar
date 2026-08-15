export interface ImportReport {
  users_created: number
  repositories_created: number
  permissions_granted: number
  invited: string[]
  skipped_no_email: string[]
  failed: string[]
}
