import { ChangeDetectionStrategy, Component } from '@angular/core'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { AuditLog } from '../audit-log/audit-log'

@Component({
  selector: 'app-organization-audit-page',
  standalone: true,
  imports: [OrganizationContextBanner, AuditLog],
  template: `
    <app-organization-context-banner />
    <app-audit-log />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationAuditPage {}
