import { ChangeDetectionStrategy, Component, inject } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute } from '@angular/router'
import { map } from 'rxjs'
import { SecurityLog } from '../security-log/security-log'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'

// SecurityLog needs an explicit organizationId, and a routed page has no parent template to
// bind it from — this reads the route's own `:id` and passes it down to SecurityLog.
@Component({
  selector: 'app-organization-security-page',
  standalone: true,
  imports: [SecurityLog, OrganizationContextBanner],
  template: `
    <app-organization-context-banner />
    <app-security-log [organizationId]="organizationId()" />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationSecurityPage {
  private readonly route = inject(ActivatedRoute)

  readonly organizationId = toSignal(
    this.route.paramMap.pipe(map((params) => params.get('id')!)),
    { requireSync: true },
  )
}
