import { ChangeDetectionStrategy, Component, booleanAttribute, inject, input, signal } from '@angular/core'
import { ActivatedRoute } from '@angular/router'
import { Card } from '@masmarino/gabarit'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationSummary } from '../domain/organization.entity'
import { MeService } from '../../shell/application/me.service'

// A super-admin's writes on these org-scoped admin pages actually target whichever org the
// request's DOMAIN resolves to, not the :id in the URL (see target_organization_id in the
// backend) — the two only always match for a non-super-admin. This banner names the org the
// URL refers to and warns a super-admin it may not be the one actually affected.
@Component({
  selector: 'app-organization-context-banner',
  standalone: true,
  imports: [Card],
  templateUrl: './organization-context-banner.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationContextBanner {
  private readonly route = inject(ActivatedRoute)
  private readonly organizationsService = inject(OrganizationsService)
  private readonly me = inject(MeService)

  readonly isSuperAdmin = this.me.isSuperAdmin
  readonly organization = signal<OrganizationSummary | null>(null)

  // Set by a page whose own content already uses the narrower .form-container (a pure
  // settings form) — the banner must match its sibling's width, or the two visibly
  // misalign on any screen wider than .form-container's own max-width.
  readonly narrow = input(false, { transform: booleanAttribute })

  constructor() {
    const organizationId = this.route.snapshot.paramMap.get('id')
    if (organizationId) {
      this.organizationsService.get(organizationId).subscribe((org) => this.organization.set(org))
    }
  }
}
