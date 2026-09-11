import { ChangeDetectionStrategy, Component, inject } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute } from '@angular/router'
import { map } from 'rxjs'
import { Tab, Tabs } from '@masmarino/gabarit'
import { MeService } from '../../shell/application/me.service'
import { OrganizationsList } from '../organizations-list/organizations-list'
import { OrganizationDetail } from '../organization-detail/organization-detail'
import { BrandingSettingsAdmin } from '../branding-settings/branding-settings'
import { ApiTokensAdmin } from '../api-tokens/api-tokens'
import { AuditLog } from '../audit-log/audit-log'
import { SecurityLog } from '../security-log/security-log'
import { OrganizationMetricsPage } from '../organization-metrics-page/organization-metrics-page'
import { SystemSettingsAdmin } from '../system-settings/system-settings'
import { SmtpSettingsAdmin } from '../smtp-settings/smtp-settings'

// Detail panel only shows once an id is present in the route.
@Component({
  selector: 'app-organizations-page',
  standalone: true,
  imports: [
    OrganizationsList,
    Tabs,
    Tab,
    OrganizationDetail,
    BrandingSettingsAdmin,
    ApiTokensAdmin,
    AuditLog,
    SecurityLog,
    OrganizationMetricsPage,
    SystemSettingsAdmin,
    SmtpSettingsAdmin,
  ],
  templateUrl: './organizations-page.html',
  styleUrl: './organizations-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationsPage {
  private readonly route = inject(ActivatedRoute)

  // list_organizations is super-admin only.
  readonly isSuperAdmin = inject(MeService).isSuperAdmin

  readonly organizationId = toSignal(this.route.paramMap.pipe(map((params) => params.get('id'))), {
    initialValue: null,
  })
}
