import { ChangeDetectionStrategy, Component } from '@angular/core'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { SystemSettingsAdmin } from '../system-settings/system-settings'

@Component({
  selector: 'app-organization-settings-page',
  standalone: true,
  imports: [OrganizationContextBanner, SystemSettingsAdmin],
  template: `
    <app-organization-context-banner [narrow]="true" />
    <app-system-settings />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationSettingsPage {}
