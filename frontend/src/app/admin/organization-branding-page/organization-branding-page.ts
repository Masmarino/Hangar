import { ChangeDetectionStrategy, Component } from '@angular/core'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { BrandingSettingsAdmin } from '../branding-settings/branding-settings'

@Component({
  selector: 'app-organization-branding-page',
  standalone: true,
  imports: [OrganizationContextBanner, BrandingSettingsAdmin],
  template: `
    <app-organization-context-banner [narrow]="true" />
    <app-branding-settings />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationBrandingPage {}
