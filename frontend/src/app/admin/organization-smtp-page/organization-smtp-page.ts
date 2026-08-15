import { ChangeDetectionStrategy, Component } from '@angular/core'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { SmtpSettingsAdmin } from '../smtp-settings/smtp-settings'

@Component({
  selector: 'app-organization-smtp-page',
  standalone: true,
  imports: [OrganizationContextBanner, SmtpSettingsAdmin],
  template: `
    <app-organization-context-banner [narrow]="true" />
    <app-smtp-settings />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationSmtpPage {}
