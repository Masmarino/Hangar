import { ChangeDetectionStrategy, Component } from '@angular/core'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { ApiTokensAdmin } from '../api-tokens/api-tokens'

@Component({
  selector: 'app-organization-tokens-page',
  standalone: true,
  imports: [OrganizationContextBanner, ApiTokensAdmin],
  template: `
    <app-organization-context-banner />
    <app-api-tokens-admin />
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationTokensPage {}
