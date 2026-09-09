import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationSmtpPage } from './organization-smtp-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { SmtpSettingsAdmin } from '../smtp-settings/smtp-settings'
import { OrganizationsService } from '../application/organizations.service'
import { SmtpSettingsService } from '../application/smtp-settings.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationSmtpPage', () => {
  it('renders the context banner and the smtp settings', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationSmtpPage],
      providers: [
        {
          provide: OrganizationsService,
          useValue: { get: () => of({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' }) },
        },
        { provide: MeService, useValue: { isSuperAdmin: () => false } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { paramMap: convertToParamMap({ id: 'org-1' }) } },
        },
        {
          provide: SmtpSettingsService,
          useValue: {
            get: () => of(null),
            update: () => of(undefined),
            sendTestEmail: () => of(undefined),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationSmtpPage)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(SmtpSettingsAdmin))).not.toBeNull()
  })
})
