import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationSettingsPage } from './organization-settings-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { SystemSettingsAdmin } from '../system-settings/system-settings'
import { OrganizationsService } from '../application/organizations.service'
import { SystemSettingsService } from '../application/system-settings.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationSettingsPage', () => {
  it('renders the context banner and the system settings', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationSettingsPage],
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
          provide: SystemSettingsService,
          useValue: {
            get: () =>
              of({
                max_login_attempts: 10,
                login_attempt_window_seconds: 300,
                session_ttl_hours: 12,
                registration_enabled: true,
              }),
            update: () => of(undefined),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationSettingsPage)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(SystemSettingsAdmin))).not.toBeNull()
  })
})
