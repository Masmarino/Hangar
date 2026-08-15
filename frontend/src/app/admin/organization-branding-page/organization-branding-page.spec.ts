import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationBrandingPage } from './organization-branding-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { BrandingSettingsAdmin } from '../branding-settings/branding-settings'
import { OrganizationsService } from '../application/organizations.service'
import { BrandingService } from '../application/branding.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationBrandingPage', () => {
  it('renders the context banner and the branding settings', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationBrandingPage],
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
          provide: BrandingService,
          useValue: {
            logoUrl: '/api/branding/logo',
            faviconUrl: '/api/branding/favicon',
            uploadLogo: () => of(undefined),
            resetLogo: () => of(undefined),
            uploadFavicon: () => of(undefined),
            resetFavicon: () => of(undefined),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationBrandingPage)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(BrandingSettingsAdmin))).not.toBeNull()
  })
})
