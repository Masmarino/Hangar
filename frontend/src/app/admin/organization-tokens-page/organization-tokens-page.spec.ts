import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationTokensPage } from './organization-tokens-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { ApiTokensAdmin } from '../api-tokens/api-tokens'
import { OrganizationsService } from '../application/organizations.service'
import { AdminApiTokensService } from '../application/admin-api-tokens.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationTokensPage', () => {
  it('renders the context banner and the api tokens settings', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationTokensPage],
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
        { provide: AdminApiTokensService, useValue: { list: () => of([]), revoke: () => of(undefined) } },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationTokensPage)
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(ApiTokensAdmin))).not.toBeNull()
  })
})
