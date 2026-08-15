import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { OrganizationMetricsPage } from './organization-metrics-page'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { adminProviders } from '../infrastructure/admin.providers'
import { OrganizationsService } from '../application/organizations.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationMetricsPage', () => {
  it('renders the context banner, the stats cards, and the usage metrics component', () => {
    TestBed.configureTestingModule({
      imports: [OrganizationMetricsPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...adminProviders,
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { paramMap: convertToParamMap({ id: 'org-1' }) } },
        },
        {
          provide: OrganizationsService,
          useValue: { get: () => of({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' }) },
        },
        { provide: MeService, useValue: { isSuperAdmin: () => false } },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationMetricsPage)
    const httpMock = TestBed.inject(HttpTestingController)
    fixture.detectChanges()
    httpMock
      .expectOne('/api/admin/stats')
      .flush({ total_users: 2, total_repositories: 1, total_active_permissions: 0 })
    httpMock.expectOne('/api/admin/metrics').flush([])
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('Utilisateurs')
    expect(text).toContain('2')
    expect(text).toContain('Dépôts')
    expect(text).toContain('Permissions actives')
  })
})
