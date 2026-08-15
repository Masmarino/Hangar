import { ComponentFixture, TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { OrganizationSecurityPage } from './organization-security-page'
import { SecurityLog } from '../security-log/security-log'
import { OrganizationContextBanner } from '../organization-context-banner/organization-context-banner'
import { userProviders } from '../../users/infrastructure/user.providers'
import { repositoryProviders } from '../../repositories/infrastructure/repository.providers'
import { adminProviders } from '../infrastructure/admin.providers'
import { organizationMembersProviders } from '../infrastructure/organization-members.providers'
import { OrganizationsService } from '../application/organizations.service'
import { MeService } from '../../shell/application/me.service'

describe('OrganizationSecurityPage', () => {
  let fixture: ComponentFixture<OrganizationSecurityPage>

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [OrganizationSecurityPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...userProviders,
        ...repositoryProviders,
        ...adminProviders,
        ...organizationMembersProviders,
        {
          provide: ActivatedRoute,
          useValue: {
            paramMap: of(convertToParamMap({ id: 'org-1' })),
            snapshot: { paramMap: convertToParamMap({ id: 'org-1' }) },
          },
        },
        {
          provide: OrganizationsService,
          useValue: { get: () => of({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' }) },
        },
        { provide: MeService, useValue: { isSuperAdmin: () => false } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationSecurityPage)
    fixture.detectChanges()
    const httpMock = TestBed.inject(HttpTestingController)
    httpMock.expectOne((r) => r.url === '/api/audit/events').flush([])
    httpMock.expectOne('/api/organizations/org-1/users').flush([])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()
  })

  it('renders the organization context banner', () => {
    expect(fixture.debugElement.query(By.directive(OrganizationContextBanner))).not.toBeNull()
  })

  it('passes the route organization id down to the security log', () => {
    const securityLog = fixture.debugElement.query(By.directive(SecurityLog))
    expect(securityLog).not.toBeNull()
    expect(securityLog.componentInstance.organizationId()).toBe('org-1')
  })
})
