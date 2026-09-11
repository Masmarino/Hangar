import { TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { of } from 'rxjs'
import { OrganizationsPage } from './organizations-page'
import { OrganizationsList } from '../organizations-list/organizations-list'
import { OrganizationDetail } from '../organization-detail/organization-detail'
import { MeService } from '../../shell/application/me.service'
import { adminProviders } from '../infrastructure/admin.providers'
import { userProviders } from '../../users/infrastructure/user.providers'
import { repositoryProviders } from '../../repositories/infrastructure/repository.providers'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationMembersService } from '../application/organization-members.service'

describe('OrganizationsPage', () => {
  function setup(organizationId: string | null, isSuperAdmin: boolean) {
    TestBed.configureTestingModule({
      imports: [OrganizationsPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...adminProviders,
        ...userProviders,
        ...repositoryProviders,
        { provide: MeService, useValue: { isSuperAdmin: () => isSuperAdmin } },
        {
          provide: OrganizationsService,
          useValue: {
            list: () => of([]),
            get: () => of({ id: organizationId, slug: 'acme', display_name: 'Acme Corp' }),
            getIdentityProvider: () => of({ type: null }),
          },
        },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
        {
          provide: ActivatedRoute,
          useValue: {
            paramMap: of(convertToParamMap(organizationId ? { id: organizationId } : {})),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(OrganizationsPage)
    const httpMock = TestBed.inject(HttpTestingController)
    fixture.detectChanges()
    // gbt-tabs renders every tab eagerly, so all their data fetches fire — not under test here.
    for (const req of httpMock.match(() => true)) {
      req.flush(req.request.responseType === 'blob' ? new Blob() : [])
    }
    fixture.detectChanges()
    return fixture
  }

  it('shows only the organizations list when browsing /admin/organizations (no id)', () => {
    const fixture = setup(null, true)

    expect(fixture.debugElement.query(By.directive(OrganizationsList))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(OrganizationDetail))).toBeNull()
  })

  it('shows both the list and the tabbed detail panel for a super-admin browsing a specific organization', () => {
    const fixture = setup('org-1', true)

    expect(fixture.debugElement.query(By.directive(OrganizationsList))).not.toBeNull()
    expect(fixture.debugElement.query(By.directive(OrganizationDetail))).not.toBeNull()
  })

  it('hides the list for a non-super-admin organization admin — list_organizations is super-admin only', () => {
    const fixture = setup('org-1', false)

    expect(fixture.debugElement.query(By.directive(OrganizationsList))).toBeNull()
    expect(fixture.debugElement.query(By.directive(OrganizationDetail))).not.toBeNull()
  })
})
