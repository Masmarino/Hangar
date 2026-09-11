import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { OrganizationMetricsPage } from './organization-metrics-page'
import { adminProviders } from '../infrastructure/admin.providers'

function render(organizationId?: string) {
  TestBed.configureTestingModule({
    imports: [OrganizationMetricsPage],
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(OrganizationMetricsPage)
  const httpMock = TestBed.inject(HttpTestingController)
  if (organizationId !== undefined) {
    fixture.componentRef.setInput('organizationId', organizationId)
  }
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('OrganizationMetricsPage', () => {
  it('renders the stats cards in a grid and the usage metrics component', () => {
    const { fixture, httpMock } = render('org-1')
    httpMock
      .expectOne((r) => r.url === '/api/admin/stats' && r.params.get('organization_id') === 'org-1')
      .flush({ total_users: 2, total_repositories: 1, total_active_permissions: 0 })
    httpMock
      .expectOne(
        (r) => r.url === '/api/admin/metrics' && r.params.get('organization_id') === 'org-1',
      )
      .flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.querySelector('.stats-grid')).not.toBeNull()
    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('Utilisateurs')
    expect(text).toContain('2')
    expect(text).toContain('Dépôts')
    expect(text).toContain('Permissions actives')
  })

  it('re-fetches stats when organizationId changes to a different organization', () => {
    const { fixture, httpMock } = render('org-1')
    httpMock
      .expectOne((r) => r.params.get('organization_id') === 'org-1' && r.url === '/api/admin/stats')
      .flush({ total_users: 2, total_repositories: 1, total_active_permissions: 0 })
    httpMock.expectOne((r) => r.url === '/api/admin/metrics').flush([])
    fixture.detectChanges()

    fixture.componentRef.setInput('organizationId', 'org-2')
    fixture.detectChanges()
    httpMock
      .expectOne((r) => r.params.get('organization_id') === 'org-2' && r.url === '/api/admin/stats')
      .flush({ total_users: 5, total_repositories: 3, total_active_permissions: 1 })
    httpMock
      .expectOne(
        (r) => r.params.get('organization_id') === 'org-2' && r.url === '/api/admin/metrics',
      )
      .flush([])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('5')
  })
})
