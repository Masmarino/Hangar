import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpOrganizationMembersAdapter } from './http-organization-members.adapter'

describe('HttpOrganizationMembersAdapter', () => {
  let adapter: HttpOrganizationMembersAdapter
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpOrganizationMembersAdapter],
    })
    adapter = TestBed.inject(HttpOrganizationMembersAdapter)
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('lists members of an organization', () => {
    let result: unknown
    adapter.list('org-1').subscribe((r) => (result = r))

    const request = httpMock.expectOne('/api/organizations/org-1/users')
    expect(request.request.method).toBe('GET')
    request.flush([
      {
        id: 'user-1',
        username: 'florian',
        email: 'florian@example.com',
        is_organization_admin: false,
        invitation_pending: true,
      },
    ])

    expect(result).toEqual([
      {
        id: 'user-1',
        username: 'florian',
        email: 'florian@example.com',
        is_organization_admin: false,
        invitation_pending: true,
      },
    ])
  })

  it('invites a new member into an organization', () => {
    adapter.invite('org-1', 'florian', 'florian@example.com', true).subscribe()

    const request = httpMock.expectOne('/api/organizations/org-1/users')
    expect(request.request.method).toBe('POST')
    expect(request.request.body).toEqual({
      username: 'florian',
      email: 'florian@example.com',
      is_organization_admin: true,
    })
    request.flush({
      id: 'user-1',
      username: 'florian',
      email: 'florian@example.com',
      is_organization_admin: true,
      invitation_pending: true,
    })
  })

  it("sets a member's organization-admin status", () => {
    adapter.setOrganizationAdmin('org-1', 'user-1', true).subscribe()

    const request = httpMock.expectOne('/api/organizations/org-1/users/user-1/organization-admin')
    expect(request.request.method).toBe('PUT')
    expect(request.request.body).toEqual({ is_organization_admin: true })
    request.flush(null)
  })
})
