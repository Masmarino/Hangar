import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpOrganizationsAdapter } from './http-organizations.adapter'

describe('HttpOrganizationsAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpOrganizationsAdapter],
    })
    return {
      adapter: TestBed.inject(HttpOrganizationsAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('lists organizations from GET /api/organizations', () => {
    const { adapter, httpMock } = setup()
    adapter.list().subscribe()
    const req = httpMock.expectOne('/api/organizations')
    expect(req.request.method).toBe('GET')
    req.flush([])
    httpMock.verify()
  })

  it('puts the LDAP config to /api/organizations/:id/identity-provider', () => {
    const { adapter, httpMock } = setup()
    const config = {
      server_url: 'ldap://dc.corp.example:389',
      bind_dn: 'cn=service,dc=corp,dc=example',
      user_search_base: 'ou=people,dc=corp,dc=example',
      user_search_filter: '(uid={username})',
      email_attribute: 'mail',
    }
    adapter.setLdapIdentityProvider('org-1', config).subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ type: 'ldap', ...config })
    req.flush(null)
    httpMock.verify()
  })

  it('puts an OIDC config with the type discriminator to /api/organizations/:id/identity-provider', () => {
    const { adapter, httpMock } = setup()
    const config = {
      issuer_url: 'https://accounts.example.com',
      client_id: 'hangar',
      client_secret: 's3cret!',
    }
    adapter.setOidcIdentityProvider('org-1', config).subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ type: 'oidc', ...config })
    req.flush(null)
    httpMock.verify()
  })

  it('creates an organization via POST /api/organizations', () => {
    const { adapter, httpMock } = setup()
    adapter.create('acme', 'Acme Corp').subscribe()
    const req = httpMock.expectOne('/api/organizations')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ slug: 'acme', display_name: 'Acme Corp' })
    req.flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })
    httpMock.verify()
  })

  it('deletes the identity provider config', () => {
    const { adapter, httpMock } = setup()
    adapter.clearIdentityProvider('org-1').subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)
    httpMock.verify()
  })
})
