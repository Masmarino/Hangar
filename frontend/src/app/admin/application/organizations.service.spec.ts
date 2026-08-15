import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { OrganizationsService } from './organizations.service'
import { ORGANIZATIONS_PORT, OrganizationsPort } from './organizations.port'

describe('OrganizationsService', () => {
  function setup(port: Partial<OrganizationsPort>) {
    TestBed.configureTestingModule({
      providers: [OrganizationsService, { provide: ORGANIZATIONS_PORT, useValue: port }],
    })
    return TestBed.inject(OrganizationsService)
  }

  it('lists organizations from the port', () => {
    const orgs = [{ id: '1', slug: 'acme', display_name: 'Acme', is_public: false }]
    const service = setup({ list: () => of(orgs) })

    let result
    service.list().subscribe((r) => (result = r))

    expect(result).toEqual(orgs)
  })

  it('caches the list and clears the cache after configuring an identity provider', () => {
    let listCalls = 0
    const service = setup({
      list: () => {
        listCalls++
        return of([])
      },
      setLdapIdentityProvider: () => of(undefined),
    })

    service.list().subscribe()
    service.list().subscribe()
    expect(listCalls).toBe(1)

    service
      .setLdapIdentityProvider('1', {
        server_url: 'ldap://x',
        bind_dn: 'cn=x',
        user_search_base: 'ou=x',
        user_search_filter: '(uid={username})',
        email_attribute: 'mail',
      })
      .subscribe()

    service.list().subscribe()
    expect(listCalls).toBe(2)
  })

  it('creates an organization and clears the cache', () => {
    let listCalls = 0
    const service = setup({
      list: () => {
        listCalls++
        return of([])
      },
      create: () => of({ id: '2', slug: 'acme', display_name: 'Acme Corp', is_public: false }),
    })

    service.list().subscribe()
    service.list().subscribe()
    expect(listCalls).toBe(1)

    service.create('acme', 'Acme Corp').subscribe()

    service.list().subscribe()
    expect(listCalls).toBe(2)
  })
})
