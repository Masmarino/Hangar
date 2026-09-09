import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { OrganizationMembersService } from './organization-members.service'
import { ORGANIZATION_MEMBERS_PORT, OrganizationMembersPort } from './organization-members.port'

describe('OrganizationMembersService', () => {
  function setup(port: Partial<OrganizationMembersPort>) {
    TestBed.configureTestingModule({
      providers: [
        OrganizationMembersService,
        { provide: ORGANIZATION_MEMBERS_PORT, useValue: port },
      ],
    })
    return TestBed.inject(OrganizationMembersService)
  }

  it('delegates list to the port', () => {
    const members = [
      {
        id: 'user-1',
        username: 'florian',
        email: null,
        is_organization_admin: false,
        invitation_pending: false,
      },
    ]
    const service = setup({ list: () => of(members) })

    let result
    service.list('org-1').subscribe((r) => (result = r))

    expect(result).toEqual(members)
  })

  it('delegates invite to the port', () => {
    const list = vi.fn(() => of([]))
    const invite = vi.fn(() =>
      of({
        id: 'user-1',
        username: 'florian',
        email: 'florian@example.com',
        is_organization_admin: false,
        invitation_pending: true,
      }),
    )
    const service = setup({ list, invite })

    service.invite('org-1', 'florian', 'florian@example.com', false).subscribe()

    expect(invite).toHaveBeenCalledWith('org-1', 'florian', 'florian@example.com', false)
  })

  it('delegates setOrganizationAdmin to the port', () => {
    const setOrganizationAdmin = vi.fn(() => of(undefined))
    const service = setup({ setOrganizationAdmin })

    service.setOrganizationAdmin('org-1', 'user-1', true).subscribe()

    expect(setOrganizationAdmin).toHaveBeenCalledWith('org-1', 'user-1', true)
  })
})
