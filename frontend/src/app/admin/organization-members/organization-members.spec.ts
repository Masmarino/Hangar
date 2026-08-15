import { ComponentFixture, TestBed } from '@angular/core/testing'
import { By } from '@angular/platform-browser'
import { of, throwError } from 'rxjs'
import { OrganizationMembers } from './organization-members'
import { OrganizationMembersService } from '../application/organization-members.service'

function clickPromoteDemoteButton(fixture: ComponentFixture<OrganizationMembers>): void {
  const button = fixture.debugElement.query(By.css('.organization-members__actions button'))
  button.nativeElement.click()
}

describe('OrganizationMembers', () => {
  let fixture: ComponentFixture<OrganizationMembers>
  let component: OrganizationMembers
  let serviceSpy: {
    list: ReturnType<typeof vi.fn>
    invite: ReturnType<typeof vi.fn>
    setOrganizationAdmin: ReturnType<typeof vi.fn>
  }

  function setup() {
    serviceSpy = { list: vi.fn(), invite: vi.fn(), setOrganizationAdmin: vi.fn() }
    serviceSpy.list.mockReturnValue(
      of([{ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false }]),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationMembers],
      providers: [{ provide: OrganizationMembersService, useValue: serviceSpy }],
    })
    fixture = TestBed.createComponent(OrganizationMembers)
    component = fixture.componentInstance
    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
  }

  it('loads members for the given organization on init', () => {
    setup()

    expect(serviceSpy.list).toHaveBeenCalledWith('org-1')
    expect(component.members()).toEqual([
      { id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false },
    ])
  })

  it('invites a new member and reloads the list', () => {
    setup()
    serviceSpy.invite.mockReturnValue(
      of({ id: 'user-2', username: 'newmember', email: 'newmember@example.com', is_organization_admin: false, invitation_pending: true }),
    )
    component.startAdding()
    component.newUsername.set('newmember')
    component.newEmail.set('newmember@example.com')

    component.invite()

    expect(serviceSpy.invite).toHaveBeenCalledWith('org-1', 'newmember', 'newmember@example.com', false)
    expect(serviceSpy.list).toHaveBeenCalledTimes(2)
    expect(component.addingMember()).toBe(false)
  })

  it('shows an error when the invite fails', () => {
    setup()
    serviceSpy.invite.mockReturnValue(throwError(() => new Error('conflict')))
    component.startAdding()
    component.newUsername.set('newmember')
    component.newEmail.set('newmember@example.com')

    component.invite()

    expect(component.errorMessage()).toBe("Échec de l'invitation.")
  })

  it('toggles organization-admin status after confirmation and reloads when the promote/demote button is clicked', () => {
    setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    serviceSpy.setOrganizationAdmin.mockReturnValue(of(undefined))

    clickPromoteDemoteButton(fixture)

    expect(serviceSpy.setOrganizationAdmin).toHaveBeenCalledWith('org-1', 'user-1', true)
    expect(serviceSpy.list).toHaveBeenCalledTimes(2)
  })

  it('does nothing when the toggle confirmation is dismissed', () => {
    setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    clickPromoteDemoteButton(fixture)

    expect(serviceSpy.setOrganizationAdmin).not.toHaveBeenCalled()
  })

  it('labels the button "Promouvoir" for a non-admin member and "Rétrograder" for an admin member', () => {
    setup()
    fixture.detectChanges()

    const button = fixture.debugElement.query(By.css('.organization-members__actions button'))
    expect(button.nativeElement.textContent.trim()).toBe('Promouvoir')
  })

  it('does not react to clicks anywhere else on the member row', () => {
    setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    const row = fixture.debugElement.query(By.css('.organization-members__table tbody tr'))
    row.nativeElement.click()

    expect(serviceSpy.setOrganizationAdmin).not.toHaveBeenCalled()
  })
})
