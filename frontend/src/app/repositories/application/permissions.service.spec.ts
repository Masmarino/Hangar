import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { PermissionsService } from './permissions.service'
import { PERMISSION_PORT, PermissionPort } from './permission.port'

describe('PermissionsService', () => {
  function setup(port: Partial<PermissionPort>) {
    TestBed.configureTestingModule({ providers: [{ provide: PERMISSION_PORT, useValue: port }] })
    return TestBed.inject(PermissionsService)
  }

  it('delegates list() to the port', () => {
    const list = vi.fn().mockReturnValue(of([]))
    setup({ list }).list('repo-1')

    expect(list).toHaveBeenCalledWith('repo-1')
  })

  it('delegates lookupUser() to the port', () => {
    const lookupUser = vi.fn().mockReturnValue(of({ id: 'u1', username: 'florian' }))
    setup({ lookupUser }).lookupUser('florian')

    expect(lookupUser).toHaveBeenCalledWith('florian')
  })

  it('delegates searchUsers() to the port', () => {
    const searchUsers = vi.fn().mockReturnValue(of([]))
    setup({ searchUsers }).searchUsers('flo')

    expect(searchUsers).toHaveBeenCalledWith('flo')
  })

  it('delegates grant() to the port', () => {
    const grant = vi.fn().mockReturnValue(of(undefined))
    setup({ grant }).grant('repo-1', 'user-1', 'write')

    expect(grant).toHaveBeenCalledWith('repo-1', 'user-1', 'write')
  })

  it('delegates revoke() to the port', () => {
    const revoke = vi.fn().mockReturnValue(of(undefined))
    setup({ revoke }).revoke('repo-1', 'user-1')

    expect(revoke).toHaveBeenCalledWith('repo-1', 'user-1')
  })

  it('delegates listForUser() to the port', () => {
    const listForUser = vi.fn().mockReturnValue(of([]))
    setup({ listForUser }).listForUser('user-1')

    expect(listForUser).toHaveBeenCalledWith('user-1')
  })
})
