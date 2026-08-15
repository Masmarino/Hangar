import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpPermissionAdapter } from './http-permission.adapter'

describe('HttpPermissionAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpPermissionAdapter],
    })
    return {
      adapter: TestBed.inject(HttpPermissionAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('grants a role to a resolved user id', () => {
    const { adapter, httpMock } = setup()

    adapter.grant('repo-1', 'user-1', 'write').subscribe()
    const req = httpMock.expectOne('/api/repositories/repo-1/permissions/user-1')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ role: 'write' })
    req.flush(null)
  })

  it('lists permissions for a repository', () => {
    const { adapter, httpMock } = setup()

    adapter.list('repo-1').subscribe()
    const req = httpMock.expectOne('/api/repositories/repo-1/permissions')
    expect(req.request.method).toBe('GET')
    req.flush([{ user_id: 'user-1', username: 'member', role: 'write' }])
  })

  it('looks up a user by username', () => {
    const { adapter, httpMock } = setup()

    adapter.lookupUser('florian').subscribe()
    const req = httpMock.expectOne(
      (r) => r.url === '/api/users/lookup' && r.params.get('username') === 'florian',
    )
    expect(req.request.method).toBe('GET')
    req.flush({ id: 'user-1', username: 'florian', is_super_admin: false })
  })

  it('revokes a permission', () => {
    const { adapter, httpMock } = setup()

    adapter.revoke('repo-1', 'user-1').subscribe()
    const req = httpMock.expectOne('/api/repositories/repo-1/permissions/user-1')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)
  })
})
