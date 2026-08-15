import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpUserAdapter } from './http-user.adapter'

describe('HttpUserAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpUserAdapter],
    })
    return {
      adapter: TestBed.inject(HttpUserAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('lists users from GET /api/users', () => {
    const { adapter, httpMock } = setup()

    adapter.list().subscribe((users) => expect(users.length).toBe(1))
    httpMock
      .expectOne('/api/users')
      .flush([{ id: 'u1', username: 'florian', is_super_admin: true }])
  })

  it('creates a user via POST /api/users', () => {
    const { adapter, httpMock } = setup()

    adapter.create('newuser', 'newuser@example.com', false).subscribe()
    const req = httpMock.expectOne('/api/users')
    expect(req.request.body).toEqual({
      username: 'newuser',
      email: 'newuser@example.com',
      is_super_admin: false,
    })
    req.flush({
      id: 'u2',
      username: 'newuser',
      is_super_admin: false,
      email: 'newuser@example.com',
      invitation_pending: true,
    })
  })

  it("sends a PUT to change a user's super-admin status", () => {
    const { adapter, httpMock } = setup()

    adapter.setSuperAdmin('user-1', true).subscribe()
    const req = httpMock.expectOne('/api/users/user-1/super-admin')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ is_super_admin: true })
    req.flush(null)
  })

  it('sends a POST to resend an invitation', () => {
    const { adapter, httpMock } = setup()

    adapter.resendInvitation('user-1').subscribe()
    const req = httpMock.expectOne('/api/users/user-1/resend-invitation')
    expect(req.request.method).toBe('POST')
    req.flush(null)
  })
})
