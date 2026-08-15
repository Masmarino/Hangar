import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpMeAdapter } from './http-me.adapter'

describe('HttpMeAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpMeAdapter],
    })
    return {
      adapter: TestBed.inject(HttpMeAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('fetches the current user from /api/me', () => {
    const { adapter, httpMock } = setup()

    adapter.load().subscribe((me) => expect(me.username).toBe('florian'))
    httpMock.expectOne('/api/me').flush({
      id: 'user-1',
      username: 'florian',
      is_super_admin: true,
      is_organization_admin: false,
      organization_id: 'org-1',
      created_at: '2026-01-01T00:00:00Z',
    })
  })

  it('sends a PUT to /api/me/password with the current and new password', () => {
    const { adapter, httpMock } = setup()

    adapter.changePassword('old-s3cret!', 'new-s3cret!').subscribe()

    const req = httpMock.expectOne('/api/me/password')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({
      current_password: 'old-s3cret!',
      new_password: 'new-s3cret!',
    })
    req.flush(null)
  })
})
