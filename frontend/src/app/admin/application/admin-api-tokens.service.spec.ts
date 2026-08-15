import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { AdminApiTokensService } from './admin-api-tokens.service'
import { ADMIN_API_TOKEN_PORT, AdminApiTokenPort } from './admin-api-token.port'

describe('AdminApiTokensService', () => {
  function setup(port: Partial<AdminApiTokenPort>) {
    TestBed.configureTestingModule({
      providers: [{ provide: ADMIN_API_TOKEN_PORT, useValue: port }],
    })
    return TestBed.inject(AdminApiTokensService)
  }

  it('delegates list() to the port', () => {
    const list = vi.fn().mockReturnValue(of([]))
    setup({ list }).list()

    expect(list).toHaveBeenCalled()
  })

  it('delegates revoke() to the port', () => {
    const revoke = vi.fn().mockReturnValue(of(undefined))
    setup({ revoke }).revoke('t1')

    expect(revoke).toHaveBeenCalledWith('t1')
  })
})
