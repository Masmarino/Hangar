import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { ApiTokensApplicationService } from './api-tokens.application-service'
import { API_TOKEN_PORT, ApiTokenPort } from './api-token.port'

describe('ApiTokensApplicationService', () => {
  function setup(port: Partial<ApiTokenPort>) {
    TestBed.configureTestingModule({ providers: [{ provide: API_TOKEN_PORT, useValue: port }] })
    return TestBed.inject(ApiTokensApplicationService)
  }

  it('delegates list() to the port', () => {
    const list = vi.fn().mockReturnValue(of([]))
    const service = setup({ list })

    service.list()

    expect(list).toHaveBeenCalled()
  })

  it('delegates create() to the port with the given label', () => {
    const create = vi.fn().mockReturnValue(of({ id: '1', token: 'hgr_secret' }))
    const service = setup({ create })

    service.create('laptop')

    expect(create).toHaveBeenCalledWith('laptop')
  })

  it('delegates revoke() to the port with the given id', () => {
    const revoke = vi.fn().mockReturnValue(of(undefined))
    const service = setup({ revoke })

    service.revoke('1')

    expect(revoke).toHaveBeenCalledWith('1')
  })
})
