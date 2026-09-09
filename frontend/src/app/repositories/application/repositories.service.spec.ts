import { TestBed } from '@angular/core/testing'
import { of, throwError } from 'rxjs'
import { RepositoriesService } from './repositories.service'
import { REPOSITORY_PORT, RepositoryPort } from './repository.port'

describe('RepositoriesService', () => {
  function setup(port: Partial<RepositoryPort>) {
    TestBed.configureTestingModule({ providers: [{ provide: REPOSITORY_PORT, useValue: port }] })
    return TestBed.inject(RepositoriesService)
  }

  it('delegates list() to the port', () => {
    const list = vi.fn().mockReturnValue(of([]))
    setup({ list }).list()

    expect(list).toHaveBeenCalled()
  })

  it('shares one cached list() across multiple callers instead of re-fetching', () => {
    const list = vi.fn().mockReturnValue(of([]))
    const service = setup({ list })

    service.list().subscribe()
    service.list().subscribe()

    expect(list).toHaveBeenCalledTimes(1)
  })

  it('does not permanently cache a failed list() — a later call retries', () => {
    const list = vi
      .fn()
      .mockReturnValueOnce(throwError(() => new Error('boom')))
      .mockReturnValue(of([]))
    const service = setup({ list })

    service.list().subscribe({ error: () => undefined })
    service.list().subscribe()

    expect(list).toHaveBeenCalledTimes(2)
  })

  it('a mutation (create) clears the cache so the next list() call re-fetches', () => {
    const list = vi.fn().mockReturnValue(of([]))
    const create = vi.fn().mockReturnValue(of({}))
    const service = setup({ list, create })

    service.list().subscribe()
    service.create('my-repo', 'npm', 'hosted', null).subscribe()
    service.list().subscribe()

    expect(list).toHaveBeenCalledTimes(2)
  })

  it('a mutation (delete) clears the cache so the next list() call re-fetches', () => {
    const list = vi.fn().mockReturnValue(of([]))
    const del = vi.fn().mockReturnValue(of(undefined))
    const service = setup({ list, delete: del })

    service.list().subscribe()
    service.delete('repo-1').subscribe()
    service.list().subscribe()

    expect(list).toHaveBeenCalledTimes(2)
  })

  it('delegates get() to the port', () => {
    const get = vi.fn().mockReturnValue(of({}))
    setup({ get }).get('repo-1')

    expect(get).toHaveBeenCalledWith('repo-1')
  })

  it('delegates create() to the port, defaulting options to an empty object', () => {
    const create = vi.fn().mockReturnValue(of({}))
    setup({ create }).create('my-repo', 'npm', 'hosted', null)

    expect(create).toHaveBeenCalledWith('my-repo', 'npm', 'hosted', null, {})
  })

  it('delegates delete() to the port', () => {
    const del = vi.fn().mockReturnValue(of(undefined))
    setup({ delete: del }).delete('repo-1')

    expect(del).toHaveBeenCalledWith('repo-1')
  })

  it('delegates packages() to the port', () => {
    const packages = vi.fn().mockReturnValue(of({ format: 'npm', packages: [] }))
    setup({ packages }).packages('repo-1')

    expect(packages).toHaveBeenCalledWith('repo-1')
  })

  it('delegates scanDockerImage() to the port', () => {
    const scanDockerImage = vi.fn().mockReturnValue(of({ scanned_at: '', vulnerabilities: [] }))
    setup({ scanDockerImage }).scanDockerImage('repo-1', 'my-image', 'latest')

    expect(scanDockerImage).toHaveBeenCalledWith('repo-1', 'my-image', 'latest')
  })
})
