import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpRepositoryAdapter } from './http-repository.adapter'

describe('HttpRepositoryAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpRepositoryAdapter],
    })
    return {
      adapter: TestBed.inject(HttpRepositoryAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('creates a repository with the expected payload, defaulting every optional field', () => {
    const { adapter, httpMock } = setup()

    adapter.create('my-repo', 'npm', 'hosted', null).subscribe()
    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body).toEqual({
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      remote_username: null,
      remote_password: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
    })
    req.flush({
      id: 'r1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      remote_credentials_set: false,
      group_members: [],
    })
  })

  it('creates a group repository with initial members, credentials, quota, and retention', () => {
    const { adapter, httpMock } = setup()

    adapter
      .create('my-proxy', 'npm', 'proxy', 'https://registry.example.com', {
        remoteUsername: 'svc',
        remotePassword: 'token',
        groupMembers: ['member-a', 'member-b'],
        quotaBytes: 1024,
        retentionKeepLastN: 5,
      })
      .subscribe()
    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body).toEqual({
      name: 'my-proxy',
      format: 'npm',
      repo_type: 'proxy',
      remote_url: 'https://registry.example.com',
      remote_username: 'svc',
      remote_password: 'token',
      group_members: ['member-a', 'member-b'],
      quota_bytes: 1024,
      retention_keep_last_n: 5,
    })
    req.flush(null)
  })

  it('adds a group member with the expected payload', () => {
    const { adapter, httpMock } = setup()

    adapter.addGroupMember('group-1', 'member-1', 0).subscribe()
    const req = httpMock.expectOne('/api/repositories/group-1/group-members')
    expect(req.request.body).toEqual({ member_repository_id: 'member-1', position: 0 })
    req.flush(null)
  })

  it('renames a repository via PATCH', () => {
    const { adapter, httpMock } = setup()

    adapter.rename('r1', 'renamed-repo').subscribe()
    const req = httpMock.expectOne('/api/repositories/r1')
    expect(req.request.method).toBe('PATCH')
    expect(req.request.body).toEqual({ name: 'renamed-repo' })
    req.flush(null)
  })
})
