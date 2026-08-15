import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { CreateRepositoryModal } from './create-repository-modal'
import { RepositorySummary } from '../domain/repository.entity'
import { repositoryProviders } from '../infrastructure/repository.providers'

function repo(overrides: Partial<RepositorySummary>): RepositorySummary {
  return {
    id: 'repo-1',
    name: 'repo-1',
    format: 'npm',
    repo_type: 'hosted',
    remote_url: null,
    remote_credentials_set: false,
    group_members: [],
    quota_bytes: null,
    retention_keep_last_n: null,
    my_role: 'admin',
    ...overrides,
  }
}

function render() {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...repositoryProviders],
  })
  const fixture = TestBed.createComponent(CreateRepositoryModal)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock.expectOne('/api/repositories').flush([])
  fixture.detectChanges()
  return { fixture, httpMock }
}

describe('CreateRepositoryModal', () => {
  it('creates a hosted repository with every optional field left empty', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-repo')

    fixture.componentInstance.submit()

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
    req.flush(null)
  })

  it('sends remote credentials only for a proxy repository', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-proxy')
    fixture.componentInstance.form.controls.repoType.setValue('proxy')
    fixture.componentInstance.form.controls.remoteUrl.setValue('https://registry.example.com')
    fixture.componentInstance.form.controls.remoteUsername.setValue('svc-account')
    fixture.componentInstance.form.controls.remotePassword.setValue('s3cret')

    fixture.componentInstance.submit()

    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body.remote_url).toBe('https://registry.example.com')
    expect(req.request.body.remote_username).toBe('svc-account')
    expect(req.request.body.remote_password).toBe('s3cret')
    req.flush(null)
  })

  it('does not require remote credentials for a proxy repository', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-proxy')
    fixture.componentInstance.form.controls.repoType.setValue('proxy')
    fixture.componentInstance.form.controls.remoteUrl.setValue('https://registry.example.com')

    fixture.componentInstance.submit()

    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body.remote_username).toBeNull()
    expect(req.request.body.remote_password).toBeNull()
    req.flush(null)
  })

  it('offers only same-format repositories as group members, in the order they were added', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-group')
    fixture.componentInstance.form.controls.repoType.setValue('group')
    fixture.componentInstance.allRepositories.set([
      repo({ id: 'npm-a', name: 'npm-a', format: 'npm' }),
      repo({ id: 'npm-b', name: 'npm-b', format: 'npm' }),
      repo({ id: 'docker-a', name: 'docker-a', format: 'docker' }),
    ])
    fixture.detectChanges()

    expect(fixture.componentInstance.availableMemberOptions()).toEqual([
      { value: 'npm-a', label: 'npm-a' },
      { value: 'npm-b', label: 'npm-b' },
    ])

    fixture.componentInstance.selectedMemberId.set('npm-b')
    fixture.componentInstance.addMember()
    fixture.componentInstance.selectedMemberId.set('npm-a')
    fixture.componentInstance.addMember()

    expect(fixture.componentInstance.groupMembers().map((m) => m.id)).toEqual(['npm-b', 'npm-a'])
    // Already-picked members drop out of the picker...
    expect(fixture.componentInstance.availableMemberOptions()).toEqual([])

    fixture.componentInstance.submit()
    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body.group_members).toEqual(['npm-b', 'npm-a'])
    req.flush(null)
  })

  it('reorders and removes group members', () => {
    const { fixture } = render()
    fixture.componentInstance.form.controls.repoType.setValue('group')
    fixture.componentInstance.allRepositories.set([
      repo({ id: 'a', name: 'a' }),
      repo({ id: 'b', name: 'b' }),
      repo({ id: 'c', name: 'c' }),
    ])
    fixture.detectChanges()
    for (const id of ['a', 'b', 'c']) {
      fixture.componentInstance.selectedMemberId.set(id)
      fixture.componentInstance.addMember()
    }
    expect(fixture.componentInstance.groupMembers().map((m) => m.id)).toEqual(['a', 'b', 'c'])

    fixture.componentInstance.moveMemberUp(2) // c moves before b
    expect(fixture.componentInstance.groupMembers().map((m) => m.id)).toEqual(['a', 'c', 'b'])

    fixture.componentInstance.moveMemberDown(0) // a moves after c
    expect(fixture.componentInstance.groupMembers().map((m) => m.id)).toEqual(['c', 'a', 'b'])

    fixture.componentInstance.removeMember('a')
    expect(fixture.componentInstance.groupMembers().map((m) => m.id)).toEqual(['c', 'b'])
  })

  it('clears the picked group members when the format changes', () => {
    const { fixture } = render()
    fixture.componentInstance.form.controls.repoType.setValue('group')
    fixture.componentInstance.allRepositories.set([repo({ id: 'a', name: 'a', format: 'npm' })])
    fixture.detectChanges()
    fixture.componentInstance.selectedMemberId.set('a')
    fixture.componentInstance.addMember()
    expect(fixture.componentInstance.groupMembers().length).toBe(1)

    fixture.componentInstance.form.controls.format.setValue('docker')
    fixture.detectChanges()

    expect(fixture.componentInstance.groupMembers()).toEqual([])
  })

  it('rejects a negative quota without sending a request', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-repo')
    fixture.componentInstance.form.controls.quotaMb.setValue('-5')

    fixture.componentInstance.submit()

    httpMock.expectNone((r) => r.url === '/api/repositories' && r.method === 'POST')
    expect(fixture.componentInstance.quotaError).toContain('positif')
  })

  it('rejects a retention value below 1 without sending a request', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-repo')
    fixture.componentInstance.form.controls.retentionKeepLastN.setValue('0')

    fixture.componentInstance.submit()

    httpMock.expectNone((r) => r.url === '/api/repositories' && r.method === 'POST')
    expect(fixture.componentInstance.retentionError).toContain('entier positif')
  })

  it('converts quota in MB and retention count into the request payload', () => {
    const { fixture, httpMock } = render()
    fixture.componentInstance.form.controls.name.setValue('my-repo')
    fixture.componentInstance.form.controls.quotaMb.setValue('5')
    fixture.componentInstance.form.controls.retentionKeepLastN.setValue('3')

    fixture.componentInstance.submit()

    const req = httpMock.expectOne('/api/repositories')
    expect(req.request.body.quota_bytes).toBe(5 * 1024 * 1024)
    expect(req.request.body.retention_keep_last_n).toBe(3)
    req.flush(null)
  })

  it('emits created on a successful save', () => {
    const { fixture, httpMock } = render()
    let created = false
    fixture.componentInstance.created.subscribe(() => (created = true))
    fixture.componentInstance.form.controls.name.setValue('my-repo')

    fixture.componentInstance.submit()

    httpMock.expectOne('/api/repositories').flush(null)
    expect(created).toBe(true)
  })
})
