import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router'
import { By } from '@angular/platform-browser'
import { Table } from '@masmarino/gabarit'
import { RepositoryDetail } from './repository-detail'
import { UsageInstructions } from '../usage-instructions/usage-instructions'
import { PermissionRoleEditor } from '../permission-role-editor/permission-role-editor'
import { PackageTree } from '../package-tree/package-tree'
import { repositoryProviders } from '../infrastructure/repository.providers'
import { PageTitleService } from '../../shell/page-title.service'

describe('RepositoryDetail', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('adds a group member and reloads the repository', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'group-1' }) },
            paramMap: of(convertToParamMap({ id: 'group-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })

    fixture.componentInstance.newMemberId.set('member-1')
    fixture.componentInstance.addMember()

    const addReq = httpMock.expectOne('/api/repositories/group-1/group-members')
    expect(addReq.request.body).toEqual({ member_repository_id: 'member-1', position: 0 })
    addReq.flush(null)

    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: ['member-1'],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    // Non-empty group_members triggers a lookup to resolve member names for
    // the table (see repository-detail.ts's reload()).
    httpMock.expectOne('/api/repositories').flush([{ id: 'member-1', name: 'member-repo' }])

    expect(fixture.componentInstance.repository()?.group_members).toEqual(['member-1'])
  })

  it('ignores a second addMember call while the first is still in flight', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'group-1' }) },
            paramMap: of(convertToParamMap({ id: 'group-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/group-1/permissions').flush([])

    fixture.componentInstance.newMemberId.set('member-1')
    fixture.componentInstance.addMember()
    fixture.componentInstance.addMember()

    httpMock.expectOne('/api/repositories/group-1/group-members').flush(null)
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: ['member-1'],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/group-1/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([{ id: 'member-1', name: 'member-repo' }])

    httpMock.verify()
  })

  it('shows group member names instead of raw ids, falling back to the id when unknown', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'group-1' }) },
            paramMap: of(convertToParamMap({ id: 'group-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: ['member-1', 'ghost-id'],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories').flush([{ id: 'member-1', name: 'member-repo' }])
    fixture.detectChanges()

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('member-repo')
    // No name could be resolved for this one — falls back to the raw id
    // rather than showing nothing.
    expect(text).toContain('ghost-id')
  })

  it('renames the repository and reloads it', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    fixture.detectChanges()

    expect(fixture.debugElement.query(By.directive(UsageInstructions))).toBeTruthy()
    const packageTree = fixture.debugElement.query(By.directive(PackageTree))
    expect(packageTree).toBeTruthy()
    expect(packageTree.componentInstance.repositoryId()).toBe('repo-1')
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentInstance.newName.set('new-name')
    fixture.componentInstance.rename()

    const renameReq = httpMock.expectOne('/api/repositories/repo-1')
    expect(renameReq.request.method).toBe('PATCH')
    expect(renameReq.request.body).toEqual({ name: 'new-name' })
    renameReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'new-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })

    expect(fixture.componentInstance.repository()?.name).toBe('new-name')
  })

  it('removes a group member and reloads the repository when a member row is clicked', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'group-1' }) },
            paramMap: of(convertToParamMap({ id: 'group-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: ['member-1'],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    // Non-empty group_members triggers a lookup to resolve member names for
    // the table (see repository-detail.ts's reload()).
    httpMock.expectOne('/api/repositories').flush([{ id: 'member-1', name: 'member-repo' }])
    fixture.detectChanges()

    // Simulate the skolln-table (rowClick) output firing, exactly as it would at runtime,
    // to actually exercise the template's (rowClick)="removeMember($event.id)" binding.
    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', { id: 'member-1' })

    expect(window.confirm).toHaveBeenCalledWith('Retirer "member-repo" du groupe ?')
    const removeReq = httpMock.expectOne('/api/repositories/group-1/group-members/member-1')
    expect(removeReq.request.method).toBe('DELETE')
    removeReq.flush(null)

    // Removing a member must reload the repository, i.e. fire a second GET.
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })

    expect(fixture.componentInstance.repository()?.group_members).toEqual([])
  })

  it('does not remove a group member when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'group-1' }) },
            paramMap: of(convertToParamMap({ id: 'group-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/group-1').flush({
      id: 'group-1',
      name: 'group-repo',
      format: 'npm',
      repo_type: 'group',
      remote_url: null,
      group_members: ['member-1'],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories').flush([{ id: 'member-1', name: 'member-repo' }])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', { id: 'member-1' })

    expect(window.confirm).toHaveBeenCalled()
    httpMock.expectNone('/api/repositories/group-1/group-members/member-1')
  })

  it('deletes the repository and navigates to the list when the user confirms', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })

    fixture.componentInstance.deleteRepository()

    expect(window.confirm).toHaveBeenCalledWith('Supprimer le dépôt "old-name" ?')

    const deleteReq = httpMock.expectOne('/api/repositories/repo-1')
    expect(deleteReq.request.method).toBe('DELETE')
    deleteReq.flush(null)

    expect(router.navigate).toHaveBeenCalledWith(['/repositories'])
  })

  it('grants a permission by resolving the username first, then reloads', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

    fixture.componentInstance.grantUsername.set('florian')
    fixture.componentInstance.grantRole.set('write')
    fixture.componentInstance.grantPermission()

    const lookupReq = httpMock.expectOne(
      (r) => r.url === '/api/users/lookup' && r.params.get('username') === 'florian',
    )
    lookupReq.flush({ id: 'user-2', username: 'florian', is_super_admin: false })

    const grantReq = httpMock.expectOne('/api/repositories/repo-1/permissions/user-2')
    expect(grantReq.request.method).toBe('PUT')
    expect(grantReq.request.body).toEqual({ role: 'write' })
    grantReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-2', username: 'florian', role: 'write' }])

    expect(fixture.componentInstance.grantUsername()).toBe('')
    expect(fixture.componentInstance.permissions()).toEqual([
      { user_id: 'user-2', username: 'florian', role: 'write' },
    ])
  })

  it('debounces the username search and populates suggestions', () => {
    vi.useFakeTimers()
    try {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          ...repositoryProviders,
          provideRouter([]),
          {
            provide: ActivatedRoute,
            useValue: {
              snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
              paramMap: of(convertToParamMap({ id: 'repo-1' })),
            },
          },
        ],
      })
      const fixture = TestBed.createComponent(RepositoryDetail)
      const httpMock = TestBed.inject(HttpTestingController)

      fixture.detectChanges()
      httpMock.expectOne('/api/repositories/repo-1').flush({
        id: 'repo-1',
        name: 'my-repo',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
        my_role: 'admin',
      })
      httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

      fixture.componentInstance.onGrantUsernameInput('flo')
      httpMock.expectNone((r) => r.url === '/api/users/search')

      vi.advanceTimersByTime(200)
      const searchReq = httpMock.expectOne(
        (r) => r.url === '/api/users/search' && r.params.get('q') === 'flo',
      )
      searchReq.flush([{ id: 'user-2', username: 'florian' }])

      expect(fixture.componentInstance.userSearchResults()).toEqual([
        { id: 'user-2', username: 'florian' },
      ])
    } finally {
      vi.useRealTimers()
    }
  })

  it('grants a permission using the selected suggestion id, skipping the exact-lookup round trip', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

    fixture.componentInstance.selectUser({ id: 'user-2', username: 'florian' })
    expect(fixture.componentInstance.grantUsername()).toBe('florian')
    expect(fixture.componentInstance.userSearchResults()).toEqual([])

    fixture.componentInstance.grantRole.set('write')
    fixture.componentInstance.grantPermission()

    httpMock.expectNone((r) => r.url === '/api/users/lookup')
    const grantReq = httpMock.expectOne('/api/repositories/repo-1/permissions/user-2')
    expect(grantReq.request.method).toBe('PUT')
    expect(grantReq.request.body).toEqual({ role: 'write' })
    grantReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-2', username: 'florian', role: 'write' }])
  })

  it('opens the role editor when a permission row is clicked, and revokes on confirmation', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-2', username: 'florian', role: 'write' }])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', {
      user_id: 'user-2',
      username: 'florian',
      role: 'write',
    })
    fixture.detectChanges()

    expect(fixture.componentInstance.editingPermission()).toEqual({
      user_id: 'user-2',
      username: 'florian',
      role: 'write',
    })

    const editorDebugElement = fixture.debugElement.query(By.directive(PermissionRoleEditor))
    editorDebugElement.triggerEventHandler('revoked', undefined)

    expect(window.confirm).not.toHaveBeenCalled() // confirmation now happens inside PermissionRoleEditor, not repository-detail
    const revokeReq = httpMock.expectOne('/api/repositories/repo-1/permissions/user-2')
    expect(revokeReq.request.method).toBe('DELETE')
    revokeReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

    expect(fixture.componentInstance.permissions()).toEqual([])
  })

  it('changes a permission role via the editor and reloads', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-2', username: 'florian', role: 'read' }])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', {
      user_id: 'user-2',
      username: 'florian',
      role: 'read',
    })
    fixture.detectChanges()

    const editorDebugElement = fixture.debugElement.query(By.directive(PermissionRoleEditor))
    editorDebugElement.triggerEventHandler('roleChanged', 'admin')

    const grantReq = httpMock.expectOne('/api/repositories/repo-1/permissions/user-2')
    expect(grantReq.request.method).toBe('PUT')
    expect(grantReq.request.body).toEqual({ role: 'admin' })
    grantReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-2', username: 'florian', role: 'admin' }])

    expect(fixture.componentInstance.permissions()).toEqual([
      { user_id: 'user-2', username: 'florian', role: 'admin' },
    ])
  })

  it('does not delete the repository when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'old-name',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })

    fixture.componentInstance.deleteRepository()

    expect(window.confirm).toHaveBeenCalled()
    httpMock.expectNone('/api/repositories/repo-1')
    expect(router.navigate).not.toHaveBeenCalled()
  })

  it('sets the shared page title to the repository name once it loads', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)
    const pageTitle = TestBed.inject(PageTitleService)

    fixture.detectChanges()
    expect(pageTitle.title()).toBe('')

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    fixture.detectChanges()

    expect(pageTitle.title()).toBe('my-repo')
  })

  it('hides the admin-only tabs entirely for a read-only viewer', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'read',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'user-1', username: 'someone', role: 'read' }])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    const text = fixture.nativeElement.textContent as string
    expect(text).not.toContain('Renommer')
    expect(text).not.toContain('Supprimer le dépôt')
    expect(text).not.toContain('Accorder')

    // Not rendered at all for a read-only viewer, rather than shown read-only.
    expect(text).not.toContain("Droits d'accès")
    expect(text).not.toContain('Paramètres')
    expect(text).not.toContain('someone')
    expect(fixture.debugElement.query(By.directive(Table))).toBeNull()
  })

  it('shows rename, delete, and permission-management controls for a repository admin', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('Renommer')
    expect(text).toContain('Supprimer le dépôt')
    expect(text).toContain('Accorder')
  })

  it('loads the current quota in MB and saves an updated value converted to bytes', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: 5 * 1024 * 1024,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    expect(fixture.componentInstance.quotaMb()).toBe('5')

    fixture.componentInstance.setQuotaMb('10')
    fixture.componentInstance.saveQuota()

    const putReq = httpMock.expectOne('/api/repositories/repo-1/quota')
    expect(putReq.request.method).toBe('PUT')
    expect(putReq.request.body).toEqual({ quota_bytes: 10 * 1024 * 1024 })
    putReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: 10 * 1024 * 1024,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

    expect(fixture.componentInstance.quotaSaved()).toBe(true)
  })

  it('clears the quota back to unlimited when the field is left empty', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: 5 * 1024 * 1024,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentInstance.setQuotaMb('')
    fixture.componentInstance.saveQuota()

    const putReq = httpMock.expectOne('/api/repositories/repo-1/quota')
    expect(putReq.request.body).toEqual({ quota_bytes: null })
    putReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
  })

  it('rejects a negative quota without sending a request', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentInstance.setQuotaMb('-5')
    fixture.componentInstance.saveQuota()

    httpMock.expectNone('/api/repositories/repo-1/quota')
    expect(fixture.componentInstance.quotaError()).toContain('positif')
  })

  it('hides the quota and retention settings entirely for a non-admin viewer', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: 2 * 1024 * 1024,
      retention_keep_last_n: null,
      my_role: 'read',
    })
    httpMock
      .expectOne('/api/repositories/repo-1/permissions')
      .flush([{ user_id: 'u1', username: 'someone', role: 'read' }])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    const text = fixture.nativeElement.textContent as string
    expect(text).not.toContain('2.0 Mo')
    expect(text).not.toContain('Quota de stockage')
    expect(text).not.toContain('Enregistrer')
  })

  it('loads the current retention policy and saves an updated value', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: 3,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    expect(fixture.componentInstance.retentionKeepLastN()).toBe('3')

    fixture.componentInstance.setRetentionKeepLastN('10')
    fixture.componentInstance.saveRetentionPolicy()

    const putReq = httpMock.expectOne('/api/repositories/repo-1/retention')
    expect(putReq.request.method).toBe('PUT')
    expect(putReq.request.body).toEqual({ keep_last_n_versions: 10 })
    putReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: 10,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])

    expect(fixture.componentInstance.retentionSaved()).toBe(true)
  })

  it('disables the retention policy when the field is left empty', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: 3,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentInstance.setRetentionKeepLastN('')
    fixture.componentInstance.saveRetentionPolicy()

    const putReq = httpMock.expectOne('/api/repositories/repo-1/retention')
    expect(putReq.request.body).toEqual({ keep_last_n_versions: null })
    putReq.flush(null)

    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
  })

  it('rejects a retention value below 1 without sending a request', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ...repositoryProviders,
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'repo-1' }) },
            paramMap: of(convertToParamMap({ id: 'repo-1' })),
          },
        },
      ],
    })
    const fixture = TestBed.createComponent(RepositoryDetail)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1').flush({
      id: 'repo-1',
      name: 'my-repo',
      format: 'npm',
      repo_type: 'hosted',
      remote_url: null,
      group_members: [],
      quota_bytes: null,
      retention_keep_last_n: null,
      my_role: 'admin',
    })
    httpMock.expectOne('/api/repositories/repo-1/permissions').flush([])
    fixture.detectChanges()
    httpMock.expectOne('/api/repositories/repo-1/packages').flush({ format: 'npm', packages: [] })

    fixture.componentInstance.setRetentionKeepLastN('0')
    fixture.componentInstance.saveRetentionPolicy()

    httpMock.expectNone('/api/repositories/repo-1/retention')
    expect(fixture.componentInstance.retentionError()).toContain('entier positif')
  })
})
