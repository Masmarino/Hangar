import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router'
import { By } from '@angular/platform-browser'
import { Table } from '@masmarino/gabarit'
import { PermissionRoleEditor } from '../../repositories/permission-role-editor/permission-role-editor'
import { UserDetail } from './user-detail'
import { PageTitleService } from '../../shell/page-title.service'
import { userProviders } from '../infrastructure/user.providers'
import { repositoryProviders } from '../../repositories/infrastructure/repository.providers'
import { MeService } from '../../shell/application/me.service'

describe('UserDetail', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  // Defaults to a super-admin viewer, matching every pre-existing test below (full
  // access) — the organization-admin-viewer restrictions get their own dedicated tests.
  function setup(options?: { isSuperAdmin?: boolean }) {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...userProviders,
        ...repositoryProviders,
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { paramMap: convertToParamMap({ id: 'user-2' }) },
            paramMap: of(convertToParamMap({ id: 'user-2' })),
          },
        },
        { provide: MeService, useValue: { isSuperAdmin: () => (options?.isSuperAdmin ?? true) } },
      ],
    })
    return {
      fixture: TestBed.createComponent(UserDetail),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('loads the user and their permissions across repositories', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()

    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([
        { repository_id: 'repo-1', repository_name: 'my-repo', format: 'npm', role: 'write' },
      ])
    httpMock.expectOne('/api/repositories').flush([])

    expect(fixture.componentInstance.username()).toBe('florian')
    expect(fixture.componentInstance.permissions()).toEqual([
      { repository_id: 'repo-1', repository_name: 'my-repo', format: 'npm', role: 'write' },
    ])
  })

  it('fetches the single user by id, not the whole user list', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()

    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    httpMock.expectNone('/api/users')
  })

  it('shows a blank state instead of erroring when the user id is unknown', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()

    httpMock
      .expectOne('/api/users/user-2')
      .flush('not found', { status: 404, statusText: 'Not Found' })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    expect(fixture.componentInstance.user()).toBeNull()
  })

  it('changes a role via the editor and reloads', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([{ repository_id: 'repo-1', repository_name: 'my-repo', format: 'npm', role: 'read' }])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', {
      repository_id: 'repo-1',
      repository_name: 'my-repo',
      format: 'npm',
      role: 'read',
    })
    fixture.detectChanges()

    const editorDebugElement = fixture.debugElement.query(By.directive(PermissionRoleEditor))
    editorDebugElement.triggerEventHandler('roleChanged', 'write')

    const grantReq = httpMock.expectOne('/api/repositories/repo-1/permissions/user-2')
    expect(grantReq.request.method).toBe('PUT')
    expect(grantReq.request.body).toEqual({ role: 'write' })
    grantReq.flush(null)

    // user list is cached and unchanged by a permission edit, so no re-fetch here
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([
        { repository_id: 'repo-1', repository_name: 'my-repo', format: 'npm', role: 'write' },
      ])

    expect(fixture.componentInstance.permissions()[0].role).toBe('write')
  })

  it('deletes the user and navigates to the users list when confirmed', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = setup()
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')

    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.deleteUser()

    expect(window.confirm).toHaveBeenCalledWith('Supprimer l\'utilisateur "florian" ?')
    const deleteReq = httpMock.expectOne('/api/users/user-2')
    expect(deleteReq.request.method).toBe('DELETE')
    deleteReq.flush(null)

    expect(router.navigate).toHaveBeenCalledWith(['/users'])
  })

  it('does not delete the user when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    const { fixture, httpMock } = setup()
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')

    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.deleteUser()

    expect(window.confirm).toHaveBeenCalled()
    httpMock.expectNone('/api/users/user-2')
    expect(router.navigate).not.toHaveBeenCalled()
  })

  it('revokes a permission via the editor for the correct repository, keeping the user id fixed', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = setup()

    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([
        { repository_id: 'repo-9', repository_name: 'other-repo', format: 'npm', role: 'write' },
      ])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', {
      repository_id: 'repo-9',
      repository_name: 'other-repo',
      format: 'npm',
      role: 'write',
    })
    fixture.detectChanges()

    expect(fixture.componentInstance.editingPermission()).toEqual({
      repository_id: 'repo-9',
      repository_name: 'other-repo',
      format: 'npm',
      role: 'write',
    })

    const editorDebugElement = fixture.debugElement.query(By.directive(PermissionRoleEditor))
    editorDebugElement.triggerEventHandler('revoked', undefined)

    const revokeReq = httpMock.expectOne('/api/repositories/repo-9/permissions/user-2')
    expect(revokeReq.request.method).toBe('DELETE')
    revokeReq.flush(null)

    // user list is cached and unchanged by a permission edit, so no re-fetch here
    httpMock.expectOne('/api/users/user-2/permissions').flush([])

    expect(fixture.componentInstance.editingPermission()).toBeNull()
    expect(fixture.componentInstance.permissions()).toEqual([])
  })

  it('promotes a user to super-admin after confirmation', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.setSuperAdmin()

    expect(window.confirm).toHaveBeenCalledWith(
      'Promouvoir "florian" au rang de super-administrateur ?',
    )

    const req = httpMock.expectOne('/api/users/user-2/super-admin')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ is_super_admin: true })
    req.flush(null)

    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: true })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])

    expect(fixture.componentInstance.user()?.is_super_admin).toBe(true)
  })

  it('shows an error when demoting the last super-admin is rejected', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: true })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.setSuperAdmin()

    expect(window.confirm).toHaveBeenCalledWith(
      'Retirer le rang de super-administrateur à "florian" ?',
    )

    const req = httpMock.expectOne('/api/users/user-2/super-admin')
    req.flush({ error: 'conflict' }, { status: 409, statusText: 'Conflict' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain(
      'Impossible de rétrograder le dernier super-administrateur.',
    )
  })

  it('shows a generic error when a non-conflict failure occurs while promoting', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.setSuperAdmin()

    const req = httpMock.expectOne('/api/users/user-2/super-admin')
    req.flush({ error: 'server error' }, { status: 500, statusText: 'Internal Server Error' })
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain(
      'Impossible de modifier le statut super-administrateur.',
    )
    expect(fixture.nativeElement.textContent).not.toContain(
      'Impossible de rétrograder le dernier super-administrateur.',
    )
  })

  it('does not change super-admin status when the confirmation is cancelled', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])

    fixture.componentInstance.setSuperAdmin()

    httpMock.expectNone('/api/users/user-2/super-admin')
  })

  it('grants a new permission for the chosen repository and role', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([
      {
        id: 'repo-5',
        name: 'new-repo',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
    ])
    fixture.detectChanges()

    fixture.componentInstance.grantRepositoryIds.set(['repo-5'])
    fixture.componentInstance.grantRole.set('write')
    fixture.componentInstance.grantPermission()

    const req = httpMock.expectOne('/api/repositories/repo-5/permissions/user-2')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ role: 'write' })
    req.flush(null)

    // user list is cached and unchanged by a permission edit, so no re-fetch here
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([
        { repository_id: 'repo-5', repository_name: 'new-repo', format: 'npm', role: 'write' },
      ])

    expect(fixture.componentInstance.permissions()).toEqual([
      { repository_id: 'repo-5', repository_name: 'new-repo', format: 'npm', role: 'write' },
    ])
  })

  it('grants the same role to several repositories in one action', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([
      {
        id: 'repo-5',
        name: 'repo-a',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
      {
        id: 'repo-6',
        name: 'repo-b',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
    ])
    fixture.detectChanges()

    fixture.componentInstance.grantRepositoryIds.set(['repo-5', 'repo-6'])
    fixture.componentInstance.grantRole.set('read')
    fixture.componentInstance.grantPermission()

    const reqA = httpMock.expectOne('/api/repositories/repo-5/permissions/user-2')
    const reqB = httpMock.expectOne('/api/repositories/repo-6/permissions/user-2')
    expect(reqA.request.body).toEqual({ role: 'read' })
    expect(reqB.request.body).toEqual({ role: 'read' })
    reqA.flush(null)
    reqB.flush(null)

    // user list is cached and unchanged by a permission edit, so no re-fetch here
    httpMock.expectOne('/api/users/user-2/permissions').flush([
      { repository_id: 'repo-5', repository_name: 'repo-a', format: 'npm', role: 'read' },
      { repository_id: 'repo-6', repository_name: 'repo-b', format: 'npm', role: 'read' },
    ])

    expect(fixture.componentInstance.grantRepositoryIds()).toEqual([])
    expect(fixture.componentInstance.permissions().length).toBe(2)
  })

  it('shows an error and still reloads when one grant in a bulk action fails', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([
      {
        id: 'repo-5',
        name: 'repo-a',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
      {
        id: 'repo-6',
        name: 'repo-b',
        format: 'npm',
        repo_type: 'hosted',
        remote_url: null,
        group_members: [],
      },
    ])
    fixture.detectChanges()

    fixture.componentInstance.grantRepositoryIds.set(['repo-5', 'repo-6'])
    fixture.componentInstance.grantRole.set('read')
    fixture.componentInstance.grantPermission()

    httpMock.expectOne('/api/repositories/repo-5/permissions/user-2').flush(null)
    httpMock
      .expectOne('/api/repositories/repo-6/permissions/user-2')
      .flush('error', { status: 500, statusText: 'Server Error' })

    // the successful grant against repo-5 already committed server-side, so reload still runs
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock
      .expectOne('/api/users/user-2/permissions')
      .flush([{ repository_id: 'repo-5', repository_name: 'repo-a', format: 'npm', role: 'read' }])

    expect(fixture.componentInstance.grantError()).not.toBeNull()
    expect(fixture.componentInstance.permissions().length).toBe(1)
  })

  it('does nothing when no repository is selected for the bulk grant', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()
    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()

    fixture.componentInstance.grantPermission()

    httpMock.expectNone((r) => r.url.includes('/permissions/user-2'))
  })

  it('sets the shared page title to the username once it loads', () => {
    const { fixture, httpMock } = setup()
    const pageTitle = TestBed.inject(PageTitleService)
    fixture.detectChanges()
    expect(pageTitle.title()).toBe('')

    httpMock
      .expectOne('/api/users/user-2')
      .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()

    expect(pageTitle.title()).toBe('florian')
  })

  it('shows a load-failure message and hides the management actions when the request errors', () => {
    const { fixture, httpMock } = setup()
    fixture.detectChanges()

    httpMock.expectOne('/api/users/user-2').flush('nope', { status: 403, statusText: 'Forbidden' })
    httpMock.expectOne('/api/users/user-2/permissions').flush([])
    httpMock.expectOne('/api/repositories').flush([])
    fixture.detectChanges()

    expect(fixture.componentInstance.loadError()).toBe(true)
    expect(fixture.nativeElement.textContent).toContain('Échec du chargement');
    expect(fixture.nativeElement.textContent).not.toContain('Supprimer');
  })

  describe('as an organization admin (not a super-admin)', () => {
    it('hides the super-admin promotion control entirely', () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })
      fixture.detectChanges()
      httpMock
        .expectOne('/api/users/user-2')
        .flush({ id: 'user-2', username: 'florian', is_super_admin: false })
      httpMock.expectOne('/api/users/user-2/permissions').flush([])
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).not.toContain('super-administrateur')
    })

    it('still shows delete and resend-invitation for a regular (non-super-admin) target', () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })
      fixture.detectChanges()
      httpMock
        .expectOne('/api/users/user-2')
        .flush({ id: 'user-2', username: 'florian', is_super_admin: false, invitation_pending: true })
      httpMock.expectOne('/api/users/user-2/permissions').flush([])
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).toContain('Supprimer')
      expect(fixture.nativeElement.textContent).toContain("Renvoyer l'invitation")
    })

    it('hides delete and resend-invitation when the target is a super-admin — a global privilege outside their reach', () => {
      const { fixture, httpMock } = setup({ isSuperAdmin: false })
      fixture.detectChanges()
      httpMock
        .expectOne('/api/users/user-2')
        .flush({ id: 'user-2', username: 'florian', is_super_admin: true, invitation_pending: true })
      httpMock.expectOne('/api/users/user-2/permissions').flush([])
      httpMock.expectOne('/api/repositories').flush([])
      fixture.detectChanges()

      expect(fixture.nativeElement.textContent).not.toContain('Supprimer')
      expect(fixture.nativeElement.textContent).not.toContain("Renvoyer l'invitation")
    })
  })
})
