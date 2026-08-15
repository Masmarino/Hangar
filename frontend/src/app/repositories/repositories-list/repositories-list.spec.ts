import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { Router, provideRouter } from '@angular/router'
import { By } from '@angular/platform-browser'
import { Table } from '@masmarino/gabarit'
import { RepositoriesList } from './repositories-list'
import { repositoryProviders } from '../infrastructure/repository.providers'

describe('RepositoriesList', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('loads repositories into the repositories signal on init', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...repositoryProviders,
      ],
    })
    const fixture = TestBed.createComponent(RepositoriesList)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock
      .expectOne('/api/repositories')
      .flush([{ id: 'r1', name: 'my-repo', format: 'npm', repo_type: 'hosted' }])

    expect(fixture.componentInstance.repositories().length).toBe(1)
  })

  it('shows a loading state instead of an empty table while the request is in flight', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...repositoryProviders,
      ],
    })
    const fixture = TestBed.createComponent(RepositoriesList)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).toContain('Chargement…')
    expect(fixture.debugElement.query(By.directive(Table))).toBeNull()

    httpMock
      .expectOne('/api/repositories')
      .flush([{ id: 'r1', name: 'my-repo', format: 'npm', repo_type: 'hosted' }])
    fixture.detectChanges()

    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')
    expect(fixture.debugElement.query(By.directive(Table))).toBeTruthy()
  })

  it('navigates to the repository detail page when a table row is clicked', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...repositoryProviders,
      ],
    })
    const fixture = TestBed.createComponent(RepositoriesList)
    const httpMock = TestBed.inject(HttpTestingController)
    const router = TestBed.inject(Router)
    vi.spyOn(router, 'navigate')
    const repository = { id: 'r1', name: 'my-repo', format: 'npm', repo_type: 'hosted' }

    fixture.detectChanges()
    httpMock.expectOne('/api/repositories').flush([repository])
    fixture.detectChanges()

    const tableDebugElement = fixture.debugElement.query(By.directive(Table))
    tableDebugElement.triggerEventHandler('rowClick', repository)

    expect(router.navigate).toHaveBeenCalledWith(['/repositories', 'r1'])
  })

  it('shows a retryable error instead of hanging on "Chargement…" when the request fails', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...repositoryProviders,
      ],
    })
    const fixture = TestBed.createComponent(RepositoriesList)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock
      .expectOne('/api/repositories')
      .flush('error', { status: 500, statusText: 'Server Error' })
    fixture.detectChanges()

    expect(fixture.componentInstance.loading()).toBe(false)
    expect(fixture.nativeElement.textContent).not.toContain('Chargement…')
    expect(fixture.componentInstance.error()).not.toBeNull()

    fixture.componentInstance.reload()
    httpMock
      .expectOne('/api/repositories')
      .flush([{ id: 'r1', name: 'my-repo', format: 'npm', repo_type: 'hosted' }])
    fixture.detectChanges()

    expect(fixture.componentInstance.error()).toBeNull()
    expect(fixture.componentInstance.repositories().length).toBe(1)
  })
})
