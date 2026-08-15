import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { By } from '@angular/platform-browser'
import { Table } from '@masmarino/gabarit'
import { ApiTokensList } from './api-tokens-list'
import { apiTokenProviders } from '../infrastructure/api-token.providers'

describe('ApiTokensList', () => {
  it('loads and displays tokens on init', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...apiTokenProviders],
    })
    const fixture = TestBed.createComponent(ApiTokensList)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock
      .expectOne('/api/tokens')
      .flush([{ id: '1', label: 'laptop', created_at: '2026-01-01T00:00:00Z', last_used_at: null }])
    fixture.detectChanges()

    expect(fixture.componentInstance.tokens().length).toBe(1)
  })

  it('shows the plaintext token exactly once after creating it, via a real button click', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...apiTokenProviders],
    })
    const fixture = TestBed.createComponent(ApiTokensList)
    const httpMock = TestBed.inject(HttpTestingController)

    fixture.detectChanges()
    httpMock.expectOne('/api/tokens').flush([])
    fixture.detectChanges()

    fixture.componentInstance.showCreateForm.set(true)
    fixture.componentInstance.newLabel.setValue('laptop')
    fixture.detectChanges()

    fixture.componentInstance.createToken()
    httpMock.expectOne('/api/tokens').flush({ id: '2', token: 'hgr_plaintext-value' })
    httpMock
      .expectOne('/api/tokens')
      .flush([{ id: '2', label: 'laptop', created_at: '2026-01-01T00:00:00Z', last_used_at: null }])
    fixture.detectChanges()

    expect(fixture.componentInstance.createdToken()).toBe('hgr_plaintext-value')
    expect(fixture.nativeElement.textContent).toContain('hgr_plaintext-value')
  })

  it('revokes a token when a table row is clicked, after confirmation', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), ...apiTokenProviders],
    })
    const fixture = TestBed.createComponent(ApiTokensList)
    const httpMock = TestBed.inject(HttpTestingController)
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    fixture.detectChanges()
    httpMock
      .expectOne('/api/tokens')
      .flush([{ id: '1', label: 'laptop', created_at: '2026-01-01T00:00:00Z', last_used_at: null }])
    fixture.detectChanges()

    const table = fixture.debugElement.query(By.directive(Table))
    table.triggerEventHandler('rowClick', {
      id: '1',
      label: 'laptop',
      created_at: '2026-01-01T00:00:00Z',
      last_used_at: null,
    })

    httpMock.expectOne('/api/tokens/1').flush(null)
    httpMock.expectOne('/api/tokens').flush([])
  })
})
