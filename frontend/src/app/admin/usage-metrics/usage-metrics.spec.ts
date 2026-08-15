import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { UsageMetrics } from './usage-metrics'
import { adminProviders } from '../infrastructure/admin.providers'

function render(
  usages: {
    repository_id: string
    name: string
    used_bytes: number
    quota_bytes?: number | null
  }[],
) {
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), ...adminProviders],
  })
  const fixture = TestBed.createComponent(UsageMetrics)
  const httpMock = TestBed.inject(HttpTestingController)
  fixture.detectChanges()
  httpMock.expectOne('/api/admin/metrics').flush(usages)
  fixture.detectChanges()
  return fixture
}

describe('UsageMetrics', () => {
  it('renders one chart bar per repository, most-used first', () => {
    const fixture = render([
      { repository_id: '1', name: 'small-repo', used_bytes: 100 },
      { repository_id: '2', name: 'big-repo', used_bytes: 900 },
    ])

    const labels: (string | undefined)[] = Array.from(
      fixture.nativeElement.querySelectorAll('.gbt-dimension-card__label'),
    ).map((el: unknown) => (el as HTMLElement).textContent?.trim())

    expect(labels).toEqual(['big-repo', 'small-repo'])
  })

  it('folds repositories beyond the top 15 into one "Autres" bar', () => {
    const usages = Array.from({ length: 17 }, (_, i) => ({
      repository_id: `${i}`,
      name: `repo-${i}`,
      used_bytes: 100 - i,
    }))
    const fixture = render(usages)

    const rows = fixture.nativeElement.querySelectorAll('.gbt-dimension-card tbody tr')
    expect(rows.length).toBe(16)
    expect(fixture.nativeElement.textContent).toContain('Autres (2)')
  })

  it('still lists every repository in the table, including the folded ones', () => {
    const usages = Array.from({ length: 17 }, (_, i) => ({
      repository_id: `${i}`,
      name: `repo-${i}`,
      used_bytes: 100 - i,
    }))
    const fixture = render(usages)

    const tableRows = fixture.nativeElement.querySelectorAll('gbt-table tbody tr')
    expect(tableRows.length).toBe(17)
  })

  it('formats the chart values as bytes', () => {
    const fixture = render([{ repository_id: '1', name: 'repo', used_bytes: 2048 }])

    expect(fixture.nativeElement.textContent).toContain('2.0 Ko')
  })

  it('shows an empty-state message when there are no repositories', () => {
    const fixture = render([])

    expect(fixture.nativeElement.textContent).toContain('Aucun dépôt.')
  })

  it('shows a quota gauge only for repositories with a quota set', () => {
    const fixture = render([
      { repository_id: '1', name: 'limited-repo', used_bytes: 500, quota_bytes: 1000 },
      { repository_id: '2', name: 'unlimited-repo', used_bytes: 500, quota_bytes: null },
    ])

    const gauges = fixture.nativeElement.querySelectorAll('gbt-gauge-bar')
    expect(gauges.length).toBe(1)
    const text = fixture.nativeElement.textContent as string
    expect(text).toContain('limited-repo')
  })

  it('hides the quota section entirely when no repository has a quota', () => {
    const fixture = render([{ repository_id: '1', name: 'repo', used_bytes: 500 }])

    expect(fixture.nativeElement.textContent).not.toContain('Quotas de stockage')
  })
})
