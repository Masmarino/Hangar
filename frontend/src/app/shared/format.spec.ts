import { formatBytes, formatResultsAnnouncement, formatSelectedCount } from './format'

describe('formatBytes', () => {
  it('renders zero and negative values as 0 o', () => {
    expect(formatBytes(0)).toBe('0 o')
    expect(formatBytes(-5)).toBe('0 o')
  })

  it('renders bytes below 1024 without a decimal', () => {
    expect(formatBytes(512)).toBe('512 o')
  })

  it('renders larger values with the closest unit and one decimal', () => {
    expect(formatBytes(1024)).toBe('1.0 Ko')
    expect(formatBytes(1536)).toBe('1.5 Ko')
    expect(formatBytes(1024 * 1024 * 3)).toBe('3.0 Mo')
  })
})

// An ARIA live-region announcement (RGAA 7.5) — a plural mistake here is only heard by screen reader users, so the boundary at 1 gets its own test case.
describe('formatResultsAnnouncement', () => {
  it('pluralizes zero results', () => {
    expect(formatResultsAnnouncement(0)).toBe('0 résultats')
  })

  it('keeps one result singular', () => {
    expect(formatResultsAnnouncement(1)).toBe('1 résultat')
  })

  it('pluralizes several results', () => {
    expect(formatResultsAnnouncement(2)).toBe('2 résultats')
    expect(formatResultsAnnouncement(17)).toBe('17 résultats')
  })
})

// Drives gbt-select's `selectedCountLabel` — same singular/plural boundary, same reason to test it explicitly rather than by inference.
describe('formatSelectedCount', () => {
  it('pluralizes zero selected', () => {
    expect(formatSelectedCount(0)).toBe('0 sélectionnés')
  })

  it('keeps one selected singular', () => {
    expect(formatSelectedCount(1)).toBe('1 sélectionné')
  })

  it('pluralizes several selected', () => {
    expect(formatSelectedCount(2)).toBe('2 sélectionnés')
    expect(formatSelectedCount(9)).toBe('9 sélectionnés')
  })
})
