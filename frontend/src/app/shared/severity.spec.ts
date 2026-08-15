import { bySeverityDesc, severityRank } from './severity'

describe('severityRank', () => {
  it('ranks critical first regardless of case', () => {
    expect(severityRank('critical')).toBeLessThan(severityRank('high'))
    expect(severityRank('CRITICAL')).toBe(severityRank('critical'))
  })

  it('ranks in descending order of severity', () => {
    expect(severityRank('high')).toBeLessThan(severityRank('medium'))
    expect(severityRank('medium')).toBeLessThan(severityRank('low'))
    expect(severityRank('low')).toBeLessThan(severityRank('unknown'))
  })

  it('treats medium and moderate as the same tier', () => {
    expect(severityRank('medium')).toBe(severityRank('moderate'))
  })

  it('ranks an unrecognized severity last', () => {
    expect(severityRank('totally-unknown')).toBeGreaterThan(severityRank('unknown'))
  })
})

describe('bySeverityDesc', () => {
  it('sorts a list of items most severe first', () => {
    const items = [{ severity: 'low' }, { severity: 'critical' }, { severity: 'high' }]
    items.sort(bySeverityDesc((item) => item.severity))

    expect(items.map((item) => item.severity)).toEqual(['critical', 'high', 'low'])
  })
})
