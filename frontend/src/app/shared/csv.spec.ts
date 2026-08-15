import { toCsv } from './csv'

describe('toCsv', () => {
  it('renders a header row followed by one row per item', () => {
    const csv = toCsv(
      [
        { name: 'alice', age: 30 },
        { name: 'bob', age: 25 },
      ],
      [
        { key: 'name', label: 'Name' },
        { key: 'age', label: 'Age' },
      ],
    )

    expect(csv).toBe('Name,Age\r\nalice,30\r\nbob,25')
  })

  it('quotes a value containing a comma', () => {
    const csv = toCsv([{ label: 'a, b' }], [{ key: 'label', label: 'Label' }])

    expect(csv).toBe('Label\r\n"a, b"')
  })

  it('escapes an embedded double quote by doubling it', () => {
    const csv = toCsv([{ label: 'say "hi"' }], [{ key: 'label', label: 'Label' }])

    expect(csv).toBe('Label\r\n"say ""hi"""')
  })

  it('renders null and undefined values as an empty cell', () => {
    const csv = toCsv([{ value: null }, { value: undefined }], [{ key: 'value', label: 'Value' }])

    expect(csv).toBe('Value\r\n\r\n')
  })

  it('produces just the header row for an empty array', () => {
    const csv = toCsv([], [{ key: 'name', label: 'Name' }])

    expect(csv).toBe('Name')
  })

  it('neutralizes a leading =, +, -, or @ so the cell can never be read as a formula', () => {
    const csv = toCsv(
      [{ v: '=cmd|/c calc' }, { v: '+1' }, { v: '-1' }, { v: '@SUM(A1)' }],
      [{ key: 'v', label: 'V' }],
    )

    expect(csv).toBe("V\r\n'=cmd|/c calc\r\n'+1\r\n'-1\r\n'@SUM(A1)")
  })

  it('still quotes a neutralized value that also contains a comma', () => {
    const csv = toCsv([{ v: '=SUM(A1,B1)' }], [{ key: 'v', label: 'V' }])

    expect(csv).toBe('V\r\n"\'=SUM(A1,B1)"')
  })

  it('does not touch a value that merely contains one of those characters mid-string', () => {
    const csv = toCsv([{ v: 'a=b' }, { v: 'x-y' }], [{ key: 'v', label: 'V' }])

    expect(csv).toBe('V\r\na=b\r\nx-y')
  })
})
