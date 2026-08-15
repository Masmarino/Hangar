export function toCsv<T>(rows: T[], columns: { key: keyof T; label: string }[]): string {
  const escape = (value: unknown): string => {
    const raw = value === null || value === undefined ? '' : String(value)
    // Neutralize formula injection: a leading =, +, -, @, tab, or CR would run as a formula in Excel/Sheets.
    const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw
    return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
  }
  const header = columns.map((c) => escape(c.label)).join(',')
  const lines = rows.map((row) => columns.map((c) => escape(row[c.key])).join(','))
  return [header, ...lines].join('\r\n')
}
