// French pluralization for Gabarit's function-typed label inputs — their English defaults can't be overridden with a plain attribute.
export const formatResultsAnnouncement = (count: number): string =>
  `${count} résultat${count !== 1 ? 's' : ''}`

export const formatSelectedCount = (count: number): string =>
  `${count} sélectionné${count !== 1 ? 's' : ''}`

const BYTE_UNITS = ['o', 'Ko', 'Mo', 'Go', 'To']

export function formatBytes(bytes: number): string {
  if (bytes <= 0) {
    return '0 o'
  }
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), BYTE_UNITS.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${BYTE_UNITS[exponent]}`
}
