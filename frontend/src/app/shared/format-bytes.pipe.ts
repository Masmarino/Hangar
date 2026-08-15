import { Pipe, PipeTransform } from '@angular/core'
import { formatBytes } from './format'

/** Pure pipe: memoized by Angular per input value, unlike calling formatBytes() directly in a template. */
@Pipe({ name: 'formatBytes' })
export class FormatBytesPipe implements PipeTransform {
  transform(bytes: number): string {
    return formatBytes(bytes)
  }
}
