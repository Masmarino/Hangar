import { Injectable, signal } from '@angular/core'
import type { ToastItem, ToastVariant } from '@masmarino/gabarit'

let nextId = 0

/** App-wide toast queue — `gbt-toaster` is purely presentational, so this owns the state it renders. */
@Injectable({ providedIn: 'root' })
export class ToastService {
  readonly toasts = signal<ToastItem[]>([])

  show(message: string, variant: ToastVariant = 'info'): void {
    const id = `toast-${++nextId}`
    this.toasts.update((toasts) => [...toasts, { id, variant, message }])
  }

  success(message: string): void {
    this.show(message, 'success')
  }

  error(message: string): void {
    this.show(message, 'error')
  }

  warning(message: string): void {
    this.show(message, 'warning')
  }

  info(message: string): void {
    this.show(message, 'info')
  }

  dismiss(id: string): void {
    this.toasts.update((toasts) => toasts.filter((t) => t.id !== id))
  }
}
