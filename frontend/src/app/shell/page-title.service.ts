import { Injectable, effect, inject, signal } from '@angular/core'
import { Title } from '@angular/platform-browser'

// Current page title, shown in the shell's header. Static routes set it via data.title; pages with a data-dependent title override it once that data resolves.
@Injectable({ providedIn: 'root' })
export class PageTitleService {
  private readonly browserTitle = inject(Title)

  readonly title = signal('')

  constructor() {
    // Otherwise the tab title (and what a screen reader announces) never changes between routes.
    effect(() => {
      const title = this.title()
      this.browserTitle.setTitle(title ? `${title} · Hangar` : 'Hangar · Artifact Repository')
    })
  }
}
