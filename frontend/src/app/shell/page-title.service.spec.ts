import { TestBed } from '@angular/core/testing'
import { Title } from '@angular/platform-browser'
import { PageTitleService } from './page-title.service'

describe('PageTitleService', () => {
  it('sets the browser tab title from the page title', () => {
    const service = TestBed.inject(PageTitleService)
    const title = TestBed.inject(Title)

    service.title.set('Utilisateurs')
    TestBed.flushEffects()

    expect(title.getTitle()).toBe('Utilisateurs · Hangar')
  })

  it('falls back to the app name when the page title is empty', () => {
    const service = TestBed.inject(PageTitleService)
    const title = TestBed.inject(Title)

    service.title.set('')
    TestBed.flushEffects()

    expect(title.getTitle()).toBe('Hangar · Artifact Repository')
  })
})
