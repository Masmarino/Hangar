import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { TRANSLOCO_LOADER } from '@jsverse/transloco'
import { TranslocoHttpLoader } from './transloco-loader'
import { appConfig } from './app.config'

describe('TranslocoHttpLoader', () => {
  it('fetches the translation file for the requested language', () => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] })
    const loader = TestBed.inject(TranslocoHttpLoader)
    const httpMock = TestBed.inject(HttpTestingController)

    let translation: unknown
    loader.getTranslation('fr').subscribe((value) => (translation = value))

    const req = httpMock.expectOne('/i18n/fr.json')
    expect(req.request.method).toBe('GET')
    req.flush({ hangar: { title: 'Hangar' } })

    expect(translation).toEqual({ hangar: { title: 'Hangar' } })
    httpMock.verify()
  })

  it('is the loader registered in the application config', () => {
    TestBed.configureTestingModule({
      providers: [...appConfig.providers, provideHttpClientTesting()],
    })

    expect(TestBed.inject(TRANSLOCO_LOADER)).toBeInstanceOf(TranslocoHttpLoader)
  })
})
