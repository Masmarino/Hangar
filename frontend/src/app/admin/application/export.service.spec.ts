import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { ExportService } from './export.service'
import { EXPORT_PORT, ExportPort } from './export.port'

describe('ExportService', () => {
  function setup(port: Partial<ExportPort>) {
    TestBed.configureTestingModule({ providers: [{ provide: EXPORT_PORT, useValue: port }] })
    return TestBed.inject(ExportService)
  }

  it('delegates exportConfiguration() to the port', () => {
    const exportConfiguration = vi.fn().mockReturnValue(of(new Blob()))
    setup({ exportConfiguration }).exportConfiguration()

    expect(exportConfiguration).toHaveBeenCalled()
  })

  it('delegates importConfiguration() to the port', () => {
    const file = new File(['{}'], 'config.json')
    const importConfiguration = vi.fn().mockReturnValue(
      of({
        users_created: 0,
        repositories_created: 0,
        permissions_granted: 0,
        invited: [],
        skipped_no_email: [],
        failed: [],
      }),
    )
    setup({ importConfiguration }).importConfiguration(file)

    expect(importConfiguration).toHaveBeenCalledWith(file)
  })
})
