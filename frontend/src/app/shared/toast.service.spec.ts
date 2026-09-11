import { TestBed } from '@angular/core/testing'
import { ToastService } from './toast.service'

describe('ToastService', () => {
  function setup() {
    TestBed.configureTestingModule({})
    return TestBed.inject(ToastService)
  }

  it('starts with no toasts', () => {
    const service = setup()

    expect(service.toasts()).toEqual([])
  })

  it('adds a toast with the given variant and message', () => {
    const service = setup()

    service.success('Paramètres enregistrés.')

    expect(service.toasts()).toHaveLength(1)
    expect(service.toasts()[0].variant).toBe('success')
    expect(service.toasts()[0].message).toBe('Paramètres enregistrés.')
    expect(service.toasts()[0].id).toBeTruthy()
  })

  it('supports every convenience variant', () => {
    const service = setup()

    service.success('ok')
    service.error('ko')
    service.warning('attention')
    service.info('info')

    expect(service.toasts().map((t) => t.variant)).toEqual(['success', 'error', 'warning', 'info'])
  })

  it('assigns a distinct id to each toast, even with the same message', () => {
    const service = setup()

    service.info('same')
    service.info('same')

    const ids = service.toasts().map((t) => t.id)
    expect(new Set(ids).size).toBe(2)
  })

  it('removes a toast by id on dismiss', () => {
    const service = setup()
    service.success('first')
    service.error('second')
    const [first, second] = service.toasts()

    service.dismiss(first.id)

    expect(service.toasts()).toEqual([second])
  })

  it('dismissing an unknown id is a no-op', () => {
    const service = setup()
    service.success('only')

    service.dismiss('does-not-exist')

    expect(service.toasts()).toHaveLength(1)
  })
})
