import { ScopedError } from './ScopedError'

export class NotYetError extends ScopedError {
  constructor(what, scope) {
    super(`not yet: ${what}`, scope)
    this.what = what
  }
}
