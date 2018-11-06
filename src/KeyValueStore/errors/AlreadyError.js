import { ScopedError } from './ScopedError'

export class AlreadyError extends ScopedError {
  constructor(what, scope) {
    super(`already: ${what}`, scope)
    this.what = what
  }
}
