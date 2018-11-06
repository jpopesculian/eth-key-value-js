import { ScopedError } from './ScopedError'

export class NotAuthorizedError extends ScopedError {
  constructor(what, scope) {
    super(`not authorized to: ${what}`, scope)
    this.what = what
  }
}
