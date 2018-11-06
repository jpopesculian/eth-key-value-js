export class ScopedError extends Error {
  constructor(message, scope) {
    super(`[${scope}] ${message}`)
    this.scope = scope
  }
}
