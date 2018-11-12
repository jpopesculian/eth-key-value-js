import { noop } from 'lodash/fp'

export const asyncNoop = async () => {
  return noop()
}
