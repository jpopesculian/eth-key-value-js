import { noop } from 'lodash'

export const asyncNoop = async () => {
  return noop()
}
