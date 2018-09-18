import Contract from './Contract'

export default class KeyValueStoreContract extends Contract {
  async exists(accessor) {
    return this._call('exists', accessor)
  }

  async setRegistration(publicKey) {
    return this._send('setRegistration', publicKey)
  }

  async getRegistration(account) {
    return this._call('registration', account)
  }

  async isRegistered(account) {
    return this._call('registered', account)
  }

  static async _getContractDescription() {
    return (await import('eth-key-value-contracts')).KeyValueStore
  }
}
