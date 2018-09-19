import Contract from './Contract'

export default class KeyValueStoreContract extends Contract {
  async create(account, accessor, encryptedData, encryptedKey) {
    return this._send('create', account, accessor, encryptedData, encryptedKey)
  }

  async write(accessor, encryptedData) {
    return this._send('write', accessor, encryptedData)
  }

  async created(accessor) {
    return this._call('created', accessor)
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

  async getData(accessor) {
    return this._wrapBytes(this._call('data', accessor))
  }

  async getKey(accessor, account) {
    return this._wrapBytes(this._call('getKey', accessor, account))
  }

  static async _getContractDescription() {
    return (await import('eth-key-value-contracts')).KeyValueStore
  }
}
