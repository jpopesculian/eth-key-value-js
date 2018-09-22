import Contract from './Contract'

export default class KeyValueStoreContract extends Contract {
  async create(account, accessor, encryptedData, encryptedKey) {
    return this._send('create', account, accessor, encryptedData, encryptedKey)
  }

  async write(accessor, encryptedData) {
    return this._send('write', accessor, encryptedData)
  }

  async getData(accessor) {
    return this._wrapBytes(this._call('data', accessor))
  }

  async remove(acessor) {
    return this._send('remove', accessor)
  }

  async created(accessor) {
    return this._call('created', accessor)
  }

  async addOwner(accessor, account, encryptedKey) {
    return this._send('addOwner', accessor, account, encryptedKey)
  }

  async addAdmin(accessor, account, encryptedKey) {
    return this._send('addAdmin', accessor, account, encryptedKey)
  }

  async grantWriteAccess(accessor, account, encryptedKey) {
    return this._send('grantWriteAccess', accessor, account, encryptedKey)
  }

  async grantReadAccess(accessor, account, encryptedKey) {
    return this._send('grantReadAccess', accessor, account, encryptedKey)
  }

  async removeOwner(accessor, account) {
    return this._send('removeOwner', accessor, account)
  }

  async removeAdmin(accessor, account) {
    return this._send('removeAdmin', accessor, account)
  }

  async revokeWriteAccess(accessor, account) {
    return this._send('revokeWriteAccess', accessor, account)
  }

  async revokeReadAccess(accessor, account, encryptedData, encryptedKey) {
    return this._send(
      'revokeReadAccess',
      accessor,
      account,
      encryptedData,
      encryptedKey
    )
  }

  async unRegister() {
    return this._send('unRegister')
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

  async getKey(accessor, account) {
    return this._wrapBytes(this._call('getKey', accessor, account))
  }

  async issueEncryptedKey(accessor, account, encryptedKey) {
    return this._send('issueEncryptedKey', accessor, account, encryptedKey)
  }

  async getMembers(accessor) {
    return this._call('getMembers', accessor)
  }

  async isOwner(accessor, account) {
    return this._call('isOwner', accessor, account)
  }

  async isAdmin(accessor, account) {
    return this._call('isAdmin', accessor, account)
  }

  async canWrite(accessor, account) {
    return this._call('canWrite', accessor, account)
  }

  async canRead(accessor, account) {
    return this._call('canRead', accessor, account)
  }

  static async _getContractDescription() {
    return (await import('eth-key-value-contracts')).KeyValueStore
  }
}
