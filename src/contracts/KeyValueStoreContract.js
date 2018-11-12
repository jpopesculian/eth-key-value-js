import Contract from './Contract'

export default class KeyValueStoreContract extends Contract {
  async create(account, accessor, encryptedData, encryptedKey) {
    return this._send('create', account, accessor, encryptedData, encryptedKey)
  }

  async claim(account, accessor) {
    return this._send('claim', account, accessor)
  }

  async write(accessor, encryptedData) {
    return this._send('write', accessor, encryptedData)
  }

  async getData(accessor) {
    return this._wrapBytes(this._call('data', accessor))
  }

  async remove(accessor) {
    return this._send('remove', accessor)
  }

  async claimed(accessor) {
    return this._call('claimed', accessor)
  }

  async addOwner(accessor, account) {
    return this._send('addOwner', accessor, account)
  }

  async addAdmin(accessor, account) {
    return this._send('addAdmin', accessor, account)
  }

  async grantWriteAccess(accessor, account) {
    return this._send('grantWriteAccess', accessor, account)
  }

  async grantReadAccess(accessor, account) {
    return this._send('grantReadAccess', accessor, account)
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

  async revokeReadAccess(accessor, account /* encryptedData, encryptedKey */) {
    return this._send(
      'revokeReadAccess',
      accessor,
      account
      /* encryptedData,
      encryptedKey */
    )
  }

  async unRegister() {
    return this._send('unRegister')
  }

  async setRegistration(publicKey) {
    return this._send('setRegistration', publicKey)
  }

  async getUser(account) {
    return this._call('users', account)
  }

  async getKey(accessor, account) {
    return this._wrapBytes(this._call('keys', accessor, account), 'value')
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
