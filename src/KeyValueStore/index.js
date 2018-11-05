import KeyValueStoreContract from '../contracts/KeyValueStoreContract'
import { ascii, hex, text, json } from '../utils/encoder'
import Symmetric from '../crypto/Symmetric'
import EthCrypto, { cipher } from 'eth-crypto'
import { set, reject, keys, map, each, filter, identity } from 'lodash'

export const PERMISSIONS = {
  OWNER: Symbol('owner'),
  ADMIN: Symbol('admin'),
  CAN_READ: Symbol('can_read'),
  CAN_WRITE: Symbol('can_write')
}

export default class KeyValueStore {
  constructor(contract, privateKey) {
    this.contract = contract
    this.privateKey = privateKey
  }

  static async build(address, account, privateKey) {
    return new KeyValueStore(
      (await KeyValueStoreContract.build(address, account)),
      privateKey
    )
  }

  async register(publicKey) {
    if (await this.isRegistered()) {
      throw Error('Already registered')
    }
    return this.setPublicKey(publicKey)
  }

  async unRegister() {
    if (!await this.isRegistered()) {
      throw Error('Not registered')
    }
    return this.contract.unRegister()
  }

  async create(accessor, data, account) {
    if (await this.exists(accessor)) {
      throw Error('Already created')
    }
    data = data || ''
    account = account || this.sender
    const { symmetric, encryptedKey } = await this.createSymmetricKey(
      accessor,
      account
    )
    const encryptedData = await symmetric.encryptString(data)

    return this.contract.create(
      account,
      ascii.encode(accessor),
      encryptedData,
      encryptedKey
    )
  }

  async createJson(accessor, data, account) {
    return this.create(accessor, json.encode(data), account)
  }

  async write(accessor, data, privateKey) {
    if (!await this.canWrite(accessor)) {
      throw Error('Not permitted to write')
    }
    privateKey = privateKey || this.privateKey
    const { symmetric } = await this.getSymmetricKey(accessor, privateKey)
    const encryptedData = await symmetric.encryptString(data)
    return this.contract.write(ascii.encode(accessor), encryptedData)
  }

  async writeJson(accessor, data, privateKey) {
    return this.write(accessor, json.encode(data), privateKey)
  }

  async read(accessor, privateKey) {
    if (!await this.canRead(accessor)) {
      throw Error('Not permitted to read')
    }
    privateKey = privateKey || this.privateKey
    const data = await this.contract.getData(ascii.encode(accessor))
    if (!data) {
      throw Error('No data')
    }
    const { symmetric } = await this.getSymmetricKey(accessor, privateKey)
    return symmetric.decryptString(data)
  }

  async readJson(accessor, privateKey) {
    return json.decode(await this.read(accessor, privateKey))
  }

  async remove(accessor) {
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to remove key')
    }
    this.contract.remove(ascii.encode(accessor))
  }

  async addOwner(accessor, account) {
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to add owners')
    }
    return this.contract.addOwner(ascii.encode(accessor), account)
  }

  async addAdmin(accessor, account) {
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to add admins')
    }
    return this.contract.addAdmin(ascii.encode(accessor), account)
  }

  async grantReadAccess(accessor, account) {
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to grant read permissions')
    }
    return this.contract.grantReadAccess(ascii.encode(accessor), account)
  }

  async grantWriteAccess(accessor, account) {
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to grant write permissions')
    }
    return this.contract.grantWriteAccess(ascii.encode(accessor), account)
  }

  async removeAdmin(accessor, account) {
    if (this.isSender(account)) {
      throw Error('Cannot remove own permissions')
    }
    if (!await this.isAdmin(accessor, account)) {
      throw Error('Account is not an admin')
    }
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to remove admins')
    }
    return this.contract.removeAdmin(ascii.encode(accessor), account)
  }

  async removeOwner(accessor, account) {
    if (this.isSender(account)) {
      throw Error('Cannot remove own permissions')
    }
    if (!await this.isOwner(accessor, account)) {
      throw Error('Account is not an owner')
    }
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to remove owners')
    }
    return this.contract.removeOwner(ascii.encode(accessor), account)
  }

  async revokeWriteAccess(accessor, account) {
    if (this.isSender(account)) {
      throw Error('Cannot remove own permissions')
    }
    if (!await this.canWrite(accessor, account)) {
      throw Error('Account does not have write permissions')
    }
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to revoke write permissions')
    }
    if (
      (await this.isAdmin(accessor, account)) ||
      (await this.isOwner(accessor, account))
    ) {
      if (!await this.isOwner(accessor)) {
        throw Error(
          'Not permitted to revoke write permissions for this account'
        )
      }
    }
    return this.contract.revokeWriteAccess(ascii.encode(accessor), account)
  }

  async revokeReadAccess(accessor, account) {
    if (this.isSender(account)) {
      throw Error('Cannot remove own permissions')
    }
    if (!await this.canRead(accessor, account)) {
      throw Error('Account does not have read permissions')
    }
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to revoke read permissions')
    }
    if (
      (await this.isAdmin(accessor, account)) ||
      (await this.isOwner(accessor, account))
    ) {
      if (!await this.isOwner(accessor)) {
        throw Error('Not permitted to revoke read permissions for this account')
      }
    }
    return this.contract.revokeReadAccess(ascii.encode(accessor), account)
  }

  async issueAllEncryptedKeys(accessor, privateKey) {
    privateKey = privateKey || this.privateKey
    const accounts = map(
      'account',
      reject({ account: this.sender }, await this.getMembers(accessor))
    )
    return Promise.all(
      map(
        account => this.issueEncryptedKey(accessor, account, privateKey),
        accounts
      )
    )
  }

  async issueEncryptedKey(accessor, account, privateKey) {
    if (!await this.isAdmin(accessor, this.sender)) {
      throw Error('Not permitted to issue new keys')
    }
    if (!await this.canRead(accessor, account)) {
      throw Error('Account needs read permissions to get a key')
    }
    const { encryptedKey } = await this.newEncryptedKey(
      accessor,
      account,
      privateKey
    )
    return this.contract.issueEncryptedKey(
      ascii.encode(accessor),
      account,
      encryptedKey
    )
  }

  async getMembers(accessor, options = {}) {
    const { permissions } = options
    let members = map(
      account => ({ account }),
      await this.contract.getMembers(ascii.encode(accessor))
    )
    if (permissions) {
      members = await Promise.all(
        map(
          async member =>
            set(
              'permissions',
              await this.getPermissions(accessor, member.account),
              member
            ),
          members
        )
      )
    }
    return members
  }

  async isRegistered(account) {
    return this.contract.isRegistered(account || this.sender)
  }

  async exists(accessor) {
    return this.contract.claimed(ascii.encode(accessor))
  }

  async isOwner(accessor, account) {
    account = account || this.sender
    return this.contract.isOwner(ascii.encode(accessor), account)
  }

  async isAdmin(accessor, account) {
    account = account || this.sender
    return this.contract.isAdmin(ascii.encode(accessor), account)
  }

  async canWrite(accessor, account) {
    account = account || this.sender
    return this.contract.canWrite(ascii.encode(accessor), account)
  }

  async canRead(accessor, account) {
    account = account || this.sender
    return this.contract.canRead(ascii.encode(accessor), account)
  }

  async getPermissions(accessor, account) {
    account = account || this.sender
    return filter(
      identity,
      await Promise.all([
        this.isOwner(accessor, account).then(y => y && PERMISSIONS.OWNER),
        this.isAdmin(accessor, account).then(y => y && PERMISSIONS.ADMIN),
        this.canWrite(accessor, account).then(y => y && PERMISSIONS.CAN_WRITE),
        this.canRead(accessor, account).then(y => y && PERMISSIONS.CAN_READ)
      ])
    )
  }

  async getPublicKey(account) {
    account = account || this.sender
    if (!await this.isRegistered(account)) {
      throw Error('Not registered')
    }
    return this.contract.getRegistration(account)
  }

  async setPublicKey(publicKey) {
    return this.contract.setRegistration(publicKey)
  }

  async createSymmetricKey(accessor, account) {
    const symmetric = await Symmetric.build()
    const encryptedKey = await KeyValueStore._encryptSymmetric(
      symmetric,
      await this.getPublicKey(account)
    )
    return { symmetric, encryptedKey }
  }

  async getSymmetricKey(accessor, privateKey, account) {
    privateKey = privateKey || this.privateKey
    account = account || this.sender
    const encryptedKey = await this.contract.getKey(
      ascii.encode(accessor),
      account
    )
    const symmetric = await KeyValueStore._decryptSymmetric(
      encryptedKey,
      privateKey
    )
    return { symmetric, encryptedKey }
  }

  async newEncryptedKey(accessor, account, privateKey) {
    account = account || this.sender
    privateKey = privateKey || this.privateKey
    const { symmetric } = this.getSymmetricKey(accessor, privateKey, account)
    const encryptedKey = await KeyValueStore._encryptSymmetric(
      symmetric,
      await this.getPublicKey(account)
    )
    return { symmetric, encryptedKey }
  }

  isSender(account) {
    return this.sender == account
  }

  static async _encryptSymmetric(symmetric, publicKey) {
    return hex.encode(
      cipher.stringify(
        await EthCrypto.encryptWithPublicKey(
          publicKey,
          text.decode(await symmetric.export())
        )
      )
    )
  }

  static async _decryptSymmetric(encryptedKey, privateKey) {
    const exportedKey = text.encode(
      await EthCrypto.decryptWithPrivateKey(
        privateKey,
        cipher.parse(hex.decode(encryptedKey))
      )
    )
    return Symmetric.build(exportedKey)
  }

  get sender() {
    return this.contract.sender
  }
}
