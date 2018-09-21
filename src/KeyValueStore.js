import KeyValueStoreContract from './contracts/KeyValueStoreContract'
import { ascii, hex, text } from './encoder'
import Symmetric from './crypto/Symmetric'
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

  async create(accessor, data, account) {
    if (await this.exists(accessor)) {
      throw Error('Already created')
    }
    account = account || this.sender
    const symmetric = await Symmetric.build()
    const encryptedData = await symmetric.encryptString(data)
    const encryptedKey = await KeyValueStore._encryptSymmetric(
      symmetric,
      await this.getPublicKey(account)
    )
    return this.contract.create(
      account,
      ascii.encode(accessor),
      encryptedData,
      encryptedKey
    )
  }

  async write(accessor, data, privateKey) {
    if (!await this.canWrite(accessor)) {
      throw Error('Not permitted to write')
    }
    privateKey = privateKey || this.privateKey
    const symmetric = await this.getSymmetricKey(accessor, privateKey)
    const encryptedData = await symmetric.encryptString(data)
    return this.contract.write(ascii.encode(accessor), encryptedData)
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
    const symmetric = await this.getSymmetricKey(accessor, privateKey)
    return symmetric.decryptString(data)
  }

  async addOwner(accessor, account, privateKey) {
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to add owners')
    }
    privateKey = privateKey || this.privateKey
    return this.contract.addOwner(
      ascii.encode(accessor),
      account,
      await this.newEncryptedKey(accessor, account, privateKey)
    )
  }

  async addAdmin(accessor, account, privateKey) {
    if (!await this.isOwner(accessor)) {
      throw Error('Not permitted to add admins')
    }
    privateKey = privateKey || this.privateKey
    return this.contract.addAdmin(
      ascii.encode(accessor),
      account,
      await this.newEncryptedKey(accessor, account, privateKey)
    )
  }

  async grantReadAccess(accessor, account, privateKey) {
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to grant read permissions')
    }
    privateKey = privateKey || this.privateKey
    return this.contract.grantReadAccess(
      ascii.encode(accessor),
      account,
      await this.newEncryptedKey(accessor, account, privateKey)
    )
  }

  async grantWriteAccess(accessor, account, privateKey) {
    if (!await this.isAdmin(accessor)) {
      throw Error('Not permitted to grant write permissions')
    }
    privateKey = privateKey || this.privateKey
    return this.contract.grantWriteAccess(
      ascii.encode(accessor),
      account,
      await this.newEncryptedKey(accessor, account, privateKey)
    )
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

  async revokeReadAccess(accessor, account, privateKey) {
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
    privateKey = privateKey || this.privateKey
    const symmetric = await Symmetric.build()
    const encryptedData = await symmetric.encryptString(
      await this.read(accessor, privateKey)
    )
    const encryptedKey = await KeyValueStore._encryptSymmetric(
      symmetric,
      await this.getPublicKey()
    )
    return this.contract.revokeReadAccess(
      ascii.encode(accessor),
      account,
      encryptedData,
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

  async getSymmetricKey(accessor, privateKey, account) {
    privateKey = privateKey || this.privateKey
    account = account || this.sender
    return KeyValueStore._decryptSymmetric(
      await this.contract.getKey(ascii.encode(accessor), account),
      privateKey
    )
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
    return this.contract.issueEncryptedKey(
      ascii.encode(accessor),
      account,
      await this.newEncryptedKey(accessor, account, privateKey)
    )
  }

  async newEncryptedKey(accessor, account, privateKey) {
    account = account || this.sender
    privateKey = privateKey || this.privateKey
    return KeyValueStore._encryptSymmetric(
      await this.getSymmetricKey(accessor, privateKey),
      await this.getPublicKey(account)
    )
  }

  async isRegistered(account) {
    return this.contract.isRegistered(account || this.sender)
  }

  async exists(accessor) {
    return this.contract.created(ascii.encode(accessor))
  }

  async setPublicKey(publicKey) {
    return this.contract.setRegistration(publicKey)
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
