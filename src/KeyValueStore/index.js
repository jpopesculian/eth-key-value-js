import KeyValueStoreContract from '../contracts/KeyValueStoreContract'
import { ascii, hex, text, json } from '../utils/encoder'
import Symmetric from '../crypto/Symmetric'
import EthCrypto, { cipher } from 'eth-crypto'
import { NotYetError, AlreadyError, NotAuthorizedError } from './errors'
import {
  noop,
  set,
  isEqual,
  reject,
  keys,
  map,
  each,
  filter,
  identity
} from 'lodash'
import { asyncNoop } from '../utils/asyncNoop'

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
      throw new AlreadyError('registered', this.sender)
    }
    return this.setPublicKey(publicKey)
  }

  async unRegister() {
    if (!await this.isRegistered()) {
      throw new NotYetError('registered', this.sender)
    }
    return this.contract.unRegister()
  }

  async create(accessor, data, account) {
    if (await this.claimed(accessor)) {
      throw new AlreadyError('claimed', accessor)
    }
    data = data || ''
    account = account || this.sender
    const { symmetric, encryptedKey } = await this._createSymmetricKey(account)
    const encryptedData = await symmetric.encryptString(data)

    return this.contract.create(
      account,
      ascii.encode(accessor),
      encryptedData,
      encryptedKey
    )
  }

  async claim(accessor, account) {
    if (await this.claimed(accessor)) {
      throw new AlreadyError('claimed', accessor)
    }
    account = account || this.sender
    return this.contract.claim(account, ascii.encode(accessor))
  }

  async createJson(accessor, data, account) {
    return this.create(accessor, json.encode(data), account)
  }

  async write(accessor, data, privateKey) {
    if (!await this.canWrite(accessor)) {
      throw new NotAuthorizedError('to write', this.sender)
    }
    privateKey = privateKey || this.privateKey
    const { symmetric } = await this._getSymmetricKey(accessor, privateKey)
    const encryptedData = await symmetric.encryptString(data)
    return this.contract.write(ascii.encode(accessor), encryptedData)
  }

  async writeJson(accessor, data, privateKey) {
    return this.write(accessor, json.encode(data), privateKey)
  }

  async read(accessor, privateKey) {
    if (!await this.canRead(accessor)) {
      throw new NotAuthorizedError('read', this.sender)
    }
    privateKey = privateKey || this.privateKey
    const data = await this.contract.getData(ascii.encode(accessor))
    if (!data) {
      throw new NotYetError('written', accessor)
    }
    const { symmetric } = await this._getSymmetricKey(accessor, privateKey)
    return symmetric.decryptString(data)
  }

  async readJson(accessor, privateKey) {
    return json.decode(await this.read(accessor, privateKey))
  }

  async remove(accessor) {
    if (!await this.isOwner(accessor)) {
      throw new NotAuthorizedError('remove key', this.sender)
    }
    return this.contract.remove(ascii.encode(accessor))
  }

  async addOwner(accessor, account) {
    if (!await this.isOwner(accessor)) {
      throw new NotAuthorizedError('add owners', this.sender)
    }
    if (await this.isOwner(accessor, account)) {
      throw new AlreadyError('is owner', account)
    }
    return this.contract.addOwner(ascii.encode(accessor), account)
  }

  async addAdmin(accessor, account) {
    if (!await this.isOwner(accessor)) {
      throw new NotAuthorizedError('add admins', this.sender)
    }
    if (await this.isAdmin(accessor, account)) {
      throw new AlreadyError('is admin', account)
    }
    return this.contract.addAdmin(ascii.encode(accessor), account)
  }

  async grantWriteAccess(accessor, account) {
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('grant write permissions', this.sender)
    }
    if (await this.canWrite(accessor, account)) {
      throw new AlreadyError('can write', account)
    }
    return this.contract.grantWriteAccess(ascii.encode(accessor), account)
  }

  async grantReadAccess(accessor, account) {
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('grant read permissions', this.sender)
    }
    if (await this.canRead(accessor, account)) {
      throw new AlreadyError('can read', account)
    }
    return this.contract.grantReadAccess(ascii.encode(accessor), account)
  }

  async removeAdmin(accessor, account) {
    if (this.isSender(account)) {
      throw new NotAuthorizedError('remove own permissions', this.sender)
    }
    if (!await this.isAdmin(accessor, account)) {
      throw new AlreadyError('not an admin', account)
    }
    if (!await this.isOwner(accessor)) {
      throw new NotAuthorizedError('remove admins', this.sender)
    }
    return this.contract.removeAdmin(ascii.encode(accessor), account)
  }

  async removeOwner(accessor, account) {
    if (this.isSender(account)) {
      throw new NotAuthorizedError('remove own permissions', this.sender)
    }
    if (!await this.isOwner(accessor, account)) {
      throw new AlreadyError('not an owner', account)
    }
    if (!await this.isOwner(accessor)) {
      throw new NotAuthorizedError('remove owners', this.sender)
    }
    return this.contract.removeOwner(ascii.encode(accessor), account)
  }

  async revokeWriteAccess(accessor, account) {
    if (this.isSender(account)) {
      throw new NotAuthorizedError('remove own permissions', this.sender)
    }
    if (!await this.canWrite(accessor, account)) {
      throw new AlreadyError('does not have write permissions', account)
    }
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('revoke write permissions', this.sender)
    }
    if (
      (await this.isAdmin(accessor, account)) &&
      !await this.isOwner(accessor)
    ) {
      throw new NotAuthorizedError(
        'revoke write permissions for [${account}]',
        this.sender
      )
    }
    return this.contract.revokeWriteAccess(ascii.encode(accessor), account)
  }

  async revokeReadAccess(accessor, account, privateKey) {
    if (this.isSender(account)) {
      throw new NotAuthorizedError('remove own permissions', this.sender)
    }
    if (!await this.canRead(accessor, account)) {
      throw new AlreadyError('does not have read permissions', account)
    }
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('revoke read permissions', this.sender)
    }
    if (
      (await this.isAdmin(accessor, account)) &&
      !await this.isOwner(accessor)
    ) {
      throw new NotAuthorizedError(
        'revoke read permissions for [${account}]',
        this.sender
      )
    }
    return Promise.all([
      this.contract.revokeReadAccess(ascii.encode(accessor), account),
      ...(await this.reEncrypt(
        accessor,
        map(
          'account',
          this.getMembers(accessor, { except: [account] }),
          privateKey
        )
      ))
    ])
  }

  async reEncrypt(accessor, accounts, privateKey) {
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('issue new keys', this.sender)
    }
    privateKey = privateKey || this.privateKey
    accounts = accounts || map('account', await this.getMembers(accessor))
    const { symmetric, encrypted } = this._createSymmetricKey()

    let encryptData = asyncNoop()
    try {
      const data = await this.read(accessor, privateKey)
      const encryptedData = await symmetric.encryptString(data)
      encryptData = this.contract.write(ascii.encode(accessor), encryptedData)
    } catch (err) {
      if (!(err instanceof NotYet)) {
        throw err
      }
    }

    return Promise.all([
      encryptData,
      ...map(async account => {
        if (!await this.canRead(accessor, account)) {
          return noop()
        }
        const encryptedKey = await KeyValueStore._encryptSymmetric(
          symmetric,
          await this.getPublicKey(account)
        )
        return this.contract.issueEncryptedKey(
          ascii.encode(accessor),
          account,
          encryptedKey
        )
      }, accounts)
    ])
  }

  async issueEncryptedKey(accessor, account, privateKey) {
    if (this.isSender(account)) {
      throw new NotAuthorizedError('issue self key', this.sender)
    }
    if (!await this.isAdmin(accessor)) {
      throw new NotAuthorizedError('issue new keys', this.sender)
    }
    if (!await this.canRead(accessor, account)) {
      throw new NotAuthorizedError('receive a key', account)
    }
    const { encryptedKey } = await this._newEncryptedKey(
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
    const { permissions, only, except } = options
    let members = map(
      account => ({ account }),
      await this.contract.getMembers(ascii.encode(accessor))
    )
    if (only) {
      filter(({ account }) => includes(account, only), members)
    }
    if (except) {
      reject(({ account }) => includes(account, except), members)
    }
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

  async claimed(accessor) {
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
      throw new NotYetError('registered', account)
    }
    return this.contract.getRegistration(account)
  }

  async setPublicKey(publicKey) {
    return this.contract.setRegistration(publicKey)
  }

  async _getSymmetricKey(accessor, privateKey, account) {
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

  async _createSymmetricKey(account) {
    account = account || this.sender
    const symmetric = await Symmetric.build()
    const encryptedKey = await KeyValueStore._encryptSymmetric(
      symmetric,
      await this.getPublicKey(account)
    )
    return { symmetric, encryptedKey }
  }

  async _newEncryptedKey(accessor, account, privateKey) {
    account = account || this.sender
    privateKey = privateKey || this.privateKey
    const { symmetric } = await this._getSymmetricKey(accessor, privateKey)
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
