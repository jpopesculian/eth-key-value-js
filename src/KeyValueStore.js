import KeyValueStoreContract from './contracts/KeyValueStoreContract'
import { encode, decode } from './accessor'
import Symmetric from './crypto/Symmetric'
import EthCrypto from 'eth-crypto'

export default class KeyValueStore {
  constructor(contract) {
    this.contract = contract
  }

  async register(publicKey) {
    if (await this.isRegistered()) {
      throw Error('Already registered')
    }
    return this.setPublicKey(publicKey)
  }

  async create(key, data, account) {
    account = account || this.sender
    const symmetric = await Symmetric.build()
  }

  async isRegistered(account) {
    return this.contract.isRegistered(account || this.sender)
  }

  async exists(accessor) {
    return this.contract.exists(encode(accessor))
  }

  async setPublicKey(publicKey) {
    return this.contract.setRegistration(publicKey)
  }

  async getPublicKey(account) {
    account = account || this.sender
    if (!await this.isRegistered(account)) {
      throw Error('Account not registered')
    }
    return this.contract.getRegistration(account)
  }

  async setPublicKey(publicKey) {
    return this.contract.setRegistration(publicKey)
  }

  get sender() {
    return this.contract.sender
  }

  static async build(address, account) {
    return new KeyValueStore(
      (await KeyValueStoreContract.build(address, account))
    )
  }
}
