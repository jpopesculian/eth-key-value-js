import KeyValueStoreContract from './contracts/KeyValueStoreContract'
import { ascii, hex, text } from './encoder'
import Symmetric from './crypto/Symmetric'
import EthCrypto, { cipher } from 'eth-crypto'

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

  async create(accessor, data, account) {
    if (this.exists(accessor)) {
      // throw Error('Already created')
    }
    account = account || this.sender
    const publicKey = await this.getPublicKey(account)
    const symmetric = await Symmetric.build()
    const encryptedData = await symmetric.encryptString(data)
    const encryptedKey = hex.encode(
      cipher.stringify(
        await EthCrypto.encryptWithPublicKey(
          publicKey,
          text.decode(await symmetric.export())
        )
      )
    )
    return this.contract.create(
      account,
      ascii.encode(accessor),
      encryptedData,
      encryptedKey
    )
  }

  async write(accessor, data, privateKey) {
    const symmetric = await this.getSymmetricKey(accessor, privateKey)
    const encryptedData = await symmetric.encryptString(data)
    return this.contract.write(ascii.encode(accessor), encryptedData)
  }

  async read(accessor, privateKey) {
    const data = await this.contract.getData(ascii.encode(accessor))
    if (!data) {
      throw Error('No data')
    }
    const symmetric = await this.getSymmetricKey(accessor, privateKey)
    return symmetric.decryptString(data)
  }

  async getSymmetricKey(accessor, privateKey, account) {
    account = account || this.sender
    const exportedKey = text.encode(
      await EthCrypto.decryptWithPrivateKey(
        privateKey,
        cipher.parse(
          hex.decode(
            await this.contract.getKey(ascii.encode(accessor), account)
          )
        )
      )
    )
    return Symmetric.build(exportedKey)
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
