export default class Contract {
  constructor(contract, sender) {
    this.contract = contract
    this.sender = sender
  }

  static async build(address, account) {
    const [contract, sender] = await Promise.all([
      this._getWeb3Contract(address),
      new Promise((resolve, reject) =>
        resolve(account ? account : Contract._getDefaultAccount())
      )
    ])
    return new this(contract, sender)
  }

  async _call(name, ...args) {
    return this.contract.methods[name](...args).call()
  }

  async _send(name, ...args) {
    return this.contract.methods
      [name](...args)
      .send({ from: this.sender, gas: 1000000 })
  }

  static async _getDefaultAccount() {
    const accounts = await web3.eth.getAccounts()
    if (accounts.length < 1) {
      throw Error('No account given')
    }
    return accounts[0]
  }

  static async _getDefaultAddress(description) {
    const networkId = await web3.eth.net.getId()
    if (description.networks[networkId]) {
      return description.networks[networkId].address
    }
    return null
  }

  static async _getWeb3Contract(address) {
    const description = await this._getContractDescription()
    address = address || (await Contract._getDefaultAddress(description))
    if (!address) {
      throw Error('No address given!')
    }
    return new web3.eth.Contract(description.abi, address)
  }
}
