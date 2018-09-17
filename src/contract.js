export default class Contract {
  constructor(contract) {
    this.contract = contract
  }

  async helloWorld() {
    return this.contract.methods.helloWorld().call()
  }

  static async deployed(address) {
    const description = await this._getContractAbi()
    if (!address) {
      const networkId = await web3.eth.net.getId()
      if (description.networks[networkId]) {
        address = description.networks[networkId].address
      } else {
        throw Error('No address found!')
      }
    }
    const contract = new web3.eth.Contract(description.abi, address)
    return new Contract(contract)
  }

  static async _getContractAbi() {
    return (await import('eth-key-value-contracts')).HelloWorld
  }
}
