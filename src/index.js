import getWeb3, { setProvider } from './web3'
import Contract from './contract'

const init = async () => {
  const { web3 } = await getWeb3()
  const provider = setProvider(web3, { development: true })
  window.Contract = Contract
  window.contract = await Contract.deployed()
  console.log('ready')
}

init()
