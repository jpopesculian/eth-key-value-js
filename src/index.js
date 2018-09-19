import getWeb3, { setProvider } from './web3'
import Symmetric from './crypto/Symmetric'
import EthCrypto from 'eth-crypto'
import KeyValueStore from './KeyValueStore'

const IDENTITY = {
  address: '0xc85Bd11BA90F629bdEdAc15a406b6801F0a991A4',
  privateKey: '0xe57b73d530d8f3136f892b587f137d9e24f4ddede02037182aa66f0e8c5dea81',
  publicKey: 'bacb473a3fd348e263cb5d23900cdc98711b6ddf3c70d089728835e4023ffae8da00abd825593410e1b5d627e3ddd3195f864892f7546df39a27a57b44dd836e'
}

window.id = IDENTITY
window.EthCrypto = EthCrypto
window.Symmetric = Symmetric

const init = async () => {
  const { web3 } = await getWeb3()
  const provider = setProvider(web3, { development: true })
  window.store = await KeyValueStore.build()
  await store.setPublicKey(id.publicKey)
  try {
    await store.create('hello', 'hi')
  } catch (e) {
    console.log('hello already created')
  }
  console.log('ready')
}

init()
